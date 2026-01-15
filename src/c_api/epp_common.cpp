/**
 * @file epp_common.cpp
 * @brief Shared C API implementations for both client and server libraries
 *
 * This file contains all functions that are shared between the client (epp_api)
 * and server (epp_server_api) C API implementations to avoid duplicate symbols.
 */

#include "ecliptix/c_api/epp_api.h"
#include "epp_internal.hpp"
#include "ecliptix/protocol/protocol_system.hpp"
#include "ecliptix/protocol/connection/protocol_connection.hpp"
#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/crypto/shamir_secret_sharing.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/constants.hpp"
#include "common/secure_envelope.pb.h"
#include "protocol/key_exchange.pb.h"
#include <atomic>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <span>
#include <string>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::identity;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::models;
using ecliptix::proto::common::SecureEnvelope;
using ecliptix::proto::protocol::PublicKeyBundle;
using crypto::KyberInterop;

// ============================================================================
// Internal Helper Implementations
// ============================================================================

namespace epp::internal {

EppErrorCode EnsureInitialized() {
    static std::once_flag init_flag;
    static std::atomic init_success{false};

    std::call_once(init_flag, [] {
        const auto result = SodiumInterop::Initialize();
        init_success.store(result.IsOk(), std::memory_order_release);
    });

    return init_success.load(std::memory_order_acquire)
               ? EPP_SUCCESS
               : EPP_ERROR_SODIUM_FAILURE;
}

void fill_error(EppError* out_error, const EppErrorCode code, const std::string& message) {
    if (out_error) {
        out_error->code = code;
#ifdef _WIN32
        out_error->message = _strdup(message.c_str());
#else
        out_error->message = strdup(message.c_str());
#endif
    }
}

EppErrorCode fill_error_from_failure(EppError* out_error, const ProtocolFailure& failure) {
    EppErrorCode code = EPP_ERROR_GENERIC;

    switch (failure.type) {
        case ProtocolFailureType::KeyGeneration:
            code = EPP_ERROR_KEY_GENERATION;
            break;
        case ProtocolFailureType::DeriveKey:
            code = EPP_ERROR_DERIVE_KEY;
            break;
        case ProtocolFailureType::Handshake:
            code = EPP_ERROR_HANDSHAKE;
            break;
        case ProtocolFailureType::Decode:
            code = EPP_ERROR_DECODE;
            break;
        case ProtocolFailureType::Encode:
            code = EPP_ERROR_ENCODE;
            break;
        case ProtocolFailureType::BufferTooSmall:
            code = EPP_ERROR_BUFFER_TOO_SMALL;
            break;
        case ProtocolFailureType::ObjectDisposed:
            code = EPP_ERROR_OBJECT_DISPOSED;
            break;
        case ProtocolFailureType::InvalidInput:
            code = EPP_ERROR_INVALID_INPUT;
            break;
        case ProtocolFailureType::PrepareLocal:
            code = EPP_ERROR_PREPARE_LOCAL;
            break;
        case ProtocolFailureType::PeerPubKey:
            code = EPP_ERROR_HANDSHAKE;
            break;
        case ProtocolFailureType::InvalidState:
            code = EPP_ERROR_INVALID_STATE;
            break;
        case ProtocolFailureType::NullPointer:
            code = EPP_ERROR_NULL_POINTER;
            break;
        default:
            code = EPP_ERROR_GENERIC;
            break;
    }

    if (out_error) {
        fill_error(out_error, code, failure.message);
    }
    return code;
}

bool validate_buffer_param(const uint8_t* data, const size_t length, EppError* out_error) {
    if (!data && length > 0) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Buffer data is null but length is non-zero");
        return false;
    }
    return true;
}

bool validate_output_handle(const void* handle, EppError* out_error) {
    if (!handle) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Output handle pointer is null");
        return false;
    }
    return true;
}

bool copy_to_buffer(const std::span<const uint8_t> input, EppBuffer* out_buffer, EppError* out_error) {
    if (!out_buffer) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Output buffer is null");
        return false;
    }

    auto* data = new(std::nothrow) uint8_t[input.size()];
    if (!data) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate output buffer");
        return false;
    }
    std::memcpy(data, input.data(), input.size());
    out_buffer->data = data;
    out_buffer->length = input.size();
    return true;
}

Result<LocalPublicKeyBundle, ProtocolFailure> build_local_bundle(const PublicKeyBundle& proto_bundle) {
    if (proto_bundle.identity_public_key().empty() || proto_bundle.identity_x25519_public_key().empty()) {
        return Result<LocalPublicKeyBundle, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Peer bundle missing identity keys"));
    }
    if (proto_bundle.signed_pre_key_public_key().empty() || proto_bundle.signed_pre_key_signature().empty()) {
        return Result<LocalPublicKeyBundle, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Peer bundle missing signed pre-key material"));
    }

    std::vector<OneTimePreKeyPublic> otps;
    otps.reserve(proto_bundle.one_time_pre_keys_size());
    for (const auto& otp : proto_bundle.one_time_pre_keys()) {
        if (otp.public_key().empty()) {
            return Result<LocalPublicKeyBundle, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Peer bundle contains empty one-time pre-key"));
        }
        otps.emplace_back(
            otp.pre_key_id(),
            std::vector<uint8_t>(otp.public_key().begin(), otp.public_key().end()));
    }

    std::optional<std::vector<uint8_t>> ephemeral = std::nullopt;
    if (!proto_bundle.ephemeral_x25519_public_key().empty()) {
        ephemeral = std::vector<uint8_t>(
            proto_bundle.ephemeral_x25519_public_key().begin(),
            proto_bundle.ephemeral_x25519_public_key().end());
    }

    std::optional<std::vector<uint8_t>> kyber = std::nullopt;
    if (!proto_bundle.kyber_public_key().empty()) {
        kyber = std::vector<uint8_t>(
            proto_bundle.kyber_public_key().begin(),
            proto_bundle.kyber_public_key().end());
    }

    std::optional<std::vector<uint8_t>> kyber_ciphertext = std::nullopt;
    if (!proto_bundle.kyber_ciphertext().empty()) {
        kyber_ciphertext = std::vector<uint8_t>(
            proto_bundle.kyber_ciphertext().begin(),
            proto_bundle.kyber_ciphertext().end());
    }

    std::optional<uint32_t> used_opk_id = std::nullopt;
    if (proto_bundle.has_used_one_time_pre_key_id()) {
        used_opk_id = proto_bundle.used_one_time_pre_key_id();
    }

    return Result<LocalPublicKeyBundle, ProtocolFailure>::Ok(
        LocalPublicKeyBundle(
            std::vector<uint8_t>(proto_bundle.identity_public_key().begin(),
                                 proto_bundle.identity_public_key().end()),
            std::vector<uint8_t>(proto_bundle.identity_x25519_public_key().begin(),
                                 proto_bundle.identity_x25519_public_key().end()),
            proto_bundle.signed_pre_key_id(),
            std::vector<uint8_t>(proto_bundle.signed_pre_key_public_key().begin(),
                                 proto_bundle.signed_pre_key_public_key().end()),
            std::vector<uint8_t>(proto_bundle.signed_pre_key_signature().begin(),
                                 proto_bundle.signed_pre_key_signature().end()),
            std::move(otps),
            std::move(ephemeral),
            std::move(kyber),
            std::move(kyber_ciphertext),
            used_opk_id));
}

CApiEventHandler::CApiEventHandler(const EppEventCallback callback, void* user_data)
    : callback_(callback), user_data_(user_data) {
}

void CApiEventHandler::OnProtocolStateChanged(const uint32_t connection_id) {
    if (callback_) {
        callback_(connection_id, user_data_);
    }
}

void CApiEventHandler::OnRatchetRequired(const uint32_t connection_id, const std::string& reason) {
    (void)connection_id;
    (void)reason;
}

} // namespace epp::internal

// ============================================================================
// Shared C API Implementations
// ============================================================================

using namespace epp::internal;

extern "C" {

// ----------------------------------------------------------------------------
// Version & Initialization
// ----------------------------------------------------------------------------

const char* epp_version(void) {
    return "1.0.0";
}

EppErrorCode epp_init(void) {
    const auto result = SodiumInterop::Initialize();
    if (result.IsErr()) {
        return EPP_ERROR_SODIUM_FAILURE;
    }
    return EPP_SUCCESS;
}

void epp_shutdown(void) {
}

// ----------------------------------------------------------------------------
// Identity Keys Management
// ----------------------------------------------------------------------------

EppErrorCode epp_identity_create(
    EppIdentityHandle** out_handle,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!validate_output_handle(out_handle, out_error)) {
        return EPP_ERROR_NULL_POINTER;
    }

    constexpr uint32_t default_one_time_key_count = 100;
    auto result = IdentityKeys::Create(default_one_time_key_count);
    if (result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(result).UnwrapErr());
    }

    auto* handle = new(std::nothrow) EppIdentityHandle{
        std::make_unique<IdentityKeys>(std::move(result).Unwrap())
    };

    if (!handle) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate identity keys handle");
        return EPP_ERROR_OUT_OF_MEMORY;
    }

    *out_handle = handle;
    return EPP_SUCCESS;
}

EppErrorCode epp_identity_create_from_seed(
    const uint8_t* seed,
    const size_t seed_length,
    EppIdentityHandle** out_handle,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!validate_output_handle(out_handle, out_error) ||
        !validate_buffer_param(seed, seed_length, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }

    if (constexpr size_t expected_master_key_size = 32; seed_length != expected_master_key_size) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT,
                   "Master key length must be " + std::to_string(expected_master_key_size) + " bytes");
        return EPP_ERROR_INVALID_INPUT;
    }

    constexpr uint32_t default_one_time_key_count = 100;
    constexpr std::string_view default_membership_id = "default";

    const std::span master_key_span(seed, seed_length);
    auto result = IdentityKeys::CreateFromMasterKey(
        master_key_span,
        default_membership_id,
        default_one_time_key_count
    );

    if (result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(result).UnwrapErr());
    }

    auto* handle = new(std::nothrow) EppIdentityHandle{
        std::make_unique<IdentityKeys>(std::move(result).Unwrap())
    };

    if (!handle) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate identity keys handle");
        return EPP_ERROR_OUT_OF_MEMORY;
    }

    *out_handle = handle;
    return EPP_SUCCESS;
}

EppErrorCode epp_identity_create_with_context(
    const uint8_t* seed,
    const size_t seed_length,
    const char* membership_id,
    const size_t membership_id_length,
    EppIdentityHandle** out_handle,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!validate_output_handle(out_handle, out_error) ||
        !validate_buffer_param(seed, seed_length, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (!membership_id || membership_id_length == 0) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Membership id must not be empty");
        return EPP_ERROR_INVALID_INPUT;
    }

    if (constexpr size_t expected_master_key_size = 32; seed_length != expected_master_key_size) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT,
                   "Master key length must be " + std::to_string(expected_master_key_size) + " bytes");
        return EPP_ERROR_INVALID_INPUT;
    }

    constexpr uint32_t default_one_time_key_count = 100;
    const std::span master_key_span(seed, seed_length);
    const std::string_view membership_view(membership_id, membership_id_length);

    auto result = IdentityKeys::CreateFromMasterKey(
        master_key_span,
        membership_view,
        default_one_time_key_count
    );

    if (result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(result).UnwrapErr());
    }

    auto* handle = new(std::nothrow) EppIdentityHandle{
        std::make_unique<IdentityKeys>(std::move(result).Unwrap())
    };

    if (!handle) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate identity keys handle");
        return EPP_ERROR_OUT_OF_MEMORY;
    }

    *out_handle = handle;
    return EPP_SUCCESS;
}

EppErrorCode epp_identity_get_x25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    const size_t out_key_length,
    EppError* out_error) {
    if (!handle || !handle->identity_keys) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Identity keys handle is null");
        return EPP_ERROR_NULL_POINTER;
    }

    if (!validate_buffer_param(out_key, out_key_length, out_error)) {
        return out_error->code;
    }

    if (out_key_length != Constants::X_25519_PUBLIC_KEY_SIZE) {
        fill_error(out_error, EPP_ERROR_BUFFER_TOO_SMALL,
                   "Output buffer must be " + std::to_string(Constants::X_25519_PUBLIC_KEY_SIZE) + " bytes");
        return EPP_ERROR_BUFFER_TOO_SMALL;
    }

    const auto& key = handle->identity_keys->GetIdentityX25519PublicKeyCopy();
    std::memcpy(out_key, key.data(), key.size());

    return EPP_SUCCESS;
}

EppErrorCode epp_identity_get_ed25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    const size_t out_key_length,
    EppError* out_error) {
    if (!handle || !handle->identity_keys) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Identity keys handle is null");
        return EPP_ERROR_NULL_POINTER;
    }

    if (!validate_buffer_param(out_key, out_key_length, out_error)) {
        return out_error->code;
    }

    if (out_key_length != Constants::ED_25519_PUBLIC_KEY_SIZE) {
        fill_error(out_error, EPP_ERROR_BUFFER_TOO_SMALL,
                   "Output buffer must be " + std::to_string(Constants::ED_25519_PUBLIC_KEY_SIZE) + " bytes");
        return EPP_ERROR_BUFFER_TOO_SMALL;
    }

    const auto& key = handle->identity_keys->GetIdentityEd25519PublicKeyCopy();
    std::memcpy(out_key, key.data(), key.size());

    return EPP_SUCCESS;
}

EppErrorCode epp_identity_get_kyber_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    const size_t out_key_length,
    EppError* out_error) {
    if (!handle || !handle->identity_keys) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Identity keys handle is null");
        return EPP_ERROR_NULL_POINTER;
    }

    if (!validate_buffer_param(out_key, out_key_length, out_error)) {
        return out_error->code;
    }

    if (out_key_length != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
        fill_error(out_error, EPP_ERROR_BUFFER_TOO_SMALL,
                   "Output buffer must be " + std::to_string(KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) + " bytes");
        return EPP_ERROR_BUFFER_TOO_SMALL;
    }

    const auto& key = handle->identity_keys->GetKyberPublicKeyCopy();
    std::memcpy(out_key, key.data(), key.size());

    return EPP_SUCCESS;
}

void epp_identity_destroy(EppIdentityHandle* handle) {
    delete handle;
}

// ----------------------------------------------------------------------------
// Session Utilities
// ----------------------------------------------------------------------------

EppErrorCode epp_session_age_seconds(
    const ProtocolSystemHandle* handle,
    uint64_t* out_age_seconds,
    EppError* out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!out_age_seconds) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "out_age_seconds is null");
        return EPP_ERROR_NULL_POINTER;
    }
    if (!handle->system->HasConnection()) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol connection not established");
        return EPP_ERROR_INVALID_STATE;
    }

    *out_age_seconds = handle->system->GetSessionAgeSeconds();
    return EPP_SUCCESS;
}

// ----------------------------------------------------------------------------
// Envelope & Key Derivation
// ----------------------------------------------------------------------------

EppErrorCode epp_envelope_validate(
    const uint8_t* encrypted_envelope,
    const size_t encrypted_envelope_length,
    EppError* out_error) {
    if (!validate_buffer_param(encrypted_envelope, encrypted_envelope_length, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }

    SecureEnvelope envelope;
    if (!envelope.ParseFromArray(encrypted_envelope, static_cast<int>(encrypted_envelope_length))) {
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse envelope");
        return EPP_ERROR_DECODE;
    }

    if (!envelope.has_ratchet_epoch()) {
        fill_error(out_error, EPP_ERROR_DECODE, "Missing ratchet epoch");
        return EPP_ERROR_DECODE;
    }

    if (!envelope.dh_public_key().empty() && envelope.kyber_ciphertext().empty()) {
        fill_error(out_error, EPP_ERROR_PQ_MISSING, "Missing Kyber ciphertext for hybrid ratchet");
        return EPP_ERROR_PQ_MISSING;
    }

    if (!envelope.kyber_ciphertext().empty()) {
        const auto& ct = envelope.kyber_ciphertext();
        if (ct.size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
            fill_error(out_error, EPP_ERROR_DECODE, "Invalid Kyber ciphertext size");
            return EPP_ERROR_DECODE;
        }
    }

    return EPP_SUCCESS;
}

EppErrorCode epp_derive_root_key(
    const uint8_t* opaque_session_key,
    const size_t opaque_session_key_length,
    const uint8_t* user_context,
    const size_t user_context_length,
    uint8_t* out_root_key,
    const size_t out_root_key_length,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!validate_buffer_param(opaque_session_key, opaque_session_key_length, out_error) ||
        !validate_buffer_param(user_context, user_context_length, out_error) ||
        !validate_buffer_param(out_root_key, out_root_key_length, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }

    if (opaque_session_key_length != Constants::X_25519_KEY_SIZE) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT,
                   "OPAQUE session key must be 32 bytes");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (user_context_length == 0) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "OPAQUE user context must not be empty");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (out_root_key_length < Constants::X_25519_KEY_SIZE) {
        fill_error(out_error, EPP_ERROR_BUFFER_TOO_SMALL,
                   "Output buffer too small for derived root key");
        return EPP_ERROR_BUFFER_TOO_SMALL;
    }

    auto root_result = ProtocolConnection::DeriveOpaqueMessagingRoot(
        std::span(opaque_session_key, opaque_session_key_length),
        std::span(user_context, user_context_length));
    if (root_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(root_result).UnwrapErr());
    }
    auto root = root_result.Unwrap();
    std::memcpy(out_root_key, root.data(), Constants::X_25519_KEY_SIZE);
    const auto _wipe = SodiumInterop::SecureWipe(std::span(root));
    (void)_wipe;
    return EPP_SUCCESS;
}

// ----------------------------------------------------------------------------
// Shamir Secret Sharing
// ----------------------------------------------------------------------------

EppErrorCode epp_shamir_split(
    const uint8_t* secret,
    const size_t secret_length,
    const uint8_t threshold,
    const uint8_t share_count,
    const uint8_t* auth_key,
    const size_t auth_key_length,
    EppBuffer* out_shares,
    size_t* out_share_length,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!validate_buffer_param(secret, secret_length, out_error) ||
        !validate_buffer_param(auth_key, auth_key_length, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (!out_shares || !out_share_length) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Output parameters are null");
        return EPP_ERROR_NULL_POINTER;
    }
    if (secret_length == 0) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Secret must not be empty");
        return EPP_ERROR_INVALID_INPUT;
    }

    const std::span<const uint8_t> auth_span =
            auth_key && auth_key_length > 0
                ? std::span(auth_key, auth_key_length)
                : std::span<const uint8_t>();

    auto split_result = ShamirSecretSharing::Split(
        std::span(secret, secret_length),
        threshold,
        share_count,
        auth_span);
    if (split_result.IsErr()) {
        return fill_error_from_failure(out_error, split_result.UnwrapErr());
    }

    const auto shares = std::move(split_result).Unwrap();
    if (shares.empty()) {
        fill_error(out_error, EPP_ERROR_GENERIC, "No shares generated");
        return EPP_ERROR_GENERIC;
    }

    const size_t share_length = shares.front().size();
    for (const auto& share : shares) {
        if (share.size() != share_length) {
            fill_error(out_error, EPP_ERROR_GENERIC, "Share length mismatch");
            return EPP_ERROR_GENERIC;
        }
    }

    if (share_length > 0 && shares.size() > std::numeric_limits<size_t>::max() / share_length) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Share buffer size overflow");
        return EPP_ERROR_OUT_OF_MEMORY;
    }

    const size_t total_length = share_length * shares.size();
    auto* data = new(std::nothrow) uint8_t[total_length];
    if (!data) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate share buffer");
        return EPP_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < shares.size(); ++i) {
        std::memcpy(data + (i * share_length), shares[i].data(), share_length);
    }

    out_shares->data = data;
    out_shares->length = total_length;
    *out_share_length = share_length;
    return EPP_SUCCESS;
}

EppErrorCode epp_shamir_reconstruct(
    const uint8_t* shares,
    const size_t shares_length,
    const size_t share_length,
    const size_t share_count,
    const uint8_t* auth_key,
    const size_t auth_key_length,
    EppBuffer* out_secret,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!validate_buffer_param(shares, shares_length, out_error) ||
        !validate_buffer_param(auth_key, auth_key_length, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (!out_secret) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Output secret buffer is null");
        return EPP_ERROR_NULL_POINTER;
    }
    if (share_length == 0 || share_count == 0) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Share length or count is invalid");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (share_length * share_count != shares_length) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Share buffer length mismatch");
        return EPP_ERROR_INVALID_INPUT;
    }

    const std::span<const uint8_t> auth_span =
            auth_key && auth_key_length > 0
                ? std::span(auth_key, auth_key_length)
                : std::span<const uint8_t>();

    auto reconstruct_result = ShamirSecretSharing::ReconstructSerialized(
        std::span(shares, shares_length),
        share_length,
        share_count,
        auth_span);
    if (reconstruct_result.IsErr()) {
        return fill_error_from_failure(out_error, reconstruct_result.UnwrapErr());
    }

    auto secret = std::move(reconstruct_result).Unwrap();
    if (!copy_to_buffer(secret, out_secret, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }

    return EPP_SUCCESS;
}

// ----------------------------------------------------------------------------
// Memory & Error Management
// ----------------------------------------------------------------------------

EppBuffer* epp_buffer_alloc(const size_t capacity) {
    auto* buffer = new(std::nothrow) EppBuffer{};
    if (!buffer) {
        return nullptr;
    }

    if (capacity > 0) {
        buffer->data = new(std::nothrow) uint8_t[capacity];
        if (!buffer->data) {
            delete buffer;
            return nullptr;
        }
    } else {
        buffer->data = nullptr;
    }

    buffer->length = capacity;
    return buffer;
}

void epp_buffer_free(EppBuffer* buffer) {
    if (buffer) {
        if (buffer->data) {
            SodiumInterop::SecureWipe(std::span(buffer->data, buffer->length));
            delete[] buffer->data;
        }
        delete buffer;
    }
}

void epp_error_free(EppError* error) {
    if (error && error->message) {
        free(error->message);
        error->message = nullptr;
    }
}

const char* epp_error_string(const EppErrorCode code) {
    switch (code) {
        case EPP_SUCCESS: return "Success";
        case EPP_ERROR_GENERIC: return "Generic error";
        case EPP_ERROR_INVALID_INPUT: return "Invalid input";
        case EPP_ERROR_KEY_GENERATION: return "Key generation failed";
        case EPP_ERROR_DERIVE_KEY: return "Key derivation failed";
        case EPP_ERROR_HANDSHAKE: return "Handshake failed";
        case EPP_ERROR_ENCRYPTION: return "Encryption failed";
        case EPP_ERROR_DECRYPTION: return "Decryption failed";
        case EPP_ERROR_DECODE: return "Decoding failed";
        case EPP_ERROR_ENCODE: return "Encoding failed";
        case EPP_ERROR_BUFFER_TOO_SMALL: return "Buffer too small";
        case EPP_ERROR_OBJECT_DISPOSED: return "Object disposed";
        case EPP_ERROR_PREPARE_LOCAL: return "Prepare local failed";
        case EPP_ERROR_OUT_OF_MEMORY: return "Out of memory";
        case EPP_ERROR_SODIUM_FAILURE: return "Sodium library failure";
        case EPP_ERROR_NULL_POINTER: return "Null pointer";
        case EPP_ERROR_INVALID_STATE: return "Invalid state";
        case EPP_ERROR_REPLAY_ATTACK: return "Replay attack detected";
        case EPP_ERROR_SESSION_EXPIRED: return "Session expired";
        case EPP_ERROR_PQ_MISSING: return "Hybrid PQ material missing";
        default: return "Unknown error";
    }
}

EppErrorCode epp_secure_wipe(uint8_t* data, const size_t length) {
    if (!data && length > 0) {
        return EPP_ERROR_NULL_POINTER;
    }

    if (length > 0) {
        SodiumInterop::SecureWipe(std::span(data, length));
    }

    return EPP_SUCCESS;
}

} // extern "C"
