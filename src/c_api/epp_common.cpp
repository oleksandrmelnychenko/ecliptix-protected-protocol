#include "ecliptix/c_api/epp_api.h"
#include "epp_internal.hpp"
#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/crypto/shamir_secret_sharing.hpp"
#include "ecliptix/protocol/handshake.hpp"
#include "ecliptix/protocol/session.hpp"
#include "ecliptix/protocol/constants.hpp"
#include "ecliptix/security/validation/dh_validator.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/constants.hpp"
#include "protocol/handshake.pb.h"
#include "protocol/envelope.pb.h"
#include "protocol/state.pb.h"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::identity;
using namespace ecliptix::protocol::crypto;
using crypto::KyberInterop;

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
        case ProtocolFailureType::ReplayAttack:
            code = EPP_ERROR_REPLAY_ATTACK;
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

bool validate_session_config(const EppSessionConfig* config, EppError* out_error) {
    if (!config) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Session config is null");
        return false;
    }
    if (config->max_messages_per_chain == 0 ||
        config->max_messages_per_chain > kMaxMessagesPerChain) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid max messages per chain");
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

}

using namespace epp::internal;

extern "C" {

const char* epp_version(void) {
    return EPP_LIBRARY_VERSION;
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

    auto result = IdentityKeys::Create(EPP_DEFAULT_ONE_TIME_KEY_COUNT);
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

    const std::span master_key_span(seed, seed_length);
    auto result = IdentityKeys::CreateFromMasterKey(
        master_key_span,
        ecliptix::protocol::kDefaultMembershipId,
        EPP_DEFAULT_ONE_TIME_KEY_COUNT
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

    const std::span master_key_span(seed, seed_length);
    const std::string_view membership_view(membership_id, membership_id_length);

    auto result = IdentityKeys::CreateFromMasterKey(
        master_key_span,
        membership_view,
        EPP_DEFAULT_ONE_TIME_KEY_COUNT
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

    if (out_key_length != kX25519PublicKeyBytes) {
        fill_error(out_error, EPP_ERROR_BUFFER_TOO_SMALL,
                   "Output buffer must be " + std::to_string(kX25519PublicKeyBytes) + " bytes");
        return EPP_ERROR_BUFFER_TOO_SMALL;
    }

    const auto& key = handle->identity_keys->GetIdentityX25519PublicCopy();
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

    if (out_key_length != kEd25519PublicKeyBytes) {
        fill_error(out_error, EPP_ERROR_BUFFER_TOO_SMALL,
                   "Output buffer must be " + std::to_string(kEd25519PublicKeyBytes) + " bytes");
        return EPP_ERROR_BUFFER_TOO_SMALL;
    }

    const auto& key = handle->identity_keys->GetIdentityEd25519PublicCopy();
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

    const auto& key = handle->identity_keys->GetKyberPublicCopy();
    std::memcpy(out_key, key.data(), key.size());

    return EPP_SUCCESS;
}

void epp_identity_destroy(EppIdentityHandle* handle) {
    delete handle;
}

EppErrorCode epp_prekey_bundle_create(
    const EppIdentityHandle* identity_keys,
    EppBuffer* out_bundle,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!identity_keys || !identity_keys->identity_keys) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Identity keys handle is null");
        return EPP_ERROR_NULL_POINTER;
    }
    if (!validate_output_handle(out_bundle, out_error)) {
        return EPP_ERROR_NULL_POINTER;
    }

    auto bundle_result = identity_keys->identity_keys->CreatePublicBundle();
    if (bundle_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(bundle_result).UnwrapErr());
    }
    const auto& bundle = bundle_result.Unwrap();

    if (bundle.GetIdentityEd25519Public().size() != kEd25519PublicKeyBytes ||
        bundle.GetIdentityX25519Public().size() != kX25519PublicKeyBytes ||
        bundle.GetSignedPreKeyPublic().size() != kX25519PublicKeyBytes ||
        bundle.GetSignedPreKeySignature().size() != kEd25519SignatureBytes) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid local identity key sizes for bundle");
        return EPP_ERROR_INVALID_INPUT;
    }

    if (!bundle.HasKyberPublic()) {
        fill_error(out_error, EPP_ERROR_PQ_MISSING, "Kyber public key required for bundle");
        return EPP_ERROR_PQ_MISSING;
    }
    const auto& kyber_public = bundle.GetKyberPublic();
    if (!kyber_public.has_value() || kyber_public->size() != kKyberPublicKeyBytes) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid Kyber public key size for bundle");
        return EPP_ERROR_INVALID_INPUT;
    }

    ecliptix::proto::protocol::PreKeyBundle proto_bundle;
    proto_bundle.set_version(kProtocolVersion);
    proto_bundle.set_identity_ed25519_public(
        bundle.GetIdentityEd25519Public().data(),
        bundle.GetIdentityEd25519Public().size());
    proto_bundle.set_identity_x25519_public(
        bundle.GetIdentityX25519Public().data(),
        bundle.GetIdentityX25519Public().size());
    proto_bundle.set_signed_pre_key_id(bundle.GetSignedPreKeyId());
    proto_bundle.set_signed_pre_key_public(
        bundle.GetSignedPreKeyPublic().data(),
        bundle.GetSignedPreKeyPublic().size());
    proto_bundle.set_signed_pre_key_signature(
        bundle.GetSignedPreKeySignature().data(),
        bundle.GetSignedPreKeySignature().size());
    for (const auto& opk : bundle.GetOneTimePreKeys()) {
        auto* opk_proto = proto_bundle.add_one_time_pre_keys();
        opk_proto->set_one_time_pre_key_id(opk.GetOneTimePreKeyId());
        const auto& opk_pub = opk.GetPublicKey();
        opk_proto->set_public_key(opk_pub.data(), opk_pub.size());
    }
    proto_bundle.set_kyber_public(kyber_public->data(), kyber_public->size());

    std::string serialized;
    if (!proto_bundle.SerializeToString(&serialized)) {
        fill_error(out_error, EPP_ERROR_ENCODE, "Failed to serialize PreKeyBundle");
        return EPP_ERROR_ENCODE;
    }

    if (!copy_to_buffer(
        std::span(reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size()),
        out_bundle,
        out_error)) {
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }

    return EPP_SUCCESS;
}

#ifndef EPP_SERVER_BUILD
EppErrorCode epp_handshake_initiator_start(
    EppIdentityHandle* identity_keys,
    const uint8_t* peer_prekey_bundle,
    size_t peer_prekey_bundle_length,
    const EppSessionConfig* config,
    EppHandshakeInitiatorHandle** out_handle,
    EppBuffer* out_handshake_init,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!identity_keys || !identity_keys->identity_keys) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Identity keys handle is null");
        return EPP_ERROR_NULL_POINTER;
    }
    if (!validate_buffer_param(peer_prekey_bundle, peer_prekey_bundle_length, out_error) ||
        !validate_output_handle(out_handle, out_error) ||
        !validate_output_handle(out_handshake_init, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (!validate_session_config(config, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_INVALID_INPUT;
    }

    if (peer_prekey_bundle_length > ecliptix::protocol::kMaxProtobufMessageSize) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Message too large");
        return EPP_ERROR_INVALID_INPUT;
    }
    ecliptix::proto::protocol::PreKeyBundle peer_bundle;
    if (!peer_bundle.ParseFromArray(peer_prekey_bundle, static_cast<int>(peer_prekey_bundle_length))) {
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse peer PreKeyBundle");
        return EPP_ERROR_DECODE;
    }
    if (peer_bundle.kyber_public().empty()) {
        fill_error(out_error, EPP_ERROR_PQ_MISSING, "Peer bundle missing Kyber public key");
        return EPP_ERROR_PQ_MISSING;
    }
    if (peer_bundle.kyber_public().size() != kKyberPublicKeyBytes) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid peer Kyber public key size");
        return EPP_ERROR_INVALID_INPUT;
    }

    auto handshake_result = ecliptix::protocol::HandshakeInitiator::Start(
        *identity_keys->identity_keys,
        peer_bundle,
        config->max_messages_per_chain);
    if (handshake_result.IsErr()) {
        return fill_error_from_failure(out_error, handshake_result.UnwrapErr());
    }

    auto* handle = new(std::nothrow) EppHandshakeInitiatorHandle{};
    if (!handle) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate handshake handle");
        return EPP_ERROR_OUT_OF_MEMORY;
    }
    handle->handshake = std::move(handshake_result).Unwrap();

    const auto& init_bytes = handle->handshake->EncodedMessage();
    if (!copy_to_buffer(std::span(init_bytes.data(), init_bytes.size()), out_handshake_init, out_error)) {
        delete handle;
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }

    *out_handle = handle;
    return EPP_SUCCESS;
}

EppErrorCode epp_handshake_initiator_finish(
    EppHandshakeInitiatorHandle* handle,
    const uint8_t* handshake_ack,
    size_t handshake_ack_length,
    EppSessionHandle** out_session,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->handshake) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Handshake initiator handle is null or consumed");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(handshake_ack, handshake_ack_length, out_error) ||
        !validate_output_handle(out_session, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }

    if (handshake_ack_length > ecliptix::protocol::kMaxProtobufMessageSize) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Message too large");
        return EPP_ERROR_INVALID_INPUT;
    }
    ecliptix::proto::protocol::HandshakeAck ack;
    if (!ack.ParseFromArray(handshake_ack, static_cast<int>(handshake_ack_length))) {
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse HandshakeAck");
        return EPP_ERROR_DECODE;
    }

    auto session_result = handle->handshake->Finish(ack);
    if (session_result.IsErr()) {
        return fill_error_from_failure(out_error, session_result.UnwrapErr());
    }

    auto* session_handle = new(std::nothrow) EppSessionHandle{};
    if (!session_handle) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate session handle");
        return EPP_ERROR_OUT_OF_MEMORY;
    }
    session_handle->session = std::move(session_result).Unwrap();
    handle->handshake.reset();

    *out_session = session_handle;
    return EPP_SUCCESS;
}

void epp_handshake_initiator_destroy(EppHandshakeInitiatorHandle* handle) {
    delete handle;
}
#endif

EppErrorCode epp_handshake_responder_start(
    EppIdentityHandle* identity_keys,
    const uint8_t* local_prekey_bundle,
    size_t local_prekey_bundle_length,
    const uint8_t* handshake_init,
    size_t handshake_init_length,
    const EppSessionConfig* config,
    EppHandshakeResponderHandle** out_handle,
    EppBuffer* out_handshake_ack,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!identity_keys || !identity_keys->identity_keys) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Identity keys handle is null");
        return EPP_ERROR_NULL_POINTER;
    }
    if (!validate_buffer_param(local_prekey_bundle, local_prekey_bundle_length, out_error) ||
        !validate_buffer_param(handshake_init, handshake_init_length, out_error) ||
        !validate_output_handle(out_handle, out_error) ||
        !validate_output_handle(out_handshake_ack, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (!validate_session_config(config, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_INVALID_INPUT;
    }

    if (local_prekey_bundle_length > ecliptix::protocol::kMaxProtobufMessageSize) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Message too large");
        return EPP_ERROR_INVALID_INPUT;
    }
    ecliptix::proto::protocol::PreKeyBundle local_bundle;
    if (!local_bundle.ParseFromArray(local_prekey_bundle, static_cast<int>(local_prekey_bundle_length))) {
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse local PreKeyBundle");
        return EPP_ERROR_DECODE;
    }
    if (local_bundle.kyber_public().empty()) {
        fill_error(out_error, EPP_ERROR_PQ_MISSING, "Local bundle missing Kyber public key");
        return EPP_ERROR_PQ_MISSING;
    }
    if (local_bundle.kyber_public().size() != kKyberPublicKeyBytes) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid local Kyber public key size");
        return EPP_ERROR_INVALID_INPUT;
    }

    auto handshake_result = ecliptix::protocol::HandshakeResponder::Process(
        *identity_keys->identity_keys,
        local_bundle,
        std::span(handshake_init, handshake_init_length),
        config->max_messages_per_chain);
    if (handshake_result.IsErr()) {
        return fill_error_from_failure(out_error, handshake_result.UnwrapErr());
    }

    auto* handle = new(std::nothrow) EppHandshakeResponderHandle{};
    if (!handle) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate handshake handle");
        return EPP_ERROR_OUT_OF_MEMORY;
    }
    handle->handshake = std::move(handshake_result).Unwrap();

    const auto& ack_bytes = handle->handshake->EncodedAck();
    if (!copy_to_buffer(std::span(ack_bytes.data(), ack_bytes.size()), out_handshake_ack, out_error)) {
        delete handle;
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }

    *out_handle = handle;
    return EPP_SUCCESS;
}

EppErrorCode epp_handshake_responder_finish(
    EppHandshakeResponderHandle* handle,
    EppSessionHandle** out_session,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->handshake) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Handshake responder handle is null or consumed");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_output_handle(out_session, out_error)) {
        return EPP_ERROR_NULL_POINTER;
    }

    auto session_result = handle->handshake->Finish();
    if (session_result.IsErr()) {
        return fill_error_from_failure(out_error, session_result.UnwrapErr());
    }

    auto* session_handle = new(std::nothrow) EppSessionHandle{};
    if (!session_handle) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate session handle");
        return EPP_ERROR_OUT_OF_MEMORY;
    }
    session_handle->session = std::move(session_result).Unwrap();
    handle->handshake.reset();

    *out_session = session_handle;
    return EPP_SUCCESS;
}

void epp_handshake_responder_destroy(EppHandshakeResponderHandle* handle) {
    delete handle;
}

EppErrorCode epp_session_encrypt(
    EppSessionHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    EppEnvelopeType envelope_type,
    uint32_t envelope_id,
    const char* correlation_id,
    size_t correlation_id_length,
    EppBuffer* out_encrypted_envelope,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->session) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Session handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(plaintext, plaintext_length, out_error) ||
        !validate_output_handle(out_encrypted_envelope, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (correlation_id_length > 0 && !correlation_id) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Correlation id is null");
        return EPP_ERROR_NULL_POINTER;
    }

    if (envelope_type < EPP_ENVELOPE_REQUEST || envelope_type > EPP_ENVELOPE_ERROR_RESPONSE) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid envelope type");
        return EPP_ERROR_INVALID_INPUT;
    }

    std::string_view correlation_view;
    if (correlation_id && correlation_id_length > 0) {
        correlation_view = std::string_view(correlation_id, correlation_id_length);
    }

    auto encrypt_result = handle->session->Encrypt(
        std::span(plaintext, plaintext_length),
        static_cast<ecliptix::proto::protocol::EnvelopeType>(envelope_type),
        envelope_id,
        correlation_view);
    if (encrypt_result.IsErr()) {
        return fill_error_from_failure(out_error, encrypt_result.UnwrapErr());
    }

    const auto& envelope = encrypt_result.Unwrap();
    std::string serialized;
    if (!envelope.SerializeToString(&serialized)) {
        fill_error(out_error, EPP_ERROR_ENCODE, "Failed to serialize SecureEnvelope");
        return EPP_ERROR_ENCODE;
    }
    if (!copy_to_buffer(
        std::span(reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size()),
        out_encrypted_envelope,
        out_error)) {
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }

    return EPP_SUCCESS;
}

EppErrorCode epp_session_decrypt(
    EppSessionHandle* handle,
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppBuffer* out_plaintext,
    EppBuffer* out_metadata,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->session) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Session handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(encrypted_envelope, encrypted_envelope_length, out_error) ||
        !validate_output_handle(out_plaintext, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (out_metadata && !validate_output_handle(out_metadata, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }

    if (encrypted_envelope_length > ecliptix::protocol::kMaxProtobufMessageSize) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Message too large");
        return EPP_ERROR_INVALID_INPUT;
    }
    ecliptix::proto::protocol::SecureEnvelope envelope;
    if (!envelope.ParseFromArray(encrypted_envelope, static_cast<int>(encrypted_envelope_length))) {
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse SecureEnvelope");
        return EPP_ERROR_DECODE;
    }

    auto decrypt_result = handle->session->Decrypt(envelope);
    if (decrypt_result.IsErr()) {
        return fill_error_from_failure(out_error, decrypt_result.UnwrapErr());
    }

    auto result = std::move(decrypt_result).Unwrap();
    std::string metadata_serialized;
    if (out_metadata) {
        if (!result.metadata.SerializeToString(&metadata_serialized)) {
            fill_error(out_error, EPP_ERROR_ENCODE, "Failed to serialize EnvelopeMetadata");
            return EPP_ERROR_ENCODE;
        }
        if (!copy_to_buffer(
            std::span(reinterpret_cast<const uint8_t*>(metadata_serialized.data()), metadata_serialized.size()),
            out_metadata,
            out_error)) {
            return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
        }
    }

    if (!copy_to_buffer(std::span(result.plaintext.data(), result.plaintext.size()), out_plaintext, out_error)) {
        if (out_metadata && out_metadata->data) {
            SodiumInterop::SecureWipe(std::span(out_metadata->data, out_metadata->length));
            delete[] out_metadata->data;
            out_metadata->data = nullptr;
            out_metadata->length = 0;
        }
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }

    return EPP_SUCCESS;
}

EppErrorCode epp_session_serialize(
    EppSessionHandle* handle,
    EppBuffer* out_state,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->session) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Session handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_output_handle(out_state, out_error)) {
        return EPP_ERROR_NULL_POINTER;
    }

    auto state_result = handle->session->ExportState();
    if (state_result.IsErr()) {
        return fill_error_from_failure(out_error, state_result.UnwrapErr());
    }

    const auto& state = state_result.Unwrap();
    std::string serialized;
    if (!state.SerializeToString(&serialized)) {
        fill_error(out_error, EPP_ERROR_ENCODE, "Failed to serialize ProtocolState");
        return EPP_ERROR_ENCODE;
    }
    if (!copy_to_buffer(
        std::span(reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size()),
        out_state,
        out_error)) {
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }

    return EPP_SUCCESS;
}

EppErrorCode epp_session_deserialize(
    const uint8_t* state_bytes,
    size_t state_bytes_length,
    EppSessionHandle** out_handle,
    EppError* out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!validate_buffer_param(state_bytes, state_bytes_length, out_error) ||
        !validate_output_handle(out_handle, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }

    if (state_bytes_length > ecliptix::protocol::kMaxProtobufMessageSize) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Message too large");
        return EPP_ERROR_INVALID_INPUT;
    }
    ecliptix::proto::protocol::ProtocolState state;
    if (!state.ParseFromArray(state_bytes, static_cast<int>(state_bytes_length))) {
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse ProtocolState");
        return EPP_ERROR_DECODE;
    }

    auto session_result = ecliptix::protocol::Session::FromState(state);
    if (session_result.IsErr()) {
        return fill_error_from_failure(out_error, session_result.UnwrapErr());
    }

    auto* handle = new(std::nothrow) EppSessionHandle{};
    if (!handle) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate session handle");
        return EPP_ERROR_OUT_OF_MEMORY;
    }
    handle->session = std::move(session_result).Unwrap();

    *out_handle = handle;
    return EPP_SUCCESS;
}

void epp_session_destroy(EppSessionHandle* handle) {
    delete handle;
}

EppErrorCode epp_envelope_validate(
    const uint8_t* encrypted_envelope,
    const size_t encrypted_envelope_length,
    EppError* out_error) {
    if (!validate_buffer_param(encrypted_envelope, encrypted_envelope_length, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (encrypted_envelope_length > ecliptix::protocol::kMaxProtobufMessageSize) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Message too large");
        return EPP_ERROR_INVALID_INPUT;
    }

    ecliptix::proto::protocol::SecureEnvelope envelope;
    if (!envelope.ParseFromArray(encrypted_envelope, static_cast<int>(encrypted_envelope_length))) {
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse envelope");
        return EPP_ERROR_DECODE;
    }

    if (envelope.version() != kProtocolVersion) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid envelope version");
        return EPP_ERROR_INVALID_INPUT;
    }

    if (envelope.encrypted_metadata().size() <= kAesGcmTagBytes) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Encrypted metadata too small");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (envelope.encrypted_payload().size() < kAesGcmTagBytes) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Encrypted payload too small");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (envelope.header_nonce().size() != kAesGcmNonceBytes) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid header nonce size");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (std::all_of(envelope.header_nonce().begin(), envelope.header_nonce().end(),
                    [](const char value) { return value == 0; })) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Header nonce must not be all zeros");
        return EPP_ERROR_INVALID_INPUT;
    }

    const bool has_dh = envelope.has_dh_public_key();
    const bool has_pq = envelope.has_kyber_ciphertext();
    if (has_dh != has_pq) {
        fill_error(out_error, EPP_ERROR_PQ_MISSING, "Incomplete hybrid ratchet header");
        return EPP_ERROR_PQ_MISSING;
    }
    if (has_dh && envelope.ratchet_epoch() == 0) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Ratchet header requires non-zero epoch");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (has_dh && envelope.dh_public_key().size() != kX25519PublicKeyBytes) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid DH public key size");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (has_pq && envelope.kyber_ciphertext().size() != kKyberCiphertextBytes) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid Kyber ciphertext size");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (has_dh) {
        auto dh_check = security::DhValidator::ValidateX25519PublicKey(
            std::span(reinterpret_cast<const uint8_t*>(envelope.dh_public_key().data()),
                      envelope.dh_public_key().size()));
        if (dh_check.IsErr()) {
            return fill_error_from_failure(out_error, dh_check.UnwrapErr());
        }
    }
    if (has_pq) {
        auto pq_check = KyberInterop::ValidateCiphertext(
            std::span(reinterpret_cast<const uint8_t*>(envelope.kyber_ciphertext().data()),
                      envelope.kyber_ciphertext().size()));
        if (pq_check.IsErr()) {
            auto pq_err = pq_check.UnwrapErr();
            fill_error(out_error, EPP_ERROR_INVALID_INPUT, pq_err.message);
            return EPP_ERROR_INVALID_INPUT;
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

    if (opaque_session_key_length != kOpaqueSessionKeyBytes) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT,
                   "OPAQUE session key must be 32 bytes");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (user_context_length == 0) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "OPAQUE user context must not be empty");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (out_root_key_length < kRootKeyBytes) {
        fill_error(out_error, EPP_ERROR_BUFFER_TOO_SMALL,
                   "Output buffer too small for derived root key");
        return EPP_ERROR_BUFFER_TOO_SMALL;
    }

    const auto info = kOpaqueRootInfo;
    const std::span<const uint8_t> info_span(
        reinterpret_cast<const uint8_t*>(info.data()),
        info.size());

    auto root_result = Hkdf::DeriveKeyBytes(
        std::span(opaque_session_key, opaque_session_key_length),
        kRootKeyBytes,
        std::span(user_context, user_context_length),
        info_span);
    if (root_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(root_result).UnwrapErr());
    }
    auto root = root_result.Unwrap();
    std::memcpy(out_root_key, root.data(), kRootKeyBytes);
    const auto _wipe = SodiumInterop::SecureWipe(std::span(root));
    (void)_wipe;
    return EPP_SUCCESS;
}

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
    if (share_length > ecliptix::protocol::kMaxShareSize) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Share too large");
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

void epp_buffer_release(EppBuffer* buffer) {
    if (!buffer) {
        return;
    }
    if (buffer->data) {
        SodiumInterop::SecureWipe(std::span(buffer->data, buffer->length));
        delete[] buffer->data;
        buffer->data = nullptr;
    }
    buffer->length = 0;
}

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
    if (!buffer) {
        return;
    }
    epp_buffer_release(buffer);
    delete buffer;
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

}
