#include "ecliptix/c_api/ecliptix_c_api.h"
#include "ecliptix/protocol/ecliptix_protocol_system.hpp"
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/identity/ecliptix_system_identity_keys.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/constants.hpp"
#include "common/secure_envelope.pb.h"
#include "protocol/protocol_state.pb.h"
#include "protocol/key_exchange.pb.h"
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::identity;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::models;
using ecliptix::proto::common::SecureEnvelope;
using namespace ecliptix::proto::protocol;
using crypto::KyberInterop;

struct EcliptixProtocolSystemHandle {
    std::unique_ptr<EcliptixProtocolSystem> system;
    std::shared_ptr<IProtocolEventHandler> event_handler;
};

struct EcliptixProtocolConnectionHandle {
    std::unique_ptr<EcliptixProtocolConnection> connection;
};

struct EcliptixIdentityKeysHandle {
    std::unique_ptr<EcliptixSystemIdentityKeys> identity_keys;
};

namespace {
    class CApiEventHandler : public IProtocolEventHandler {
    public:
        CApiEventHandler(EcliptixProtocolEventCallback callback, void *user_data)
            : callback_(callback), user_data_(user_data) {
        }

        void OnProtocolStateChanged(uint32_t connection_id) override {
            if (callback_) {
                callback_(connection_id, user_data_);
            }
        }

        void OnRatchetRequired(uint32_t connect_id, const std::string &reason) override {
        }

    private:
        EcliptixProtocolEventCallback callback_;
        void *user_data_;
    };

    void fill_error(EcliptixError *out_error, EcliptixErrorCode code, const std::string &message) {
        if (out_error) {
            out_error->code = code;
            out_error->message = strdup(message.c_str());
        }
    }

    void fill_error_from_failure(EcliptixError *out_error, const EcliptixProtocolFailure &failure) {
        if (!out_error) return;

        EcliptixErrorCode code = ECLIPTIX_ERROR_GENERIC;

        switch (failure.type) {
            case EcliptixProtocolFailureType::KeyGeneration:
                code = ECLIPTIX_ERROR_KEY_GENERATION;
                break;
            case EcliptixProtocolFailureType::DeriveKey:
                code = ECLIPTIX_ERROR_DERIVE_KEY;
                break;
            case EcliptixProtocolFailureType::Handshake:
                code = ECLIPTIX_ERROR_HANDSHAKE;
                break;
            case EcliptixProtocolFailureType::Decode:
                code = ECLIPTIX_ERROR_DECODE;
                break;
            case EcliptixProtocolFailureType::Encode:
                code = ECLIPTIX_ERROR_ENCODE;
                break;
            case EcliptixProtocolFailureType::BufferTooSmall:
                code = ECLIPTIX_ERROR_BUFFER_TOO_SMALL;
                break;
            case EcliptixProtocolFailureType::ObjectDisposed:
                code = ECLIPTIX_ERROR_OBJECT_DISPOSED;
                break;
            case EcliptixProtocolFailureType::InvalidInput:
                code = ECLIPTIX_ERROR_INVALID_INPUT;
                break;
            case EcliptixProtocolFailureType::PrepareLocal:
                code = ECLIPTIX_ERROR_PREPARE_LOCAL;
                break;
            case EcliptixProtocolFailureType::PeerPubKey:
                code = ECLIPTIX_ERROR_HANDSHAKE;
                break;
            default:
                code = ECLIPTIX_ERROR_GENERIC;
                break;
        }

        fill_error(out_error, code, failure.message);
    }

    bool validate_buffer_param(const uint8_t *data, size_t length, EcliptixError *out_error) {
        if (!data && length > 0) {
            fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "Buffer data is null but length is non-zero");
            return false;
        }
        return true;
    }

    bool validate_output_handle(void *handle, EcliptixError *out_error) {
        if (!handle) {
            fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "Output handle pointer is null");
            return false;
        }
        return true;
    }

    bool copy_to_buffer(std::span<const uint8_t> input, EcliptixBuffer *out_buffer, EcliptixError *out_error) {
        if (!out_buffer) {
            fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "Output buffer is null");
            return false;
        }
        auto *data = new(std::nothrow) uint8_t[input.size()];
        if (!data) {
            fill_error(out_error, ECLIPTIX_ERROR_OUT_OF_MEMORY, "Failed to allocate output buffer");
            return false;
        }
        std::memcpy(data, input.data(), input.size());
        out_buffer->data = data;
        out_buffer->length = input.size();
        return true;
    }

    Result<LocalPublicKeyBundle, EcliptixProtocolFailure> build_local_bundle(const PublicKeyBundle &proto_bundle) {
        if (proto_bundle.identity_public_key().empty() || proto_bundle.identity_x25519_public_key().empty()) {
            return Result<LocalPublicKeyBundle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Peer bundle missing identity keys"));
        }
        if (proto_bundle.signed_pre_key_public_key().empty() || proto_bundle.signed_pre_key_signature().empty()) {
            return Result<LocalPublicKeyBundle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Peer bundle missing signed pre-key material"));
        }

        std::vector<OneTimePreKeyRecord> otps;
        otps.reserve(proto_bundle.one_time_pre_keys_size());
        for (const auto &otp : proto_bundle.one_time_pre_keys()) {
            if (otp.public_key().empty()) {
                return Result<LocalPublicKeyBundle, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput("Peer bundle contains empty one-time pre-key"));
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

        return Result<LocalPublicKeyBundle, EcliptixProtocolFailure>::Ok(
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
                std::move(kyber)));
    }
}

extern "C" {
const char *ecliptix_get_version(void) {
    return "1.0.0";
}

EcliptixErrorCode ecliptix_initialize(void) {
    auto result = SodiumInterop::Initialize();
    if (result.IsErr()) {
        return ECLIPTIX_ERROR_SODIUM_FAILURE;
    }
    return ECLIPTIX_SUCCESS;
}

void ecliptix_shutdown(void) {
}

EcliptixErrorCode ecliptix_identity_keys_create(
    EcliptixIdentityKeysHandle **out_handle,
    EcliptixError *out_error) {
    if (!validate_output_handle(out_handle, out_error)) {
        return ECLIPTIX_ERROR_NULL_POINTER;
    }

    constexpr uint32_t default_one_time_key_count = 100;
    auto result = EcliptixSystemIdentityKeys::Create(default_one_time_key_count);
    if (result.IsErr()) {
        fill_error_from_failure(out_error, std::move(result).UnwrapErr());
        return out_error->code;
    }

    auto *handle = new(std::nothrow) EcliptixIdentityKeysHandle{
        std::make_unique<EcliptixSystemIdentityKeys>(std::move(result).Unwrap())
    };

    if (!handle) {
        fill_error(out_error, ECLIPTIX_ERROR_OUT_OF_MEMORY, "Failed to allocate identity keys handle");
        return ECLIPTIX_ERROR_OUT_OF_MEMORY;
    }

    *out_handle = handle;
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_identity_keys_create_from_seed(
    const uint8_t *seed,
    size_t seed_length,
    EcliptixIdentityKeysHandle **out_handle,
    EcliptixError *out_error) {
    if (!validate_output_handle(out_handle, out_error) ||
        !validate_buffer_param(seed, seed_length, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }

    constexpr size_t expected_master_key_size = 32;
    if (seed_length != expected_master_key_size) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT,
                   "Master key length must be " + std::to_string(expected_master_key_size) + " bytes");
        return ECLIPTIX_ERROR_INVALID_INPUT;
    }

    constexpr uint32_t default_one_time_key_count = 100;
    const std::string_view default_membership_id = "default";

    std::span<const uint8_t> master_key_span(seed, seed_length);
    auto result = EcliptixSystemIdentityKeys::CreateFromMasterKey(
        master_key_span,
        default_membership_id,
        default_one_time_key_count
    );

    if (result.IsErr()) {
        fill_error_from_failure(out_error, std::move(result).UnwrapErr());
        return out_error->code;
    }

    auto *handle = new(std::nothrow) EcliptixIdentityKeysHandle{
        std::make_unique<EcliptixSystemIdentityKeys>(std::move(result).Unwrap())
    };

    if (!handle) {
        fill_error(out_error, ECLIPTIX_ERROR_OUT_OF_MEMORY, "Failed to allocate identity keys handle");
        return ECLIPTIX_ERROR_OUT_OF_MEMORY;
    }

    *out_handle = handle;
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_identity_keys_create_from_seed_with_context(
    const uint8_t *seed,
    size_t seed_length,
    const char *membership_id,
    size_t membership_id_length,
    EcliptixIdentityKeysHandle **out_handle,
    EcliptixError *out_error) {
    if (!validate_output_handle(out_handle, out_error) ||
        !validate_buffer_param(seed, seed_length, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }
    if (!membership_id || membership_id_length == 0) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT, "Membership id must not be empty");
        return ECLIPTIX_ERROR_INVALID_INPUT;
    }

    constexpr size_t expected_master_key_size = 32;
    if (seed_length != expected_master_key_size) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT,
                   "Master key length must be " + std::to_string(expected_master_key_size) + " bytes");
        return ECLIPTIX_ERROR_INVALID_INPUT;
    }

    constexpr uint32_t default_one_time_key_count = 100;
    std::span<const uint8_t> master_key_span(seed, seed_length);
    std::string_view membership_view(membership_id, membership_id_length);

    auto result = EcliptixSystemIdentityKeys::CreateFromMasterKey(
        master_key_span,
        membership_view,
        default_one_time_key_count
    );

    if (result.IsErr()) {
        fill_error_from_failure(out_error, std::move(result).UnwrapErr());
        return out_error->code;
    }

    auto *handle = new(std::nothrow) EcliptixIdentityKeysHandle{
        std::make_unique<EcliptixSystemIdentityKeys>(std::move(result).Unwrap())
    };

    if (!handle) {
        fill_error(out_error, ECLIPTIX_ERROR_OUT_OF_MEMORY, "Failed to allocate identity keys handle");
        return ECLIPTIX_ERROR_OUT_OF_MEMORY;
    }

    *out_handle = handle;
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_identity_keys_get_public_x25519(
    const EcliptixIdentityKeysHandle *handle,
    uint8_t *out_key,
    size_t out_key_length,
    EcliptixError *out_error) {
    if (!handle || !handle->identity_keys) {
        fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "Identity keys handle is null");
        return ECLIPTIX_ERROR_NULL_POINTER;
    }

    if (!validate_buffer_param(out_key, out_key_length, out_error)) {
        return out_error->code;
    }

    if (out_key_length != Constants::X_25519_PUBLIC_KEY_SIZE) {
        fill_error(out_error, ECLIPTIX_ERROR_BUFFER_TOO_SMALL,
                   "Output buffer must be " + std::to_string(Constants::X_25519_PUBLIC_KEY_SIZE) + " bytes");
        return ECLIPTIX_ERROR_BUFFER_TOO_SMALL;
    }

    const auto &key = handle->identity_keys->GetIdentityX25519PublicKeyCopy();
    std::memcpy(out_key, key.data(), key.size());

    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_identity_keys_get_public_ed25519(
    const EcliptixIdentityKeysHandle *handle,
    uint8_t *out_key,
    size_t out_key_length,
    EcliptixError *out_error) {
    if (!handle || !handle->identity_keys) {
        fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "Identity keys handle is null");
        return ECLIPTIX_ERROR_NULL_POINTER;
    }

    if (!validate_buffer_param(out_key, out_key_length, out_error)) {
        return out_error->code;
    }

    if (out_key_length != Constants::ED_25519_PUBLIC_KEY_SIZE) {
        fill_error(out_error, ECLIPTIX_ERROR_BUFFER_TOO_SMALL,
                   "Output buffer must be " + std::to_string(Constants::ED_25519_PUBLIC_KEY_SIZE) + " bytes");
        return ECLIPTIX_ERROR_BUFFER_TOO_SMALL;
    }

    const auto &key = handle->identity_keys->GetIdentityEd25519PublicKeyCopy();
    std::memcpy(out_key, key.data(), key.size());

    return ECLIPTIX_SUCCESS;
}

void ecliptix_identity_keys_destroy(EcliptixIdentityKeysHandle *handle) {
    delete handle;
}

EcliptixErrorCode ecliptix_protocol_system_create(
    EcliptixIdentityKeysHandle *identity_keys,
    EcliptixProtocolSystemHandle **out_handle,
    EcliptixError *out_error) {
    if (!identity_keys || !identity_keys->identity_keys) {
        fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "Identity keys handle is null");
        return ECLIPTIX_ERROR_NULL_POINTER;
    }

    if (!validate_output_handle(out_handle, out_error)) {
        return ECLIPTIX_ERROR_NULL_POINTER;
    }

    auto *handle = new(std::nothrow) EcliptixProtocolSystemHandle{};
    if (!handle) {
        fill_error(out_error, ECLIPTIX_ERROR_OUT_OF_MEMORY, "Failed to allocate protocol system handle");
        return ECLIPTIX_ERROR_OUT_OF_MEMORY;
    }

    if (!identity_keys->identity_keys) {
        delete handle;
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Identity keys handle is uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }

    auto system_result = EcliptixProtocolSystem::Create(std::move(identity_keys->identity_keys));
    if (system_result.IsErr()) {
        delete handle;
        fill_error_from_failure(out_error, std::move(system_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    handle->system = std::move(system_result).Unwrap();
    identity_keys->identity_keys.reset();

    *out_handle = handle;
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_set_callbacks(
    EcliptixProtocolSystemHandle *handle,
    const EcliptixCallbacks *callbacks,
    EcliptixError *out_error) {
    if (!handle) {
        fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "Protocol system handle is null");
        return ECLIPTIX_ERROR_NULL_POINTER;
    }

    if (callbacks && callbacks->on_protocol_state_changed) {
        handle->event_handler = std::make_shared<CApiEventHandler>(
            callbacks->on_protocol_state_changed,
            callbacks->user_data
        );

        if (handle->system) {
            handle->system->SetEventHandler(handle->event_handler);
        }
    } else {
        handle->event_handler = nullptr;
        if (handle->system) {
            handle->system->SetEventHandler(nullptr);
        }
    }

    return ECLIPTIX_SUCCESS;
}

void ecliptix_protocol_system_destroy(EcliptixProtocolSystemHandle *handle) {
    delete handle;
}

EcliptixErrorCode ecliptix_protocol_system_begin_handshake(
    EcliptixProtocolSystemHandle *handle,
    uint32_t connection_id,
    uint8_t exchange_type,
    EcliptixBuffer *out_handshake_message,
    EcliptixError *out_error) {
    (void) connection_id;
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!validate_output_handle(out_handshake_message, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }

    auto bundle_result = handle->system->GetIdentityKeys().CreatePublicBundle();
    if (bundle_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(bundle_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    const auto &bundle = bundle_result.Unwrap();
    ecliptix::proto::protocol::PublicKeyBundle proto_bundle;
    proto_bundle.set_identity_public_key(bundle.GetEd25519Public().data(), bundle.GetEd25519Public().size());
    proto_bundle.set_identity_x25519_public_key(bundle.GetIdentityX25519().data(), bundle.GetIdentityX25519().size());
    proto_bundle.set_signed_pre_key_id(bundle.GetSignedPreKeyId());
    proto_bundle.set_signed_pre_key_public_key(bundle.GetSignedPreKeyPublic().data(),
                                               bundle.GetSignedPreKeyPublic().size());
    proto_bundle.set_signed_pre_key_signature(bundle.GetSignedPreKeySignature().data(),
                                              bundle.GetSignedPreKeySignature().size());
    for (const auto &otp : bundle.GetOneTimePreKeys()) {
        auto *otp_proto = proto_bundle.add_one_time_pre_keys();
        otp_proto->set_pre_key_id(otp.GetPreKeyId());
        const auto &pub = otp.GetPublicKey();
        otp_proto->set_public_key(pub.data(), pub.size());
    }
    if (bundle.HasEphemeralKey()) {
        const auto &eph = bundle.GetEphemeralX25519Public();
        proto_bundle.set_ephemeral_x25519_public_key(eph->data(), eph->size());
    }
    if (bundle.HasKyberKey()) {
        const auto &kyber = bundle.GetKyberPublicKey();
        proto_bundle.set_kyber_public_key(kyber->data(), kyber->size());
    }

    ecliptix::proto::protocol::PubKeyExchange handshake;
    handshake.set_state(ecliptix::proto::protocol::PubKeyExchangeState::INIT);
    handshake.set_of_type(static_cast<ecliptix::proto::protocol::PubKeyExchangeType>(exchange_type));
    handshake.set_payload(proto_bundle.SerializeAsString());
    // initial_Dh_public_Key left empty because bootstrap uses pre-shared root key.

    handle->system->SetPendingInitiator(true);

    const std::string serialized = handshake.SerializeAsString();
    if (!copy_to_buffer(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size()),
        out_handshake_message,
        out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_OUT_OF_MEMORY;
    }
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_complete_handshake(
    EcliptixProtocolSystemHandle *handle,
    const uint8_t *peer_handshake_message,
    size_t peer_handshake_message_length,
    const uint8_t *root_key,
    size_t root_key_length,
    EcliptixError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(peer_handshake_message, peer_handshake_message_length, out_error) ||
        !validate_buffer_param(root_key, root_key_length, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }
    if (root_key_length != Constants::X_25519_KEY_SIZE) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT, "Root key must be 32 bytes");
        return ECLIPTIX_ERROR_INVALID_INPUT;
    }

    ecliptix::proto::protocol::PubKeyExchange peer_exchange;
    if (!peer_exchange.ParseFromArray(peer_handshake_message, static_cast<int>(peer_handshake_message_length))) {
        // Try direct bundle parsing as a fallback.
        ecliptix::proto::protocol::PublicKeyBundle direct_bundle;
        if (!direct_bundle.ParseFromArray(peer_handshake_message, static_cast<int>(peer_handshake_message_length))) {
            fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Failed to parse peer handshake");
            return ECLIPTIX_ERROR_DECODE;
        }
        auto finalize_result = handle->system->FinalizeWithRootAndPeerBundle(
            std::span<const uint8_t>(root_key, root_key_length),
            direct_bundle,
            handle->system->GetPendingInitiator().value_or(false));
        if (finalize_result.IsErr()) {
            fill_error_from_failure(out_error, std::move(finalize_result).UnwrapErr());
            return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
        }
        return ECLIPTIX_SUCCESS;
    }

    ecliptix::proto::protocol::PublicKeyBundle peer_bundle;
    if (!peer_bundle.ParseFromString(peer_exchange.payload())) {
        fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Failed to parse peer public bundle");
        return ECLIPTIX_ERROR_DECODE;
    }

    bool is_initiator = handle->system->GetPendingInitiator().value_or(false);
    auto finalize_result = handle->system->FinalizeWithRootAndPeerBundle(
        std::span<const uint8_t>(root_key, root_key_length),
        peer_bundle,
        is_initiator);
    if (finalize_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(finalize_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_complete_handshake_auto(
    EcliptixProtocolSystemHandle *handle,
    const uint8_t *peer_handshake_message,
    size_t peer_handshake_message_length,
    EcliptixError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(peer_handshake_message, peer_handshake_message_length, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }

    PubKeyExchange peer_exchange;
    if (!peer_exchange.ParseFromArray(peer_handshake_message, static_cast<int>(peer_handshake_message_length))) {
        fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Failed to parse peer handshake");
        return ECLIPTIX_ERROR_DECODE;
    }

    PublicKeyBundle peer_bundle;
    if (!peer_bundle.ParseFromString(peer_exchange.payload())) {
        fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Failed to parse peer public bundle");
        return ECLIPTIX_ERROR_DECODE;
    }

    auto peer_bundle_result = build_local_bundle(peer_bundle);
    if (peer_bundle_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(peer_bundle_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    std::vector<uint8_t> info(ProtocolConstants::X3DH_INFO.begin(), ProtocolConstants::X3DH_INFO.end());
    auto shared_secret_result = handle->system->GetIdentityKeysMutable().X3dhDeriveSharedSecret(
        peer_bundle_result.Unwrap(),
        std::span<const uint8_t>(info));
    if (shared_secret_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(shared_secret_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    auto shared_secret_handle = std::move(shared_secret_result).Unwrap();
    std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE);
    auto read_result = shared_secret_handle.Read(root_key);
    if (read_result.IsErr()) {
        fill_error_from_failure(
            out_error,
            EcliptixProtocolFailure::FromSodiumFailure(std::move(read_result).UnwrapErr()));
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    bool is_initiator = handle->system->GetPendingInitiator().value_or(false);
    auto finalize_result = handle->system->FinalizeWithRootAndPeerBundle(
        root_key,
        peer_bundle,
        is_initiator);
    auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
    (void) _wipe_root;
    if (finalize_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(finalize_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_send_message(
    EcliptixProtocolSystemHandle *handle,
    const uint8_t *plaintext,
    size_t plaintext_length,
    EcliptixBuffer *out_encrypted_envelope,
    EcliptixError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(plaintext, plaintext_length, out_error) ||
        !validate_output_handle(out_encrypted_envelope, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }

    auto send_result = handle->system->SendMessage(std::span<const uint8_t>(plaintext, plaintext_length));
    if (send_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(send_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    const SecureEnvelope &envelope = send_result.Unwrap();
    const std::string serialized = envelope.SerializeAsString();
    if (!copy_to_buffer(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size()),
        out_encrypted_envelope,
        out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_OUT_OF_MEMORY;
    }

    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_receive_message(
    EcliptixProtocolSystemHandle *handle,
    const uint8_t *encrypted_envelope,
    size_t encrypted_envelope_length,
    EcliptixBuffer *out_plaintext,
    EcliptixError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(encrypted_envelope, encrypted_envelope_length, out_error) ||
        !validate_output_handle(out_plaintext, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }

    SecureEnvelope envelope;
    if (!envelope.ParseFromArray(encrypted_envelope, static_cast<int>(encrypted_envelope_length))) {
        fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Failed to parse envelope");
        return ECLIPTIX_ERROR_DECODE;
    }
    if (!envelope.has_ratchet_epoch()) {
        fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Missing ratchet epoch");
        return ECLIPTIX_ERROR_DECODE;
    }
    if (envelope.dh_public_key().size() > 0 && envelope.kyber_ciphertext().empty()) {
        fill_error(out_error, ECLIPTIX_ERROR_PQ_MISSING, "Missing Kyber ciphertext for hybrid ratchet");
        return ECLIPTIX_ERROR_PQ_MISSING;
    }

    auto receive_result = handle->system->ReceiveMessage(envelope);
    if (receive_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(receive_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    const auto &plaintext = receive_result.Unwrap();
    if (!copy_to_buffer(std::span<const uint8_t>(plaintext.data(), plaintext.size()), out_plaintext, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_OUT_OF_MEMORY;
    }

    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_has_connection(
    const EcliptixProtocolSystemHandle *handle,
    bool *out_has_connection,
    EcliptixError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!out_has_connection) {
        fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "out_has_connection is null");
        return ECLIPTIX_ERROR_NULL_POINTER;
    }

    *out_has_connection = handle->system->HasConnection();
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_get_connection_id(
    const EcliptixProtocolSystemHandle *handle,
    uint32_t *out_connection_id,
    EcliptixError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!out_connection_id) {
        fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "out_connection_id is null");
        return ECLIPTIX_ERROR_NULL_POINTER;
    }
    if (!handle->system->HasConnection()) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol connection not established");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }

    *out_connection_id = handle->system->GetConnectionId();
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_create_from_root(
    EcliptixIdentityKeysHandle *identity_keys,
    const uint8_t *root_key,
    size_t root_key_length,
    const uint8_t *peer_bundle,
    size_t peer_bundle_length,
    bool is_initiator,
    EcliptixProtocolSystemHandle **out_handle,
    EcliptixError *out_error) {
    if (!identity_keys || !identity_keys->identity_keys) {
        fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "Identity keys handle is null");
        return ECLIPTIX_ERROR_NULL_POINTER;
    }
    if (!validate_buffer_param(root_key, root_key_length, out_error) ||
        !validate_buffer_param(peer_bundle, peer_bundle_length, out_error) ||
        !validate_output_handle(out_handle, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }
    if (root_key_length != Constants::X_25519_KEY_SIZE) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT, "Root key must be 32 bytes");
        return ECLIPTIX_ERROR_INVALID_INPUT;
    }

    auto *handle = new(std::nothrow) EcliptixProtocolSystemHandle{};
    if (!handle) {
        fill_error(out_error, ECLIPTIX_ERROR_OUT_OF_MEMORY, "Failed to allocate protocol system handle");
        return ECLIPTIX_ERROR_OUT_OF_MEMORY;
    }

    PublicKeyBundle bundle;
    if (!bundle.ParseFromArray(peer_bundle, static_cast<int>(peer_bundle_length))) {
        delete handle;
        fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Failed to parse peer bundle");
        return ECLIPTIX_ERROR_DECODE;
    }

    auto system_result = EcliptixProtocolSystem::CreateFromRootAndPeerBundle(
        std::move(identity_keys->identity_keys),
        std::span<const uint8_t>(root_key, root_key_length),
        bundle,
        is_initiator);

    if (system_result.IsErr()) {
        delete handle;
        fill_error_from_failure(out_error, std::move(system_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    handle->system = std::move(system_result).Unwrap();
    identity_keys->identity_keys.reset();
    *out_handle = handle;
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_export_state(
    EcliptixProtocolSystemHandle *handle,
    EcliptixBuffer *out_state,
    EcliptixError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!validate_output_handle(out_state, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }

    auto state_result = handle->system->ToProtoState();
    if (state_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(state_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    const auto &state = state_result.Unwrap();
    const std::string serialized = state.SerializeAsString();
    if (!copy_to_buffer(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size()),
        out_state,
        out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_OUT_OF_MEMORY;
    }

    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_import_state(
    EcliptixIdentityKeysHandle *identity_keys,
    const uint8_t *state_bytes,
    size_t state_bytes_length,
    EcliptixProtocolSystemHandle **out_handle,
    EcliptixError *out_error) {
    if (!identity_keys || !identity_keys->identity_keys) {
        fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "Identity keys handle is null");
        return ECLIPTIX_ERROR_NULL_POINTER;
    }
    if (!validate_buffer_param(state_bytes, state_bytes_length, out_error) ||
        !validate_output_handle(out_handle, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }

    RatchetState proto_state;
    if (!proto_state.ParseFromArray(state_bytes, static_cast<int>(state_bytes_length))) {
        fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Failed to parse protocol state");
        return ECLIPTIX_ERROR_DECODE;
    }

    auto system_result = EcliptixProtocolSystem::FromProtoState(
        std::move(identity_keys->identity_keys),
        proto_state);

    if (system_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(system_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    auto *handle = new(std::nothrow) EcliptixProtocolSystemHandle{};
    if (!handle) {
        fill_error(out_error, ECLIPTIX_ERROR_OUT_OF_MEMORY, "Failed to allocate protocol system handle");
        return ECLIPTIX_ERROR_OUT_OF_MEMORY;
    }

    handle->system = std::move(system_result).Unwrap();
    identity_keys->identity_keys.reset();
    *out_handle = handle;
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_envelope_validate_hybrid_requirements(
    const uint8_t *encrypted_envelope,
    size_t encrypted_envelope_length,
    EcliptixError *out_error) {
    if (!validate_buffer_param(encrypted_envelope, encrypted_envelope_length, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }

    SecureEnvelope envelope;
    if (!envelope.ParseFromArray(encrypted_envelope, static_cast<int>(encrypted_envelope_length))) {
        fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Failed to parse envelope");
        return ECLIPTIX_ERROR_DECODE;
    }
    if (!envelope.has_ratchet_epoch()) {
        fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Missing ratchet epoch");
        return ECLIPTIX_ERROR_DECODE;
    }

    if (!envelope.dh_public_key().empty() && envelope.kyber_ciphertext().empty()) {
        fill_error(out_error, ECLIPTIX_ERROR_PQ_MISSING, "Missing Kyber ciphertext for hybrid ratchet");
        return ECLIPTIX_ERROR_PQ_MISSING;
    }

    if (!envelope.kyber_ciphertext().empty()) {
        const auto &ct = envelope.kyber_ciphertext();
        if (ct.size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
            fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Invalid Kyber ciphertext size");
            return ECLIPTIX_ERROR_DECODE;
        }
    }

    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_derive_root_from_opaque_session_key(
    const uint8_t *opaque_session_key,
    size_t opaque_session_key_length,
    const uint8_t *user_context,
    size_t user_context_length,
    uint8_t *out_root_key,
    size_t out_root_key_length,
    EcliptixError *out_error) {
    if (!validate_buffer_param(opaque_session_key, opaque_session_key_length, out_error) ||
        !validate_buffer_param(user_context, user_context_length, out_error) ||
        !validate_buffer_param(out_root_key, out_root_key_length, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }

    if (opaque_session_key_length != Constants::X_25519_KEY_SIZE) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT,
                   "OPAQUE session key must be 32 bytes");
        return ECLIPTIX_ERROR_INVALID_INPUT;
    }
    if (user_context_length == 0) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT, "OPAQUE user context must not be empty");
        return ECLIPTIX_ERROR_INVALID_INPUT;
    }
    if (out_root_key_length < Constants::X_25519_KEY_SIZE) {
        fill_error(out_error, ECLIPTIX_ERROR_BUFFER_TOO_SMALL,
                   "Output buffer too small for derived root key");
        return ECLIPTIX_ERROR_BUFFER_TOO_SMALL;
    }

    auto root_result = EcliptixProtocolConnection::DeriveOpaqueMessagingRoot(
        std::span<const uint8_t>(opaque_session_key, opaque_session_key_length),
        std::span<const uint8_t>(user_context, user_context_length));
    if (root_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(root_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }
    auto root = root_result.Unwrap();
    std::memcpy(out_root_key, root.data(), Constants::X_25519_KEY_SIZE);
    auto _wipe = SodiumInterop::SecureWipe(std::span(root));
    (void) _wipe;
    return ECLIPTIX_SUCCESS;
}

EcliptixBuffer *ecliptix_buffer_allocate(size_t capacity) {
    auto *buffer = new(std::nothrow) EcliptixBuffer{};
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

void ecliptix_buffer_free(EcliptixBuffer *buffer) {
    if (buffer) {
        if (buffer->data) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(buffer->data, buffer->length));
            delete[] buffer->data;
        }
        delete buffer;
    }
}

void ecliptix_error_free(EcliptixError *error) {
    if (error && error->message) {
        free(error->message);
        error->message = nullptr;
    }
}

const char *ecliptix_error_code_to_string(EcliptixErrorCode code) {
    switch (code) {
        case ECLIPTIX_SUCCESS: return "Success";
        case ECLIPTIX_ERROR_GENERIC: return "Generic error";
        case ECLIPTIX_ERROR_INVALID_INPUT: return "Invalid input";
        case ECLIPTIX_ERROR_KEY_GENERATION: return "Key generation failed";
        case ECLIPTIX_ERROR_DERIVE_KEY: return "Key derivation failed";
        case ECLIPTIX_ERROR_HANDSHAKE: return "Handshake failed";
        case ECLIPTIX_ERROR_ENCRYPTION: return "Encryption failed";
        case ECLIPTIX_ERROR_DECRYPTION: return "Decryption failed";
        case ECLIPTIX_ERROR_DECODE: return "Decoding failed";
        case ECLIPTIX_ERROR_ENCODE: return "Encoding failed";
        case ECLIPTIX_ERROR_BUFFER_TOO_SMALL: return "Buffer too small";
        case ECLIPTIX_ERROR_OBJECT_DISPOSED: return "Object disposed";
        case ECLIPTIX_ERROR_PREPARE_LOCAL: return "Prepare local failed";
        case ECLIPTIX_ERROR_OUT_OF_MEMORY: return "Out of memory";
        case ECLIPTIX_ERROR_SODIUM_FAILURE: return "Sodium library failure";
        case ECLIPTIX_ERROR_NULL_POINTER: return "Null pointer";
        case ECLIPTIX_ERROR_INVALID_STATE: return "Invalid state";
        case ECLIPTIX_ERROR_REPLAY_ATTACK: return "Replay attack detected";
        case ECLIPTIX_ERROR_SESSION_EXPIRED: return "Session expired";
        case ECLIPTIX_ERROR_PQ_MISSING: return "Hybrid PQ material missing";
        default: return "Unknown error";
    }
}

EcliptixErrorCode ecliptix_secure_wipe(uint8_t *data, size_t length) {
    if (!data && length > 0) {
        return ECLIPTIX_ERROR_NULL_POINTER;
    }

    if (length > 0) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(data, length));
    }

    return ECLIPTIX_SUCCESS;
}
}
