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
#include <atomic>
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
    
    
    inline EcliptixErrorCode EnsureInitialized() {
        static std::once_flag init_flag;
        static std::atomic<bool> init_success{false};

        std::call_once(init_flag, [] {
            auto result = SodiumInterop::Initialize();
            init_success.store(result.IsOk(), std::memory_order_release);
        });

        return init_success.load(std::memory_order_acquire)
            ? ECLIPTIX_SUCCESS
            : ECLIPTIX_ERROR_SODIUM_FAILURE;
    }

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
                std::move(kyber),
                std::move(kyber_ciphertext),
                used_opk_id));
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
    if (auto err = EnsureInitialized(); err != ECLIPTIX_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
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
    if (auto err = EnsureInitialized(); err != ECLIPTIX_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
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
    if (auto err = EnsureInitialized(); err != ECLIPTIX_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
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
    if (auto err = EnsureInitialized(); err != ECLIPTIX_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
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
    if (auto err = EnsureInitialized(); err != ECLIPTIX_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!validate_output_handle(out_handshake_message, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }

    fprintf(stderr, "\n[BEGIN-HANDSHAKE] ========== CLIENT BeginHandshake ==========\n");

    
    handle->system->GetIdentityKeysMutable().GenerateEphemeralKeyPair();

    auto bundle_result = handle->system->GetIdentityKeys().CreatePublicBundle();
    if (bundle_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(bundle_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    const auto &bundle = bundle_result.Unwrap();

    
    fprintf(stderr, "[BEGIN-HANDSHAKE] My identity_x25519: %02x%02x%02x%02x%02x%02x%02x%02x\n",
        bundle.GetIdentityX25519()[0], bundle.GetIdentityX25519()[1],
        bundle.GetIdentityX25519()[2], bundle.GetIdentityX25519()[3],
        bundle.GetIdentityX25519()[4], bundle.GetIdentityX25519()[5],
        bundle.GetIdentityX25519()[6], bundle.GetIdentityX25519()[7]);
    fprintf(stderr, "[BEGIN-HANDSHAKE] My spk_public: %02x%02x%02x%02x%02x%02x%02x%02x\n",
        bundle.GetSignedPreKeyPublic()[0], bundle.GetSignedPreKeyPublic()[1],
        bundle.GetSignedPreKeyPublic()[2], bundle.GetSignedPreKeyPublic()[3],
        bundle.GetSignedPreKeyPublic()[4], bundle.GetSignedPreKeyPublic()[5],
        bundle.GetSignedPreKeyPublic()[6], bundle.GetSignedPreKeyPublic()[7]);
    if (bundle.HasEphemeralKey()) {
        const auto &eph = bundle.GetEphemeralX25519Public();
        fprintf(stderr, "[BEGIN-HANDSHAKE] My ephemeral_x25519: %02x%02x%02x%02x%02x%02x%02x%02x\n",
            (*eph)[0], (*eph)[1], (*eph)[2], (*eph)[3], (*eph)[4], (*eph)[5], (*eph)[6], (*eph)[7]);
    } else {
        fprintf(stderr, "[BEGIN-HANDSHAKE] WARNING: No ephemeral key!\n");
    }
    if (bundle.HasKyberKey()) {
        const auto &kyber = bundle.GetKyberPublicKey();
        fprintf(stderr, "[BEGIN-HANDSHAKE] My kyber_public: %02x%02x%02x%02x... (size=%zu)\n",
            (*kyber)[0], (*kyber)[1], (*kyber)[2], (*kyber)[3], kyber->size());
    }

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
    if (auto selected_opk = handle->system->GetIdentityKeys().GetSelectedOpkId(); selected_opk.has_value()) {
        proto_bundle.set_used_one_time_pre_key_id(selected_opk.value());
        fprintf(stderr, "[BEGIN-HANDSHAKE] Including used OPK ID in bundle: %u\n", selected_opk.value());
    } else {
        fprintf(stderr, "[BEGIN-HANDSHAKE] No OPK ID selected (1-RTT fallback)\n");
    }

    ecliptix::proto::protocol::PubKeyExchange handshake;
    handshake.set_state(ecliptix::proto::protocol::PubKeyExchangeState::INIT);
    handshake.set_of_type(static_cast<ecliptix::proto::protocol::PubKeyExchangeType>(exchange_type));
    handshake.set_payload(proto_bundle.SerializeAsString());
    

    handle->system->SetPendingInitiator(true);
    fprintf(stderr, "[BEGIN-HANDSHAKE] SetPendingInitiator(true) - I am INITIATOR\n");

    const std::string serialized = handshake.SerializeAsString();
    if (!copy_to_buffer(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size()),
        out_handshake_message,
        out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_OUT_OF_MEMORY;
    }
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_begin_handshake_with_peer_kyber(
    EcliptixProtocolSystemHandle *handle,
    uint32_t connection_id,
    uint8_t exchange_type,
    const uint8_t *peer_kyber_public_key,
    size_t peer_kyber_public_key_length,
    EcliptixBuffer *out_handshake_message,
    EcliptixError *out_error) {
    (void) connection_id;
    if (auto err = EnsureInitialized(); err != ECLIPTIX_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(peer_kyber_public_key, peer_kyber_public_key_length, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }
    if (!validate_output_handle(out_handshake_message, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }
    if (peer_kyber_public_key_length != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT, "Peer Kyber public key must be 1184 bytes");
        return ECLIPTIX_ERROR_INVALID_INPUT;
    }

    fprintf(stderr, "\n[BEGIN-HANDSHAKE-KYBER] ========== SERVER BeginHandshakeWithPeerKyber ==========\n");
    fprintf(stderr, "[BEGIN-HANDSHAKE-KYBER] Received peer kyber_public: %02x%02x%02x%02x... (size=%zu)\n",
        peer_kyber_public_key[0], peer_kyber_public_key[1], peer_kyber_public_key[2], peer_kyber_public_key[3],
        peer_kyber_public_key_length);

    
    handle->system->GetIdentityKeysMutable().GenerateEphemeralKeyPair();

    
    std::vector<uint8_t> peer_kyber_pk(peer_kyber_public_key, peer_kyber_public_key + peer_kyber_public_key_length);
    auto encap_result = KyberInterop::Encapsulate(peer_kyber_pk);
    if (encap_result.IsErr()) {
        fill_error(out_error, ECLIPTIX_ERROR_KEY_GENERATION, "Kyber encapsulation failed");
        return ECLIPTIX_ERROR_KEY_GENERATION;
    }
    auto [kyber_ciphertext, kyber_ss_handle] = std::move(encap_result).Unwrap();

    
    auto kyber_ss_result = kyber_ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
    if (kyber_ss_result.IsErr()) {
        fill_error(out_error, ECLIPTIX_ERROR_SODIUM_FAILURE, "Failed to read Kyber shared secret");
        return ECLIPTIX_ERROR_SODIUM_FAILURE;
    }
    auto kyber_shared_secret = kyber_ss_result.Unwrap();

    fprintf(stderr, "[BEGIN-HANDSHAKE-KYBER] Encapsulated kyber_ss: %02x%02x%02x%02x%02x%02x%02x%02x\n",
        kyber_shared_secret[0], kyber_shared_secret[1], kyber_shared_secret[2], kyber_shared_secret[3],
        kyber_shared_secret[4], kyber_shared_secret[5], kyber_shared_secret[6], kyber_shared_secret[7]);
    fprintf(stderr, "[BEGIN-HANDSHAKE-KYBER] kyber_ciphertext: %02x%02x%02x%02x... (size=%zu)\n",
        kyber_ciphertext[0], kyber_ciphertext[1], kyber_ciphertext[2], kyber_ciphertext[3],
        kyber_ciphertext.size());

    
    handle->system->GetIdentityKeysMutable().StorePendingKyberHandshake(
        std::move(kyber_ciphertext),
        std::move(kyber_shared_secret));

    
    auto stored_result = handle->system->GetIdentityKeys().GetPendingKyberCiphertext();
    if (stored_result.IsErr()) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Failed to retrieve stored Kyber ciphertext");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    const auto& stored_ciphertext = stored_result.Unwrap();

    auto bundle_result = handle->system->GetIdentityKeys().CreatePublicBundle();
    if (bundle_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(bundle_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    const auto &bundle = bundle_result.Unwrap();

    
    fprintf(stderr, "[BEGIN-HANDSHAKE-KYBER] My identity_x25519: %02x%02x%02x%02x%02x%02x%02x%02x\n",
        bundle.GetIdentityX25519()[0], bundle.GetIdentityX25519()[1],
        bundle.GetIdentityX25519()[2], bundle.GetIdentityX25519()[3],
        bundle.GetIdentityX25519()[4], bundle.GetIdentityX25519()[5],
        bundle.GetIdentityX25519()[6], bundle.GetIdentityX25519()[7]);
    fprintf(stderr, "[BEGIN-HANDSHAKE-KYBER] My spk_public: %02x%02x%02x%02x%02x%02x%02x%02x\n",
        bundle.GetSignedPreKeyPublic()[0], bundle.GetSignedPreKeyPublic()[1],
        bundle.GetSignedPreKeyPublic()[2], bundle.GetSignedPreKeyPublic()[3],
        bundle.GetSignedPreKeyPublic()[4], bundle.GetSignedPreKeyPublic()[5],
        bundle.GetSignedPreKeyPublic()[6], bundle.GetSignedPreKeyPublic()[7]);
    if (bundle.HasEphemeralKey()) {
        const auto &eph = bundle.GetEphemeralX25519Public();
        fprintf(stderr, "[BEGIN-HANDSHAKE-KYBER] My ephemeral_x25519: %02x%02x%02x%02x%02x%02x%02x%02x (SHOULD NOT BE USED BY SERVER!)\n",
            (*eph)[0], (*eph)[1], (*eph)[2], (*eph)[3], (*eph)[4], (*eph)[5], (*eph)[6], (*eph)[7]);
    }
    if (bundle.HasKyberKey()) {
        const auto &kyber = bundle.GetKyberPublicKey();
        fprintf(stderr, "[BEGIN-HANDSHAKE-KYBER] My kyber_public: %02x%02x%02x%02x... (size=%zu)\n",
            (*kyber)[0], (*kyber)[1], (*kyber)[2], (*kyber)[3], kyber->size());
    }

    ecliptix::proto::protocol::PublicKeyBundle proto_bundle;
    proto_bundle.set_identity_public_key(bundle.GetEd25519Public().data(), bundle.GetEd25519Public().size());
    proto_bundle.set_identity_x25519_public_key(bundle.GetIdentityX25519().data(), bundle.GetIdentityX25519().size());
    proto_bundle.set_signed_pre_key_id(bundle.GetSignedPreKeyId());
    proto_bundle.set_signed_pre_key_public_key(bundle.GetSignedPreKeyPublic().data(),
                                               bundle.GetSignedPreKeyPublic().size());
    proto_bundle.set_signed_pre_key_signature(bundle.GetSignedPreKeySignature().data(),
                                              bundle.GetSignedPreKeySignature().size());
    
    
    const auto& local_opks = bundle.GetOneTimePreKeys();
    if (!local_opks.empty()) {
        
        for (const auto &otp : local_opks) {
            auto *otp_proto = proto_bundle.add_one_time_pre_keys();
            otp_proto->set_pre_key_id(otp.GetPreKeyId());
            const auto &pub = otp.GetPublicKey();
            otp_proto->set_public_key(pub.data(), pub.size());
        }
        
        uint32_t selected_opk_id = local_opks.front().GetPreKeyId();
        handle->system->GetIdentityKeysMutable().SetSelectedOpkId(selected_opk_id);
        proto_bundle.set_used_one_time_pre_key_id(selected_opk_id);
        fprintf(stderr, "[BEGIN-HANDSHAKE-KYBER] Including %zu OPKs, pre-selected OPK ID: %u\n",
            local_opks.size(), selected_opk_id);
    } else {
        fprintf(stderr, "[BEGIN-HANDSHAKE-KYBER] WARNING: No OPKs available, DH4 will be skipped\n");
    }

    if (bundle.HasEphemeralKey()) {
        const auto &eph = bundle.GetEphemeralX25519Public();
        proto_bundle.set_ephemeral_x25519_public_key(eph->data(), eph->size());
    }
    if (bundle.HasKyberKey()) {
        const auto &kyber = bundle.GetKyberPublicKey();
        proto_bundle.set_kyber_public_key(kyber->data(), kyber->size());
    }
    
    proto_bundle.set_kyber_ciphertext(stored_ciphertext.data(), stored_ciphertext.size());

    ecliptix::proto::protocol::PubKeyExchange handshake;
    handshake.set_state(ecliptix::proto::protocol::PubKeyExchangeState::INIT);
    handshake.set_of_type(static_cast<ecliptix::proto::protocol::PubKeyExchangeType>(exchange_type));
    handshake.set_payload(proto_bundle.SerializeAsString());

    
    handle->system->SetPendingInitiator(false);
    fprintf(stderr, "[BEGIN-HANDSHAKE-KYBER] SetPendingInitiator(false) - I am RESPONDER\n");

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
    if (auto err = EnsureInitialized(); err != ECLIPTIX_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
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

    
    auto finalize_with_kyber = [&](const ecliptix::proto::protocol::PublicKeyBundle &bundle) -> EcliptixErrorCode {
        
        if (bundle.kyber_public_key().empty()) {
            fill_error(out_error, ECLIPTIX_ERROR_PQ_MISSING, "Peer bundle missing Kyber public key for hybrid PQ mode");
            return ECLIPTIX_ERROR_PQ_MISSING;
        }
        if (bundle.kyber_public_key().size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT, "Invalid peer Kyber public key size");
            return ECLIPTIX_ERROR_INVALID_INPUT;
        }

        std::vector<uint8_t> kyber_ciphertext;
        std::vector<uint8_t> kyber_shared_secret;

        
        auto stored_result = handle->system->GetIdentityKeysMutable().ConsumePendingKyberHandshake();
        if (stored_result.IsOk()) {
            
            auto stored = std::move(stored_result).Unwrap();
            kyber_ciphertext = std::move(stored.kyber_ciphertext);
            kyber_shared_secret = std::move(stored.kyber_shared_secret);
        } else if (!bundle.kyber_ciphertext().empty()) {
            
            if (bundle.kyber_ciphertext().size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
                fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT, "Invalid peer Kyber ciphertext size");
                return ECLIPTIX_ERROR_INVALID_INPUT;
            }
            auto decap_result = handle->system->GetIdentityKeysMutable().DecapsulateKyberCiphertext(
                std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(bundle.kyber_ciphertext().data()),
                    bundle.kyber_ciphertext().size()));
            if (decap_result.IsErr()) {
                fill_error(out_error, ECLIPTIX_ERROR_DECRYPTION, "Kyber decapsulation failed");
                return ECLIPTIX_ERROR_DECRYPTION;
            }
            auto artifacts = std::move(decap_result).Unwrap();
            kyber_ciphertext = std::move(artifacts.kyber_ciphertext);
            kyber_shared_secret = std::move(artifacts.kyber_shared_secret);
        } else {
            
            std::vector<uint8_t> peer_kyber_pk(bundle.kyber_public_key().begin(), bundle.kyber_public_key().end());
            auto encap_result = KyberInterop::Encapsulate(peer_kyber_pk);
            if (encap_result.IsErr()) {
                fill_error(out_error, ECLIPTIX_ERROR_KEY_GENERATION, "Kyber encapsulation failed");
                return ECLIPTIX_ERROR_KEY_GENERATION;
            }
            auto [ct, kyber_ss_handle] = std::move(encap_result).Unwrap();
            kyber_ciphertext = std::move(ct);

            
            auto kyber_ss_result = kyber_ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
            if (kyber_ss_result.IsErr()) {
                fill_error(out_error, ECLIPTIX_ERROR_SODIUM_FAILURE, "Failed to read Kyber shared secret");
                return ECLIPTIX_ERROR_SODIUM_FAILURE;
            }
            kyber_shared_secret = kyber_ss_result.Unwrap();
        }

        bool is_initiator = handle->system->GetPendingInitiator().value_or(false);
        auto finalize_result = handle->system->FinalizeWithRootAndPeerBundle(
            std::span<const uint8_t>(root_key, root_key_length),
            bundle,
            is_initiator,
            kyber_ciphertext,
            kyber_shared_secret);

        
        auto _wipe_ct = SodiumInterop::SecureWipe(std::span(kyber_ciphertext));
        (void) _wipe_ct;
        auto _wipe_ss = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
        (void) _wipe_ss;

        if (finalize_result.IsErr()) {
            fill_error_from_failure(out_error, std::move(finalize_result).UnwrapErr());
            return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
        }
        return ECLIPTIX_SUCCESS;
    };

    ecliptix::proto::protocol::PubKeyExchange peer_exchange;
    if (!peer_exchange.ParseFromArray(peer_handshake_message, static_cast<int>(peer_handshake_message_length))) {
        
        ecliptix::proto::protocol::PublicKeyBundle direct_bundle;
        if (!direct_bundle.ParseFromArray(peer_handshake_message, static_cast<int>(peer_handshake_message_length))) {
            fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Failed to parse peer handshake");
            return ECLIPTIX_ERROR_DECODE;
        }
        return finalize_with_kyber(direct_bundle);
    }

    ecliptix::proto::protocol::PublicKeyBundle peer_bundle;
    if (!peer_bundle.ParseFromString(peer_exchange.payload())) {
        fill_error(out_error, ECLIPTIX_ERROR_DECODE, "Failed to parse peer public bundle");
        return ECLIPTIX_ERROR_DECODE;
    }

    return finalize_with_kyber(peer_bundle);
}

EcliptixErrorCode ecliptix_protocol_system_complete_handshake_auto(
    EcliptixProtocolSystemHandle *handle,
    const uint8_t *peer_handshake_message,
    size_t peer_handshake_message_length,
    EcliptixError *out_error) {
    if (auto err = EnsureInitialized(); err != ECLIPTIX_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(peer_handshake_message, peer_handshake_message_length, out_error)) {
        return out_error ? out_error->code : ECLIPTIX_ERROR_NULL_POINTER;
    }

    fprintf(stderr, "\n[COMPLETE-HANDSHAKE-AUTO] ========== CompleteHandshakeAuto ==========\n");

    
    handle->system->GetIdentityKeysMutable().GenerateEphemeralKeyPair();

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

    
    fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] Peer identity_x25519: %02x%02x%02x%02x%02x%02x%02x%02x\n",
        static_cast<uint8_t>(peer_bundle.identity_x25519_public_key()[0]),
        static_cast<uint8_t>(peer_bundle.identity_x25519_public_key()[1]),
        static_cast<uint8_t>(peer_bundle.identity_x25519_public_key()[2]),
        static_cast<uint8_t>(peer_bundle.identity_x25519_public_key()[3]),
        static_cast<uint8_t>(peer_bundle.identity_x25519_public_key()[4]),
        static_cast<uint8_t>(peer_bundle.identity_x25519_public_key()[5]),
        static_cast<uint8_t>(peer_bundle.identity_x25519_public_key()[6]),
        static_cast<uint8_t>(peer_bundle.identity_x25519_public_key()[7]));
    fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] Peer spk_public: %02x%02x%02x%02x%02x%02x%02x%02x\n",
        static_cast<uint8_t>(peer_bundle.signed_pre_key_public_key()[0]),
        static_cast<uint8_t>(peer_bundle.signed_pre_key_public_key()[1]),
        static_cast<uint8_t>(peer_bundle.signed_pre_key_public_key()[2]),
        static_cast<uint8_t>(peer_bundle.signed_pre_key_public_key()[3]),
        static_cast<uint8_t>(peer_bundle.signed_pre_key_public_key()[4]),
        static_cast<uint8_t>(peer_bundle.signed_pre_key_public_key()[5]),
        static_cast<uint8_t>(peer_bundle.signed_pre_key_public_key()[6]),
        static_cast<uint8_t>(peer_bundle.signed_pre_key_public_key()[7]));
    if (!peer_bundle.ephemeral_x25519_public_key().empty()) {
        fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] Peer ephemeral_x25519: %02x%02x%02x%02x%02x%02x%02x%02x (size=%zu)\n",
            static_cast<uint8_t>(peer_bundle.ephemeral_x25519_public_key()[0]),
            static_cast<uint8_t>(peer_bundle.ephemeral_x25519_public_key()[1]),
            static_cast<uint8_t>(peer_bundle.ephemeral_x25519_public_key()[2]),
            static_cast<uint8_t>(peer_bundle.ephemeral_x25519_public_key()[3]),
            static_cast<uint8_t>(peer_bundle.ephemeral_x25519_public_key()[4]),
            static_cast<uint8_t>(peer_bundle.ephemeral_x25519_public_key()[5]),
            static_cast<uint8_t>(peer_bundle.ephemeral_x25519_public_key()[6]),
            static_cast<uint8_t>(peer_bundle.ephemeral_x25519_public_key()[7]),
            peer_bundle.ephemeral_x25519_public_key().size());
    } else {
        fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] Peer ephemeral_x25519: EMPTY!\n");
    }
    if (!peer_bundle.kyber_ciphertext().empty()) {
        fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] Peer kyber_ciphertext: %02x%02x%02x%02x... (size=%zu)\n",
            static_cast<uint8_t>(peer_bundle.kyber_ciphertext()[0]),
            static_cast<uint8_t>(peer_bundle.kyber_ciphertext()[1]),
            static_cast<uint8_t>(peer_bundle.kyber_ciphertext()[2]),
            static_cast<uint8_t>(peer_bundle.kyber_ciphertext()[3]),
            peer_bundle.kyber_ciphertext().size());
    } else {
        fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] Peer kyber_ciphertext: EMPTY\n");
    }

    auto peer_bundle_result = build_local_bundle(peer_bundle);
    if (peer_bundle_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(peer_bundle_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    
    bool is_initiator = handle->system->GetPendingInitiator().value_or(false);
    fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] is_initiator=%s\n", is_initiator ? "true (CLIENT)" : "false (SERVER)");

    
    std::vector<uint8_t> initial_dh_public;
    std::vector<uint8_t> initial_dh_private;
    if (is_initiator) {
        
        auto ek_public = handle->system->GetIdentityKeys().GetEphemeralX25519PublicKeyCopy();
        auto ek_private_result = handle->system->GetIdentityKeys().GetEphemeralX25519PrivateKeyCopy();
        if (ek_public.has_value() && ek_private_result.IsOk()) {
            initial_dh_public = ek_public.value();
            initial_dh_private = ek_private_result.Unwrap();
            fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] Captured ephemeral key BEFORE X3DH (INITIATOR): %02x%02x%02x%02x%02x%02x%02x%02x\n",
                initial_dh_public[0], initial_dh_public[1], initial_dh_public[2], initial_dh_public[3],
                initial_dh_public[4], initial_dh_public[5], initial_dh_public[6], initial_dh_public[7]);
        } else {
            fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] ERROR: Ephemeral key not available before X3DH!\n");
            fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Ephemeral key not available for initiator");
            return ECLIPTIX_ERROR_INVALID_STATE;
        }
    } else {
        
        initial_dh_public = handle->system->GetIdentityKeys().GetSignedPreKeyPublicCopy();
        auto spk_private_result = handle->system->GetIdentityKeys().GetSignedPreKeyPrivateCopy();
        if (spk_private_result.IsErr()) {
            fill_error_from_failure(out_error, std::move(spk_private_result).UnwrapErr());
            return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
        }
        initial_dh_private = spk_private_result.Unwrap();
        fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] Using SPK as initial DH (RESPONDER): %02x%02x%02x%02x%02x%02x%02x%02x\n",
            initial_dh_public[0], initial_dh_public[1], initial_dh_public[2], initial_dh_public[3],
            initial_dh_public[4], initial_dh_public[5], initial_dh_public[6], initial_dh_public[7]);
    }

    std::vector<uint8_t> info(ProtocolConstants::X3DH_INFO.begin(), ProtocolConstants::X3DH_INFO.end());
    fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] Calling X3dhDeriveSharedSecret...\n");
    auto shared_secret_result = handle->system->GetIdentityKeysMutable().X3dhDeriveSharedSecret(
        peer_bundle_result.Unwrap(),
        std::span<const uint8_t>(info),
        is_initiator);
    if (shared_secret_result.IsErr()) {
        fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] X3dhDeriveSharedSecret FAILED\n");
        fill_error_from_failure(out_error, std::move(shared_secret_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }
    fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] X3dhDeriveSharedSecret SUCCEEDED\n");

    auto shared_secret_handle = std::move(shared_secret_result).Unwrap();
    std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE);
    auto read_result = shared_secret_handle.Read(root_key);
    if (read_result.IsErr()) {
        fill_error_from_failure(
            out_error,
            EcliptixProtocolFailure::FromSodiumFailure(std::move(read_result).UnwrapErr()));
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] root_key: %02x%02x%02x%02x%02x%02x%02x%02x\n",
        root_key[0], root_key[1], root_key[2], root_key[3],
        root_key[4], root_key[5], root_key[6], root_key[7]);

    
    auto kyber_artifacts_result = handle->system->GetIdentityKeysMutable().ConsumePendingKyberHandshake();
    if (kyber_artifacts_result.IsErr()) {
        auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
        (void) _wipe_root;
        fill_error_from_failure(out_error, std::move(kyber_artifacts_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }
    auto kyber_artifacts = std::move(kyber_artifacts_result).Unwrap();

    fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] kyber_ss: %02x%02x%02x%02x%02x%02x%02x%02x\n",
        kyber_artifacts.kyber_shared_secret[0], kyber_artifacts.kyber_shared_secret[1],
        kyber_artifacts.kyber_shared_secret[2], kyber_artifacts.kyber_shared_secret[3],
        kyber_artifacts.kyber_shared_secret[4], kyber_artifacts.kyber_shared_secret[5],
        kyber_artifacts.kyber_shared_secret[6], kyber_artifacts.kyber_shared_secret[7]);

    fprintf(stderr, "[COMPLETE-HANDSHAKE-AUTO] Calling FinalizeWithRootAndPeerBundle...\n");
    
    auto finalize_result = handle->system->FinalizeWithRootAndPeerBundle(
        root_key,
        peer_bundle,
        is_initiator,
        kyber_artifacts.kyber_ciphertext,
        kyber_artifacts.kyber_shared_secret,
        initial_dh_public,
        initial_dh_private);  
    auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
    (void) _wipe_root;
    auto _wipe_dh_pub = SodiumInterop::SecureWipe(std::span(initial_dh_public));
    (void) _wipe_dh_pub;
    auto _wipe_dh_priv = SodiumInterop::SecureWipe(std::span(initial_dh_private));
    (void) _wipe_dh_priv;
    
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

EcliptixErrorCode ecliptix_protocol_system_get_chain_indices(
    const EcliptixProtocolSystemHandle *handle,
    uint32_t *out_sending_index,
    uint32_t *out_receiving_index,
    EcliptixError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!out_sending_index || !out_receiving_index) {
        fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "Output parameters are null");
        return ECLIPTIX_ERROR_NULL_POINTER;
    }
    if (!handle->system->HasConnection()) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol connection not established");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }

    auto indices_result = handle->system->GetChainIndices();
    if (indices_result.IsErr()) {
        fill_error_from_failure(out_error, std::move(indices_result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

    auto [sending_index, receiving_index] = indices_result.Unwrap();
    *out_sending_index = sending_index;
    *out_receiving_index = receiving_index;
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_get_selected_opk_id(
    const EcliptixProtocolSystemHandle *handle,
    bool *out_has_opk_id,
    uint32_t *out_opk_id,
    EcliptixError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!out_has_opk_id || !out_opk_id) {
        fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "Output parameters are null");
        return ECLIPTIX_ERROR_NULL_POINTER;
    }

    auto selected_opk_id = handle->system->GetIdentityKeys().GetSelectedOpkId();
    if (selected_opk_id.has_value()) {
        *out_has_opk_id = true;
        *out_opk_id = selected_opk_id.value();
        fprintf(stderr, "[C-API] GetSelectedOpkId: has_opk_id=true, opk_id=%u\n", *out_opk_id);
    } else {
        *out_has_opk_id = false;
        *out_opk_id = 0;
        fprintf(stderr, "[C-API] GetSelectedOpkId: has_opk_id=false\n");
    }
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_connection_get_session_age_seconds(
    const EcliptixProtocolSystemHandle *handle,
    uint64_t *out_age_seconds,
    EcliptixError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!out_age_seconds) {
        fill_error(out_error, ECLIPTIX_ERROR_NULL_POINTER, "out_age_seconds is null");
        return ECLIPTIX_ERROR_NULL_POINTER;
    }
    if (!handle->system->HasConnection()) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol connection not established");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }

    *out_age_seconds = handle->system->GetSessionAgeSeconds();
    return ECLIPTIX_SUCCESS;
}

EcliptixErrorCode ecliptix_protocol_system_set_kyber_secrets(
    EcliptixProtocolSystemHandle *handle,
    const uint8_t *kyber_ciphertext,
    size_t kyber_ciphertext_length,
    const uint8_t *kyber_shared_secret,
    size_t kyber_shared_secret_length,
    EcliptixError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return ECLIPTIX_ERROR_INVALID_STATE;
    }
    if (!kyber_ciphertext || kyber_ciphertext_length == 0) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT, "Kyber ciphertext is null or empty");
        return ECLIPTIX_ERROR_INVALID_INPUT;
    }
    if (!kyber_shared_secret || kyber_shared_secret_length == 0) {
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT, "Kyber shared secret is null or empty");
        return ECLIPTIX_ERROR_INVALID_INPUT;
    }

    auto result = handle->system->SetConnectionKyberSecrets(
        std::span<const uint8_t>(kyber_ciphertext, kyber_ciphertext_length),
        std::span<const uint8_t>(kyber_shared_secret, kyber_shared_secret_length));

    if (result.IsErr()) {
        fill_error_from_failure(out_error, std::move(result).UnwrapErr());
        return out_error ? out_error->code : ECLIPTIX_ERROR_GENERIC;
    }

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
    if (auto err = EnsureInitialized(); err != ECLIPTIX_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
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

    
    if (bundle.kyber_public_key().empty()) {
        delete handle;
        fill_error(out_error, ECLIPTIX_ERROR_PQ_MISSING, "Peer bundle missing Kyber public key for hybrid PQ mode");
        return ECLIPTIX_ERROR_PQ_MISSING;
    }
    if (bundle.kyber_public_key().size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
        delete handle;
        fill_error(out_error, ECLIPTIX_ERROR_INVALID_INPUT, "Invalid peer Kyber public key size");
        return ECLIPTIX_ERROR_INVALID_INPUT;
    }

    
    std::vector<uint8_t> peer_kyber_pk(bundle.kyber_public_key().begin(), bundle.kyber_public_key().end());
    auto encap_result = KyberInterop::Encapsulate(peer_kyber_pk);
    if (encap_result.IsErr()) {
        delete handle;
        fill_error(out_error, ECLIPTIX_ERROR_KEY_GENERATION, "Kyber encapsulation failed");
        return ECLIPTIX_ERROR_KEY_GENERATION;
    }
    auto [kyber_ciphertext, kyber_shared_secret_handle] = std::move(encap_result).Unwrap();

    
    auto kyber_ss_result = kyber_shared_secret_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
    if (kyber_ss_result.IsErr()) {
        delete handle;
        fill_error(out_error, ECLIPTIX_ERROR_SODIUM_FAILURE, "Failed to read Kyber shared secret");
        return ECLIPTIX_ERROR_SODIUM_FAILURE;
    }
    auto kyber_shared_secret = kyber_ss_result.Unwrap();

    auto system_result = EcliptixProtocolSystem::CreateFromRootAndPeerBundle(
        std::move(identity_keys->identity_keys),
        std::span<const uint8_t>(root_key, root_key_length),
        bundle,
        is_initiator,
        kyber_ciphertext,
        kyber_shared_secret);

    
    auto _wipe_ct = SodiumInterop::SecureWipe(std::span(kyber_ciphertext));
    (void) _wipe_ct;
    auto _wipe_ss = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
    (void) _wipe_ss;

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
    if (auto err = EnsureInitialized(); err != ECLIPTIX_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
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
    if (auto err = EnsureInitialized(); err != ECLIPTIX_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
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
