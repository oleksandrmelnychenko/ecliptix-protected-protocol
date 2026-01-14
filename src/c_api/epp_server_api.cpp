#include "ecliptix/c_api/epp_server_api.h"
#include "ecliptix/protocol/protocol_system.hpp"
#include "ecliptix/protocol/connection/protocol_connection.hpp"
#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/crypto/shamir_secret_sharing.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/constants.hpp"
#include "common/secure_envelope.pb.h"
#include "protocol/protocol_state.pb.h"
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
using namespace ecliptix::proto::protocol;
using crypto::KyberInterop;

struct ProtocolSystemHandle {
    std::unique_ptr<ProtocolSystem> system;
    std::shared_ptr<IProtocolEventHandler> event_handler;
};

struct EppIdentityHandle {
    std::unique_ptr<IdentityKeys> identity_keys;
};

namespace {
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

    class CApiEventHandler : public IProtocolEventHandler {
    public:
        CApiEventHandler(const EppEventCallback callback, void *user_data)
            : callback_(callback), user_data_(user_data) {
        }

        void OnProtocolStateChanged(const uint32_t connection_id) override {
            if (callback_) {
                callback_(connection_id, user_data_);
            }
        }

        void OnRatchetRequired(const uint32_t connection_id, const std::string &reason) override {
            (void) connection_id;
            (void) reason;
        }

    private:
        EppEventCallback callback_;
        void *user_data_;
    };

    void fill_error(EppError *out_error, const EppErrorCode code, const std::string &message) {
        if (out_error) {
            out_error->code = code;
#ifdef _WIN32
            out_error->message = _strdup(message.c_str());
#else
            out_error->message = strdup(message.c_str());
#endif
        }
    }

    EppErrorCode fill_error_from_failure(EppError *out_error, const ProtocolFailure &failure) {
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

    bool validate_buffer_param(const uint8_t *data, const size_t length, EppError *out_error) {
        if (!data && length > 0) {
            fill_error(out_error, EPP_ERROR_NULL_POINTER, "Buffer data is null but length is non-zero");
            return false;
        }
        return true;
    }

    bool validate_output_handle(const void *handle, EppError *out_error) {
        if (!handle) {
            fill_error(out_error, EPP_ERROR_NULL_POINTER, "Output handle pointer is null");
            return false;
        }
        return true;
    }

    bool copy_to_buffer(const std::span<const uint8_t> input, EppBuffer *out_buffer, EppError *out_error) {
        if (!out_buffer) {
            fill_error(out_error, EPP_ERROR_NULL_POINTER, "Output buffer is null");
            return false;
        }

        auto *data = new(std::nothrow) uint8_t[input.size()];
        if (!data) {
            fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate output buffer");
            return false;
        }
        std::memcpy(data, input.data(), input.size());
        out_buffer->data = data;
        out_buffer->length = input.size();
        return true;
    }

    Result<LocalPublicKeyBundle, ProtocolFailure> build_local_bundle(const PublicKeyBundle &proto_bundle) {
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
        for (const auto &otp: proto_bundle.one_time_pre_keys()) {
            if (otp.public_key().empty()) {
                return Result<LocalPublicKeyBundle, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Peer bundle contains empty one-time pre-key"));
            }
            otps.emplace_back(
                otp.pre_key_id(),
                std::vector<uint8_t>(otp.public_key().begin(), otp.public_key().end()));
        }

        std::optional<std::vector<uint8_t> > ephemeral = std::nullopt;
        if (!proto_bundle.ephemeral_x25519_public_key().empty()) {
            ephemeral = std::vector<uint8_t>(
                proto_bundle.ephemeral_x25519_public_key().begin(),
                proto_bundle.ephemeral_x25519_public_key().end());
        }

        std::optional<std::vector<uint8_t> > kyber = std::nullopt;
        if (!proto_bundle.kyber_public_key().empty()) {
            kyber = std::vector<uint8_t>(
                proto_bundle.kyber_public_key().begin(),
                proto_bundle.kyber_public_key().end());
        }

        std::optional<std::vector<uint8_t> > kyber_ciphertext = std::nullopt;
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
}

extern "C" {
EppErrorCode epp_server_create(
    EppIdentityHandle *identity_keys,
    ProtocolSystemHandle **out_handle,
    EppError *out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!identity_keys || !identity_keys->identity_keys) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Identity keys handle is null");
        return EPP_ERROR_NULL_POINTER;
    }

    if (!validate_output_handle(out_handle, out_error)) {
        return EPP_ERROR_NULL_POINTER;
    }

    auto *handle = new(std::nothrow) ProtocolSystemHandle{};
    if (!handle) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate protocol system handle");
        return EPP_ERROR_OUT_OF_MEMORY;
    }

    if (!identity_keys->identity_keys) {
        delete handle;
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Identity keys handle is uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }

    auto system_result = ProtocolSystem::Create(std::move(identity_keys->identity_keys));
    if (system_result.IsErr()) {
        delete handle;
        return fill_error_from_failure(out_error, std::move(system_result).UnwrapErr());
    }

    handle->system = std::move(system_result).Unwrap();
    identity_keys->identity_keys.reset();

    *out_handle = handle;
    return EPP_SUCCESS;
}

EppErrorCode epp_server_create_from_root(
    EppIdentityHandle *identity_keys,
    const uint8_t *root_key,
    size_t root_key_length,
    const uint8_t *peer_bundle,
    size_t peer_bundle_length,
    bool is_initiator,
    ProtocolSystemHandle **out_handle,
    EppError *out_error) {
    if (auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!identity_keys || !identity_keys->identity_keys) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Identity keys handle is null");
        return EPP_ERROR_NULL_POINTER;
    }
    if (!validate_buffer_param(root_key, root_key_length, out_error) ||
        !validate_buffer_param(peer_bundle, peer_bundle_length, out_error) ||
        !validate_output_handle(out_handle, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (root_key_length != Constants::X_25519_KEY_SIZE) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Root key must be 32 bytes");
        return EPP_ERROR_INVALID_INPUT;
    }

    auto *handle = new(std::nothrow) ProtocolSystemHandle{};
    if (!handle) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate protocol system handle");
        return EPP_ERROR_OUT_OF_MEMORY;
    }

    PublicKeyBundle bundle;
    if (!bundle.ParseFromArray(peer_bundle, static_cast<int>(peer_bundle_length))) {
        delete handle;
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse peer bundle");
        return EPP_ERROR_DECODE;
    }

    if (bundle.kyber_public_key().empty()) {
        delete handle;
        fill_error(out_error, EPP_ERROR_PQ_MISSING, "Peer bundle missing Kyber public key for hybrid PQ mode");
        return EPP_ERROR_PQ_MISSING;
    }
    if (bundle.kyber_public_key().size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
        delete handle;
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid peer Kyber public key size");
        return EPP_ERROR_INVALID_INPUT;
    }

    std::vector<uint8_t> peer_kyber_pk(bundle.kyber_public_key().begin(), bundle.kyber_public_key().end());
    auto encap_result = KyberInterop::Encapsulate(peer_kyber_pk);
    if (encap_result.IsErr()) {
        delete handle;
        fill_error(out_error, EPP_ERROR_KEY_GENERATION, "Kyber encapsulation failed");
        return EPP_ERROR_KEY_GENERATION;
    }
    auto [kyber_ciphertext, kyber_shared_secret_handle] = std::move(encap_result).Unwrap();

    auto kyber_ss_result = kyber_shared_secret_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
    if (kyber_ss_result.IsErr()) {
        delete handle;
        fill_error(out_error, EPP_ERROR_SODIUM_FAILURE, "Failed to read Kyber shared secret");
        return EPP_ERROR_SODIUM_FAILURE;
    }
    auto kyber_shared_secret = kyber_ss_result.Unwrap();

    auto system_result = ProtocolSystem::CreateFromRootAndPeerBundle(
        std::move(identity_keys->identity_keys),
        std::span(root_key, root_key_length),
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
        return fill_error_from_failure(out_error, std::move(system_result).UnwrapErr());
    }

    handle->system = std::move(system_result).Unwrap();
    identity_keys->identity_keys.reset();
    *out_handle = handle;
    return EPP_SUCCESS;
}

EppErrorCode epp_server_deserialize(
    EppIdentityHandle *identity_keys,
    const uint8_t *state_bytes,
    const size_t state_bytes_length,
    ProtocolSystemHandle **out_handle,
    EppError *out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!identity_keys || !identity_keys->identity_keys) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Identity keys handle is null");
        return EPP_ERROR_NULL_POINTER;
    }
    if (!validate_buffer_param(state_bytes, state_bytes_length, out_error) ||
        !validate_output_handle(out_handle, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }

    RatchetState proto_state;
    if (!proto_state.ParseFromArray(state_bytes, static_cast<int>(state_bytes_length))) {
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse protocol state");
        return EPP_ERROR_DECODE;
    }

    auto system_result = ProtocolSystem::FromProtoState(
        std::move(identity_keys->identity_keys),
        proto_state);

    if (system_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(system_result).UnwrapErr());
    }

    auto *handle = new(std::nothrow) ProtocolSystemHandle{};
    if (!handle) {
        fill_error(out_error, EPP_ERROR_OUT_OF_MEMORY, "Failed to allocate protocol system handle");
        return EPP_ERROR_OUT_OF_MEMORY;
    }

    handle->system = std::move(system_result).Unwrap();
    identity_keys->identity_keys.reset();
    *out_handle = handle;
    return EPP_SUCCESS;
}

EppErrorCode epp_server_set_callbacks(
    ProtocolSystemHandle *handle,
    const EppCallbacks *callbacks,
    EppError *out_error) {
    if (!handle) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Protocol system handle is null");
        return EPP_ERROR_NULL_POINTER;
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

    return EPP_SUCCESS;
}

EppErrorCode epp_server_begin_handshake(
    const ProtocolSystemHandle *handle,
    const uint32_t connection_id,
    uint8_t exchange_type,
    EppBuffer *out_handshake_message,
    EppError *out_error) {
    if (const auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_output_handle(out_handshake_message, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }

    handle->system->SetPendingConnectionId(connection_id);
    handle->system->GetIdentityKeysMutable().GenerateEphemeralKeyPair();

    auto bundle_result = handle->system->GetIdentityKeys().CreatePublicBundle();
    if (bundle_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(bundle_result).UnwrapErr());
    }

    const auto &bundle = bundle_result.Unwrap();

    PublicKeyBundle proto_bundle;
    proto_bundle.set_identity_public_key(bundle.GetEd25519Public().data(), bundle.GetEd25519Public().size());
    proto_bundle.set_identity_x25519_public_key(bundle.GetIdentityX25519().data(), bundle.GetIdentityX25519().size());
    proto_bundle.set_signed_pre_key_id(bundle.GetSignedPreKeyId());
    proto_bundle.set_signed_pre_key_public_key(bundle.GetSignedPreKeyPublic().data(),
                                               bundle.GetSignedPreKeyPublic().size());
    proto_bundle.set_signed_pre_key_signature(bundle.GetSignedPreKeySignature().data(),
                                              bundle.GetSignedPreKeySignature().size());

    for (const auto &otp: bundle.GetOneTimePreKeys()) {
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

    PubKeyExchange handshake;
    handshake.set_state(INIT);
    handshake.set_of_type(static_cast<ecliptix::proto::protocol::PubKeyExchangeType>(exchange_type));
    handshake.set_payload(proto_bundle.SerializeAsString());

    handle->system->SetPendingInitiator(false);

    const std::string serialized = handshake.SerializeAsString();
    if (!copy_to_buffer(
        std::span(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size()),
        out_handshake_message,
        out_error)) {
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }

    return EPP_SUCCESS;
}

EppErrorCode epp_server_begin_handshake_with_peer_kyber(
    ProtocolSystemHandle *handle,
    uint32_t connection_id,
    uint8_t exchange_type,
    const uint8_t *peer_kyber_public_key,
    size_t peer_kyber_public_key_length,
    EppBuffer *out_handshake_message,
    EppError *out_error) {
    if (auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(peer_kyber_public_key, peer_kyber_public_key_length, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (!validate_output_handle(out_handshake_message, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (peer_kyber_public_key_length != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Peer Kyber public key must be 1184 bytes");
        return EPP_ERROR_INVALID_INPUT;
    }

    handle->system->SetPendingConnectionId(connection_id);

    handle->system->GetIdentityKeysMutable().GenerateEphemeralKeyPair();

    std::vector peer_kyber_pk(peer_kyber_public_key, peer_kyber_public_key + peer_kyber_public_key_length);
    auto encap_result = KyberInterop::Encapsulate(peer_kyber_pk);
    if (encap_result.IsErr()) {
        fill_error(out_error, EPP_ERROR_KEY_GENERATION, "Kyber encapsulation failed");
        return EPP_ERROR_KEY_GENERATION;
    }

    auto [kyber_ciphertext, kyber_ss_handle] = std::move(encap_result).Unwrap();
    auto kyber_ss_result = kyber_ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);

    if (kyber_ss_result.IsErr()) {
        fill_error(out_error, EPP_ERROR_SODIUM_FAILURE, "Failed to read Kyber shared secret");
        return EPP_ERROR_SODIUM_FAILURE;
    }

    auto kyber_shared_secret = kyber_ss_result.Unwrap();

    handle->system->GetIdentityKeysMutable().StorePendingKyberHandshake(
        std::move(kyber_ciphertext),
        std::move(kyber_shared_secret));

    auto stored_result = handle->system->GetIdentityKeys().GetPendingKyberCiphertext();
    if (stored_result.IsErr()) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Failed to retrieve stored Kyber ciphertext");
        return EPP_ERROR_INVALID_STATE;
    }

    const auto &stored_ciphertext = stored_result.Unwrap();

    auto bundle_result = handle->system->GetIdentityKeys().CreatePublicBundle();
    if (bundle_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(bundle_result).UnwrapErr());
    }

    const auto &bundle = bundle_result.Unwrap();

    PublicKeyBundle proto_bundle;
    proto_bundle.set_identity_public_key(bundle.GetEd25519Public().data(), bundle.GetEd25519Public().size());
    proto_bundle.set_identity_x25519_public_key(bundle.GetIdentityX25519().data(), bundle.GetIdentityX25519().size());
    proto_bundle.set_signed_pre_key_id(bundle.GetSignedPreKeyId());
    proto_bundle.set_signed_pre_key_public_key(bundle.GetSignedPreKeyPublic().data(),
                                               bundle.GetSignedPreKeyPublic().size());
    proto_bundle.set_signed_pre_key_signature(bundle.GetSignedPreKeySignature().data(),
                                              bundle.GetSignedPreKeySignature().size());

    if (const auto &local_opks = bundle.GetOneTimePreKeys(); !local_opks.empty()) {
        for (const auto &otp: local_opks) {
            auto *otp_proto = proto_bundle.add_one_time_pre_keys();
            otp_proto->set_pre_key_id(otp.GetPreKeyId());
            const auto &pub = otp.GetPublicKey();
            otp_proto->set_public_key(pub.data(), pub.size());
        }

        uint32_t selected_opk_id = local_opks.front().GetPreKeyId();
        handle->system->GetIdentityKeysMutable().SetSelectedOpkId(selected_opk_id);
        proto_bundle.set_used_one_time_pre_key_id(selected_opk_id);
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

    PubKeyExchange handshake;
    handshake.set_state(INIT);
    handshake.set_of_type(static_cast<ecliptix::proto::protocol::PubKeyExchangeType>(exchange_type));
    handshake.set_payload(proto_bundle.SerializeAsString());

    handle->system->SetPendingInitiator(false);

    const std::string serialized = handshake.SerializeAsString();
    if (!copy_to_buffer(
        std::span(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size()),
        out_handshake_message,
        out_error)) {
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }
    return EPP_SUCCESS;
}

EppErrorCode epp_server_complete_handshake(
    ProtocolSystemHandle *handle,
    const uint8_t *peer_handshake_message,
    size_t peer_handshake_message_length,
    const uint8_t *root_key,
    size_t root_key_length,
    EppError *out_error) {
    if (auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(peer_handshake_message, peer_handshake_message_length, out_error) ||
        !validate_buffer_param(root_key, root_key_length, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }
    if (root_key_length != Constants::X_25519_KEY_SIZE) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Root key must be 32 bytes");
        return EPP_ERROR_INVALID_INPUT;
    }

    auto finalize_with_kyber = [&](const PublicKeyBundle &bundle) -> EppErrorCode {
        if (bundle.kyber_public_key().empty()) {
            fill_error(out_error, EPP_ERROR_PQ_MISSING, "Peer bundle missing Kyber public key for hybrid PQ mode");
            return EPP_ERROR_PQ_MISSING;
        }
        if (bundle.kyber_public_key().size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid peer Kyber public key size");
            return EPP_ERROR_INVALID_INPUT;
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
                fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid peer Kyber ciphertext size");
                return EPP_ERROR_INVALID_INPUT;
            }
            auto decap_result = handle->system->GetIdentityKeysMutable().DecapsulateKyberCiphertext(
                std::span(
                    reinterpret_cast<const uint8_t *>(bundle.kyber_ciphertext().data()),
                    bundle.kyber_ciphertext().size()));
            if (decap_result.IsErr()) {
                fill_error(out_error, EPP_ERROR_DECRYPTION, "Kyber decapsulation failed");
                return EPP_ERROR_DECRYPTION;
            }
            auto artifacts = std::move(decap_result).Unwrap();
            kyber_ciphertext = std::move(artifacts.kyber_ciphertext);
            kyber_shared_secret = std::move(artifacts.kyber_shared_secret);
        } else {
            std::vector<uint8_t> peer_kyber_pk(bundle.kyber_public_key().begin(), bundle.kyber_public_key().end());
            auto encap_result = KyberInterop::Encapsulate(peer_kyber_pk);
            if (encap_result.IsErr()) {
                fill_error(out_error, EPP_ERROR_KEY_GENERATION, "Kyber encapsulation failed");
                return EPP_ERROR_KEY_GENERATION;
            }
            auto [ct, kyber_ss_handle] = std::move(encap_result).Unwrap();
            kyber_ciphertext = std::move(ct);

            auto kyber_ss_result = kyber_ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
            if (kyber_ss_result.IsErr()) {
                fill_error(out_error, EPP_ERROR_SODIUM_FAILURE, "Failed to read Kyber shared secret");
                return EPP_ERROR_SODIUM_FAILURE;
            }
            kyber_shared_secret = kyber_ss_result.Unwrap();
        }

        bool is_initiator = handle->system->ConsumePendingInitiator().value_or(false);
        auto finalize_result = handle->system->FinalizeWithRootAndPeerBundle(
            std::span(root_key, root_key_length),
            bundle,
            is_initiator,
            kyber_ciphertext,
            kyber_shared_secret);

        auto _wipe_ct = SodiumInterop::SecureWipe(std::span(kyber_ciphertext));
        (void) _wipe_ct;
        auto _wipe_ss = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
        (void) _wipe_ss;

        if (finalize_result.IsErr()) {
            return fill_error_from_failure(out_error, std::move(finalize_result).UnwrapErr());
        }
        return EPP_SUCCESS;
    };

    PubKeyExchange peer_exchange;
    if (!peer_exchange.ParseFromArray(peer_handshake_message, static_cast<int>(peer_handshake_message_length))) {
        PublicKeyBundle direct_bundle;
        if (!direct_bundle.ParseFromArray(peer_handshake_message, static_cast<int>(peer_handshake_message_length))) {
            fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse peer handshake");
            return EPP_ERROR_DECODE;
        }
        return finalize_with_kyber(direct_bundle);
    }

    PublicKeyBundle peer_bundle;
    if (!peer_bundle.ParseFromString(peer_exchange.payload())) {
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse peer public bundle");
        return EPP_ERROR_DECODE;
    }

    return finalize_with_kyber(peer_bundle);
}

EppErrorCode epp_server_complete_handshake_auto(
    ProtocolSystemHandle *handle,
    const uint8_t *peer_handshake_message,
    size_t peer_handshake_message_length,
    EppError *out_error) {
    if (auto err = EnsureInitialized(); err != EPP_SUCCESS) {
        fill_error(out_error, err, "Failed to initialize libsodium");
        return err;
    }
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(peer_handshake_message, peer_handshake_message_length, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }

    handle->system->GetIdentityKeysMutable().GenerateEphemeralKeyPair();

    PubKeyExchange peer_exchange;
    if (!peer_exchange.ParseFromArray(peer_handshake_message, static_cast<int>(peer_handshake_message_length))) {
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse peer handshake");
        return EPP_ERROR_DECODE;
    }

    PublicKeyBundle peer_bundle;
    if (!peer_bundle.ParseFromString(peer_exchange.payload())) {
        fill_error(out_error, EPP_ERROR_DECODE, "Failed to parse peer public bundle");
        return EPP_ERROR_DECODE;
    }

    auto peer_bundle_result = build_local_bundle(peer_bundle);
    if (peer_bundle_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(peer_bundle_result).UnwrapErr());
    }

    bool is_initiator = handle->system->ConsumePendingInitiator().value_or(false);

    std::vector<uint8_t> initial_dh_public;
    std::vector<uint8_t> initial_dh_private;
    if (is_initiator) {
        auto ek_public = handle->system->GetIdentityKeys().GetEphemeralX25519PublicKeyCopy();
        if (auto ek_private_result = handle->system->GetIdentityKeys().GetEphemeralX25519PrivateKeyCopy();
            ek_public.has_value() && ek_private_result.IsOk()) {
            initial_dh_public = ek_public.value();
            initial_dh_private = ek_private_result.Unwrap();
        } else {
            fill_error(out_error, EPP_ERROR_INVALID_STATE, "Ephemeral key not available for initiator");
            return EPP_ERROR_INVALID_STATE;
        }
    } else {
        initial_dh_public = handle->system->GetIdentityKeys().GetSignedPreKeyPublicCopy();
        auto spk_private_result = handle->system->GetIdentityKeys().GetSignedPreKeyPrivateCopy();
        if (spk_private_result.IsErr()) {
            return fill_error_from_failure(out_error, std::move(spk_private_result).UnwrapErr());
        }
        initial_dh_private = spk_private_result.Unwrap();
    }

    std::vector<uint8_t> info(ProtocolConstants::X3DH_INFO.begin(), ProtocolConstants::X3DH_INFO.end());
    auto shared_secret_result = handle->system->GetIdentityKeysMutable().X3dhDeriveSharedSecret(
        peer_bundle_result.Unwrap(),
        std::span<const uint8_t>(info),
        is_initiator);
    if (shared_secret_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(shared_secret_result).UnwrapErr());
    }

    auto shared_secret_handle = std::move(shared_secret_result).Unwrap();
    std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE);
    if (auto read_result = shared_secret_handle.Read(root_key); read_result.IsErr()) {
        return fill_error_from_failure(
            out_error,
            ProtocolFailure::FromSodiumFailure(std::move(read_result).UnwrapErr()));
    }

    auto kyber_artifacts_result = handle->system->GetIdentityKeysMutable().ConsumePendingKyberHandshake();

    std::vector<uint8_t> kyber_ciphertext;
    std::vector<uint8_t> kyber_shared_secret;

    if (kyber_artifacts_result.IsOk()) {
        auto kyber_artifacts = std::move(kyber_artifacts_result).Unwrap();
        kyber_ciphertext = std::move(kyber_artifacts.kyber_ciphertext);
        kyber_shared_secret = std::move(kyber_artifacts.kyber_shared_secret);
    } else if (!peer_bundle.kyber_ciphertext().empty()) {
        if (peer_bundle.kyber_ciphertext().size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Invalid peer Kyber ciphertext size");
            return EPP_ERROR_INVALID_INPUT;
        }
        auto decap_result = handle->system->GetIdentityKeysMutable().DecapsulateKyberCiphertext(
            std::span(
                reinterpret_cast<const uint8_t *>(peer_bundle.kyber_ciphertext().data()),
                peer_bundle.kyber_ciphertext().size()));
        if (decap_result.IsErr()) {
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            fill_error(out_error, EPP_ERROR_DECRYPTION, "Kyber decapsulation failed");
            return EPP_ERROR_DECRYPTION;
        }
        auto artifacts = std::move(decap_result).Unwrap();
        kyber_ciphertext = std::move(artifacts.kyber_ciphertext);
        kyber_shared_secret = std::move(artifacts.kyber_shared_secret);
    } else {
        auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
        (void) _wipe_root;
        fill_error(out_error, EPP_ERROR_PQ_MISSING, "No Kyber artifacts available for hybrid PQ mode");
        return EPP_ERROR_PQ_MISSING;
    }

    auto finalize_result = handle->system->FinalizeWithRootAndPeerBundle(
        root_key,
        peer_bundle,
        is_initiator,
        kyber_ciphertext,
        kyber_shared_secret,
        initial_dh_public,
        initial_dh_private);
    auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
    (void) _wipe_root;
    auto _wipe_dh_pub = SodiumInterop::SecureWipe(std::span(initial_dh_public));
    (void) _wipe_dh_pub;
    auto _wipe_dh_priv = SodiumInterop::SecureWipe(std::span(initial_dh_private));
    (void) _wipe_dh_priv;

    if (finalize_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(finalize_result).UnwrapErr());
    }

    return EPP_SUCCESS;
}

EppErrorCode epp_server_encrypt(
    const ProtocolSystemHandle *handle,
    const uint8_t *plaintext,
    const size_t plaintext_length,
    EppBuffer *out_encrypted_envelope,
    EppError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(plaintext, plaintext_length, out_error) ||
        !validate_output_handle(out_encrypted_envelope, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }

    auto send_result = handle->system->SendMessage(std::span(plaintext, plaintext_length));
    if (send_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(send_result).UnwrapErr());
    }

    const SecureEnvelope &envelope = send_result.Unwrap();
    const std::string serialized = envelope.SerializeAsString();
    if (!copy_to_buffer(
        std::span(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size()),
        out_encrypted_envelope,
        out_error)) {
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }

    return EPP_SUCCESS;
}

EppErrorCode epp_server_decrypt(
    const ProtocolSystemHandle *handle,
    const uint8_t *encrypted_envelope,
    const size_t encrypted_envelope_length,
    EppBuffer *out_plaintext,
    EppError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_buffer_param(encrypted_envelope, encrypted_envelope_length, out_error) ||
        !validate_output_handle(out_plaintext, out_error)) {
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
    if (envelope.dh_public_key().size() > 0 && envelope.kyber_ciphertext().empty()) {
        fill_error(out_error, EPP_ERROR_PQ_MISSING, "Missing Kyber ciphertext for hybrid ratchet");
        return EPP_ERROR_PQ_MISSING;
    }

    auto receive_result = handle->system->ReceiveMessage(envelope);
    if (receive_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(receive_result).UnwrapErr());
    }

    const auto &plaintext = receive_result.Unwrap();
    if (!copy_to_buffer(std::span(plaintext.data(), plaintext.size()), out_plaintext, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }

    return EPP_SUCCESS;
}

EppErrorCode epp_server_is_established(
    const ProtocolSystemHandle *handle,
    bool *out_has_connection,
    EppError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!out_has_connection) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "out_has_connection is null");
        return EPP_ERROR_NULL_POINTER;
    }

    *out_has_connection = handle->system->HasConnection();
    return EPP_SUCCESS;
}

EppErrorCode epp_server_get_id(
    const ProtocolSystemHandle *handle,
    uint32_t *out_connection_id,
    EppError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!out_connection_id) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "out_connection_id is null");
        return EPP_ERROR_NULL_POINTER;
    }
    if (!handle->system->HasConnection()) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol connection not established");
        return EPP_ERROR_INVALID_STATE;
    }

    *out_connection_id = handle->system->GetConnectionId();
    return EPP_SUCCESS;
}

EppErrorCode epp_server_get_chain_indices(
    const ProtocolSystemHandle *handle,
    uint32_t *out_sending_index,
    uint32_t *out_receiving_index,
    EppError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!out_sending_index || !out_receiving_index) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Output parameters are null");
        return EPP_ERROR_NULL_POINTER;
    }
    if (!handle->system->HasConnection()) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol connection not established");
        return EPP_ERROR_INVALID_STATE;
    }

    auto indices_result = handle->system->GetChainIndices();
    if (indices_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(indices_result).UnwrapErr());
    }

    auto [sending_index, receiving_index] = indices_result.Unwrap();
    *out_sending_index = sending_index;
    *out_receiving_index = receiving_index;
    return EPP_SUCCESS;
}

EppErrorCode epp_server_get_used_prekey_id(
    const ProtocolSystemHandle *handle,
    bool *out_has_opk_id,
    uint32_t *out_opk_id,
    EppError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!out_has_opk_id || !out_opk_id) {
        fill_error(out_error, EPP_ERROR_NULL_POINTER, "Output parameters are null");
        return EPP_ERROR_NULL_POINTER;
    }

    if (const auto selected_opk_id = handle->system->GetIdentityKeys().GetSelectedOpkId(); selected_opk_id.
        has_value()) {
        *out_has_opk_id = true;
        *out_opk_id = selected_opk_id.value();
    } else {
        *out_has_opk_id = false;
        *out_opk_id = 0;
    }
    return EPP_SUCCESS;
}

EppErrorCode epp_server_serialize(
    const ProtocolSystemHandle *handle,
    EppBuffer *out_state,
    EppError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!validate_output_handle(out_state, out_error)) {
        return out_error ? out_error->code : EPP_ERROR_NULL_POINTER;
    }

    auto state_result = handle->system->ToProtoState();
    if (state_result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(state_result).UnwrapErr());
    }

    const auto &state = state_result.Unwrap();
    const std::string serialized = state.SerializeAsString();
    if (!copy_to_buffer(
        std::span(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size()),
        out_state,
        out_error)) {
        return out_error ? out_error->code : EPP_ERROR_OUT_OF_MEMORY;
    }

    return EPP_SUCCESS;
}

EppErrorCode epp_server_set_kyber_secrets(
    const ProtocolSystemHandle *handle,
    const uint8_t *kyber_ciphertext,
    const size_t kyber_ciphertext_length,
    const uint8_t *kyber_shared_secret,
    const size_t kyber_shared_secret_length,
    EppError *out_error) {
    if (!handle || !handle->system) {
        fill_error(out_error, EPP_ERROR_INVALID_STATE, "Protocol system handle is null or uninitialized");
        return EPP_ERROR_INVALID_STATE;
    }
    if (!kyber_ciphertext || kyber_ciphertext_length == 0) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Kyber ciphertext is null or empty");
        return EPP_ERROR_INVALID_INPUT;
    }
    if (!kyber_shared_secret || kyber_shared_secret_length == 0) {
        fill_error(out_error, EPP_ERROR_INVALID_INPUT, "Kyber shared secret is null or empty");
        return EPP_ERROR_INVALID_INPUT;
    }

    auto result = handle->system->SetConnectionKyberSecrets(
        std::span(kyber_ciphertext, kyber_ciphertext_length),
        std::span(kyber_shared_secret, kyber_shared_secret_length));

    if (result.IsErr()) {
        return fill_error_from_failure(out_error, std::move(result).UnwrapErr());
    }

    return EPP_SUCCESS;
}

void epp_server_destroy(const ProtocolSystemHandle *handle) {
    delete handle;
}

// ============================================================================
// Version & Initialization
// ============================================================================

const char *epp_version(void) {
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

// ============================================================================
// Identity Keys Management
// ============================================================================

EppErrorCode epp_identity_create(
    EppIdentityHandle **out_handle,
    EppError *out_error) {
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

    auto *handle = new(std::nothrow) EppIdentityHandle{
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
    const uint8_t *seed,
    const size_t seed_length,
    EppIdentityHandle **out_handle,
    EppError *out_error) {
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

    auto *handle = new(std::nothrow) EppIdentityHandle{
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
    const uint8_t *seed,
    const size_t seed_length,
    const char *membership_id,
    const size_t membership_id_length,
    EppIdentityHandle **out_handle,
    EppError *out_error) {
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

    auto *handle = new(std::nothrow) EppIdentityHandle{
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
    const EppIdentityHandle *handle,
    uint8_t *out_key,
    const size_t out_key_length,
    EppError *out_error) {
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

    const auto &key = handle->identity_keys->GetIdentityX25519PublicKeyCopy();
    std::memcpy(out_key, key.data(), key.size());

    return EPP_SUCCESS;
}

EppErrorCode epp_identity_get_ed25519_public(
    const EppIdentityHandle *handle,
    uint8_t *out_key,
    const size_t out_key_length,
    EppError *out_error) {
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

    const auto &key = handle->identity_keys->GetIdentityEd25519PublicKeyCopy();
    std::memcpy(out_key, key.data(), key.size());

    return EPP_SUCCESS;
}

EppErrorCode epp_identity_get_kyber_public(
    const EppIdentityHandle *handle,
    uint8_t *out_key,
    const size_t out_key_length,
    EppError *out_error) {
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

    const auto &key = handle->identity_keys->GetKyberPublicKeyCopy();
    std::memcpy(out_key, key.data(), key.size());

    return EPP_SUCCESS;
}

void epp_identity_destroy(EppIdentityHandle *handle) {
    delete handle;
}

// ============================================================================
// Session Utilities
// ============================================================================

EppErrorCode epp_session_age_seconds(
    const ProtocolSystemHandle *handle,
    uint64_t *out_age_seconds,
    EppError *out_error) {
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

// ============================================================================
// Envelope & Key Derivation
// ============================================================================

EppErrorCode epp_envelope_validate(
    const uint8_t *encrypted_envelope,
    const size_t encrypted_envelope_length,
    EppError *out_error) {
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
        const auto &ct = envelope.kyber_ciphertext();
        if (ct.size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
            fill_error(out_error, EPP_ERROR_DECODE, "Invalid Kyber ciphertext size");
            return EPP_ERROR_DECODE;
        }
    }

    return EPP_SUCCESS;
}

EppErrorCode epp_derive_root_key(
    const uint8_t *opaque_session_key,
    const size_t opaque_session_key_length,
    const uint8_t *user_context,
    const size_t user_context_length,
    uint8_t *out_root_key,
    const size_t out_root_key_length,
    EppError *out_error) {
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
    (void) _wipe;
    return EPP_SUCCESS;
}

// ============================================================================
// Shamir Secret Sharing
// ============================================================================

EppErrorCode epp_shamir_split(
    const uint8_t *secret,
    const size_t secret_length,
    const uint8_t threshold,
    const uint8_t share_count,
    const uint8_t *auth_key,
    const size_t auth_key_length,
    EppBuffer *out_shares,
    size_t *out_share_length,
    EppError *out_error) {
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
    for (const auto &share: shares) {
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
    auto *data = new(std::nothrow) uint8_t[total_length];
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
    const uint8_t *shares,
    const size_t shares_length,
    const size_t share_length,
    const size_t share_count,
    const uint8_t *auth_key,
    const size_t auth_key_length,
    EppBuffer *out_secret,
    EppError *out_error) {
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

// ============================================================================
// Memory & Error Management
// ============================================================================

EppBuffer *epp_buffer_alloc(const size_t capacity) {
    auto *buffer = new(std::nothrow) EppBuffer{};
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

void epp_buffer_free(EppBuffer *buffer) {
    if (buffer) {
        if (buffer->data) {
            SodiumInterop::SecureWipe(std::span(buffer->data, buffer->length));
            delete[] buffer->data;
        }
        delete buffer;
    }
}

void epp_error_free(EppError *error) {
    if (error && error->message) {
        free(error->message);
        error->message = nullptr;
    }
}

const char *epp_error_string(const EppErrorCode code) {
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
}
