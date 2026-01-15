/**
 * @file epp_server_api.cpp
 * @brief Server-side C API implementation for EPP (Ecliptix Protection Protocol)
 *
 * This file contains server-specific API functions. Shared functions are
 * implemented in epp_common.cpp.
 */

#include "ecliptix/c_api/epp_server_api.h"
#include "epp_internal.hpp"
#include "ecliptix/protocol/protocol_system.hpp"
#include "ecliptix/protocol/connection/protocol_connection.hpp"
#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/constants.hpp"
#include "common/secure_envelope.pb.h"
#include "protocol/protocol_state.pb.h"
#include "protocol/key_exchange.pb.h"
#include <cstring>
#include <memory>
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

// Use shared internal helpers
using namespace epp::internal;

// Note: ProtocolSystemHandle and EppIdentityHandle are defined in epp_internal.hpp

extern "C" {

// ============================================================================
// Server Session Management
// ============================================================================

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

} // extern "C"
