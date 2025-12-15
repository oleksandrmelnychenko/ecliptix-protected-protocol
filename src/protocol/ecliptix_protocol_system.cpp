#include "ecliptix/protocol/ecliptix_protocol_system.hpp"
#include "ecliptix/utilities/envelope_builder.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include "common/secure_envelope.pb.h"
#include <sodium.h>
#include <chrono>
#include <format>
#include <optional>

namespace ecliptix::protocol {
    using Constants = Constants;
    using ProtocolConstants = ProtocolConstants;
    using utilities::EnvelopeBuilder;
    using crypto::AesGcm;
    using crypto::SodiumInterop;

    EcliptixProtocolSystem::EcliptixProtocolSystem(
        std::unique_ptr<EcliptixSystemIdentityKeys> identity_keys)
        : identity_keys_(std::move(identity_keys))
          , connection_(nullptr)
          , event_handler_(nullptr)
          , mutex_(std::make_unique<std::mutex>()) {
    }

    Result<std::unique_ptr<EcliptixProtocolSystem>, EcliptixProtocolFailure>
    EcliptixProtocolSystem::Create(std::unique_ptr<EcliptixSystemIdentityKeys> identity_keys) {
        if (!identity_keys) {
            return Result<std::unique_ptr<EcliptixProtocolSystem>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Identity keys cannot be null"));
        }
        auto system = std::unique_ptr<EcliptixProtocolSystem>(
            new EcliptixProtocolSystem(std::move(identity_keys)));
        return Result<std::unique_ptr<EcliptixProtocolSystem>, EcliptixProtocolFailure>::Ok(
            std::move(system));
    }

    void EcliptixProtocolSystem::SetConnection(std::unique_ptr<EcliptixProtocolConnection> connection) {
        std::lock_guard lock(*mutex_);
        connection_ = std::move(connection);
        if (connection_ && event_handler_) {
            connection_->SetEventHandler(event_handler_);
        }
    }

    const EcliptixSystemIdentityKeys &EcliptixProtocolSystem::GetIdentityKeys() const noexcept {
        return *identity_keys_;
    }

    void EcliptixProtocolSystem::SetEventHandler(std::shared_ptr<IProtocolEventHandler> handler) {
        std::lock_guard lock(*mutex_);
        event_handler_ = handler;
        if (connection_) {
            connection_->SetEventHandler(handler);
        }
    }

    bool EcliptixProtocolSystem::HasConnection() const noexcept {
        std::lock_guard lock(*mutex_);
        return connection_ != nullptr;
    }

    uint32_t EcliptixProtocolSystem::GetConnectionId() noexcept {
        return 0;
    }

    EcliptixProtocolConnection *EcliptixProtocolSystem::GetConnectionSafe() const noexcept {
        std::lock_guard lock(*mutex_);
        return connection_.get();
    }

    Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>
    EcliptixProtocolSystem::SendMessage(std::span<const uint8_t> payload) const {
        if (payload.size() > static_cast<size_t>(ProtocolConstants::MAX_PAYLOAD_SIZE)) {
            return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    std::format("Payload size ({} bytes) exceeds maximum allowed ({} bytes)",
                                payload.size(), ProtocolConstants::MAX_PAYLOAD_SIZE)));
        }
        EcliptixProtocolConnection *connection = GetConnectionSafe();
        if (!connection) {
            return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Protocol connection not initialized"));
        }
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> ad;
        std::vector<uint8_t> encrypted_payload;
        std::vector<uint8_t> sender_dh_key;
        std::vector<uint8_t> kyber_ciphertext;
        std::vector<uint8_t> metadata_key;
        std::vector<uint8_t> encrypted_metadata;
        try {
            auto prep_result = connection->PrepareNextSendMessage();
            if (prep_result.IsErr()) {
                return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                    prep_result.UnwrapErr());
            }
            auto [ratchet_key, include_dh] = prep_result.Unwrap();
            auto nonce_result = connection->GenerateNextNonce(ratchet_key.Index());
            if (nonce_result.IsErr()) {
                return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                    nonce_result.UnwrapErr());
            }
            nonce = nonce_result.Unwrap();
            if (include_dh) {
                auto dh_result = connection->GetCurrentSenderDhPublicKey();
                if (dh_result.IsErr()) {
                    return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                        dh_result.UnwrapErr());
                }
                if (const auto &dh_option = dh_result.Unwrap(); dh_option.has_value()) {
                    sender_dh_key = dh_option.value();
                }
                auto kyber_ct_result = connection->GetCurrentKyberCiphertext();
                if (kyber_ct_result.IsErr()) {
                    return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                        kyber_ct_result.UnwrapErr());
                }
                if (auto kyber_opt = kyber_ct_result.Unwrap(); kyber_opt.has_value()) {
                    kyber_ciphertext = kyber_opt.value();
                } else {
                    return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic("Kyber ciphertext missing for ratchet rotation"));
                }
            }
            auto peer_bundle_result = connection->GetPeerBundle();
            if (peer_bundle_result.IsErr()) {
                return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                    peer_bundle_result.UnwrapErr());
            }
            const auto &peer_bundle = peer_bundle_result.Unwrap();
            auto local_identity = identity_keys_->GetIdentityX25519PublicKeyCopy();
            auto peer_identity = peer_bundle.GetIdentityX25519();
            if ([[maybe_unused]] bool is_initiator = connection->IsInitiator()) {
                ad = CreateAssociatedData(local_identity, peer_identity);
            } else {
                ad = CreateAssociatedData(peer_identity, local_identity);
            }
            auto encrypt_result = ratchet_key.WithKeyMaterial<std::vector<uint8_t> >(
                [&payload, &nonce, &ad](
            std::span<const uint8_t> key_material) -> Result<std::vector<uint8_t>, EcliptixProtocolFailure> {
                    return AesGcm::Encrypt(key_material, nonce, payload, ad);
                });
            if (encrypt_result.IsErr()) {
                return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                    encrypt_result.UnwrapErr());
            }
            encrypted_payload = encrypt_result.Unwrap();
            uint32_t request_id;
            randombytes_buf(&request_id, sizeof(request_id));
            if (request_id == ProtocolConstants::ZERO_VALUE) {
                request_id = ComparisonConstants::MINIMUM_REQUEST_ID;
            }
            auto metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                request_id,
                nonce,
                ratchet_key.Index(),
                {},
                proto::common::EnvelopeType::REQUEST,
                ""
            );
            auto metadata_key_result = connection->GetMetadataEncryptionKey();
            if (metadata_key_result.IsErr()) {
                return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                    metadata_key_result.UnwrapErr());
            }
            metadata_key = metadata_key_result.Unwrap();
            std::vector<uint8_t> metadata_nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(metadata_nonce.data(), metadata_nonce.size());
            auto encrypt_metadata_result = EnvelopeBuilder::EncryptMetadata(
                metadata,
                metadata_key,
                metadata_nonce,
                ad);
            if (encrypt_metadata_result.IsErr()) {
                return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                    encrypt_metadata_result.UnwrapErr());
            }
            encrypted_metadata = encrypt_metadata_result.Unwrap();
            proto::common::SecureEnvelope envelope;
            envelope.set_meta_data(encrypted_metadata.data(), encrypted_metadata.size());
            envelope.set_encrypted_payload(encrypted_payload.data(), encrypted_payload.size());
            envelope.set_header_nonce(metadata_nonce.data(), metadata_nonce.size());
            auto *timestamp = envelope.mutable_timestamp();
            auto now = std::chrono::system_clock::now();
            auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count();
            timestamp->set_seconds(seconds);
            auto result_code = static_cast<int32_t>(proto::common::EnvelopeResultCode::SUCCESS);
            envelope.set_result_code(reinterpret_cast<const char *>(&result_code), sizeof(result_code));
            if (!sender_dh_key.empty()) {
                envelope.set_dh_public_key(sender_dh_key.data(), sender_dh_key.size());
            }
            if (!kyber_ciphertext.empty()) {
                envelope.set_kyber_ciphertext(kyber_ciphertext.data(), kyber_ciphertext.size());
            }
            envelope.set_ratchet_epoch(connection->GetSendingRatchetEpoch());
            return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Ok(
                std::move(envelope));
        } catch (const std::exception &ex) {
            {
                auto __wipe1 = SodiumInterop::SecureWipe(std::span(nonce));
                (void) __wipe1;
            } {
                auto __wipe2 = SodiumInterop::SecureWipe(std::span(ad));
                (void) __wipe2;
            } {
                auto __wipe3 = SodiumInterop::SecureWipe(std::span(encrypted_payload));
                (void) __wipe3;
            } {
                auto __wipe4 = SodiumInterop::SecureWipe(std::span(sender_dh_key));
                (void) __wipe4;
            } {
                auto __wipe5 = SodiumInterop::SecureWipe(std::span(metadata_key));
                (void) __wipe5;
            } {
                auto __wipe6 = SodiumInterop::SecureWipe(std::span(kyber_ciphertext));
                (void) __wipe6;
            }
            return Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    std::format("Exception during message send: {}", ex.what())));
        } {
            auto __wipe1 = SodiumInterop::SecureWipe(std::span(nonce));
            (void) __wipe1;
        } {
            auto __wipe2 = SodiumInterop::SecureWipe(std::span(ad));
            (void) __wipe2;
        } {
            auto __wipe3 = SodiumInterop::SecureWipe(std::span(encrypted_payload));
            (void) __wipe3;
        } {
            auto __wipe4 = SodiumInterop::SecureWipe(std::span(sender_dh_key));
            (void) __wipe4;
        } {
            auto __wipe5 = SodiumInterop::SecureWipe(std::span(metadata_key));
            (void) __wipe5;
        } {
            auto __wipe6 = SodiumInterop::SecureWipe(std::span(kyber_ciphertext));
            (void) __wipe6;
        }
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    EcliptixProtocolSystem::ReceiveMessage(const proto::common::SecureEnvelope &envelope) const {
        EcliptixProtocolConnection *connection = GetConnectionSafe();
        if (!connection) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Protocol connection not initialized"));
        }
        if (!envelope.has_ratchet_epoch()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Decode("Missing ratchet epoch"));
        }
        const uint64_t envelope_epoch = envelope.ratchet_epoch();
        const uint64_t current_epoch = connection->GetReceivingRatchetEpoch();
        if (envelope_epoch < current_epoch) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Decode("Stale ratchet epoch; re-establish session"));
        }
        std::vector<uint8_t> header_nonce;
        std::vector<uint8_t> metadata_key;
        std::vector<uint8_t> ad;
        std::vector<uint8_t> encrypted_metadata;
        std::vector<uint8_t> encrypted_payload;
        std::vector<uint8_t> dh_public_key;
        std::vector<uint8_t> kyber_ciphertext;
        std::optional<connection::EcliptixProtocolConnection::ReceivingRatchetPreview> receiving_preview;
        try {
            if (envelope.header_nonce().size() != Constants::AES_GCM_NONCE_SIZE) {
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Decode("Invalid or missing header nonce for metadata decryption"));
            }
            header_nonce.assign(
                envelope.header_nonce().begin(),
                envelope.header_nonce().end());
            auto peer_bundle_result = connection->GetPeerBundle();
            if (peer_bundle_result.IsErr()) {
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                    peer_bundle_result.UnwrapErr());
            }
            const auto &peer_bundle = peer_bundle_result.Unwrap();
            auto local_identity = identity_keys_->GetIdentityX25519PublicKeyCopy();
            auto peer_identity = peer_bundle.GetIdentityX25519();
            if ([[maybe_unused]] bool is_initiator = connection->IsInitiator()) {
                ad = CreateAssociatedData(local_identity, peer_identity);
            } else {
                ad = CreateAssociatedData(peer_identity, local_identity);
            }
            if (!envelope.dh_public_key().empty()) {
                dh_public_key.assign(
                    envelope.dh_public_key().begin(),
                    envelope.dh_public_key().end());
            }
            if (!envelope.kyber_ciphertext().empty()) {
                kyber_ciphertext.assign(
                    envelope.kyber_ciphertext().begin(),
                    envelope.kyber_ciphertext().end());
            }
            bool requires_receiving_ratchet = false;
            if (!dh_public_key.empty()) {
                auto current_key_result = connection->GetCurrentPeerDhPublicKey();
                if (current_key_result.IsErr()) {
                    {
                        auto __wipe = SodiumInterop::SecureWipe(std::span(dh_public_key));
                        (void) __wipe;
                    }
                    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                        current_key_result.UnwrapErr());
                }
                if (auto current_key_option = current_key_result.Unwrap(); current_key_option.has_value()) {
                    auto comparison_result = SodiumInterop::ConstantTimeEquals(
                        dh_public_key,
                        current_key_option.value());
                    if (comparison_result.IsOk()) {
                        requires_receiving_ratchet = !comparison_result.Unwrap();
                    } else {
                        requires_receiving_ratchet = true;
                    }
                } else {
                    requires_receiving_ratchet = true;
                }
            }
            if (requires_receiving_ratchet) {
                if (kyber_ciphertext.empty()) {
                    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Decode("Missing Kyber ciphertext for hybrid ratchet"));
                }
                auto preview_result = connection->PrepareReceivingRatchet(dh_public_key, kyber_ciphertext);
                if (preview_result.IsErr()) {
                    {
                        auto __wipe = SodiumInterop::SecureWipe(std::span(dh_public_key));
                        (void) __wipe;
                        auto __wipe_ct = SodiumInterop::SecureWipe(std::span(kyber_ciphertext));
                        (void) __wipe_ct;
                    }
                    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                        preview_result.UnwrapErr());
                }
                receiving_preview = std::move(preview_result.Unwrap());
            } else {
                auto metadata_key_result = connection->GetMetadataEncryptionKey();
                if (metadata_key_result.IsErr()) {
                    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                        metadata_key_result.UnwrapErr());
                }
                metadata_key = metadata_key_result.Unwrap();
            }
            encrypted_metadata.assign(
                envelope.meta_data().begin(),
                envelope.meta_data().end());
            auto decrypt_metadata_result = EnvelopeBuilder::DecryptMetadata(
                encrypted_metadata,
                receiving_preview ? std::span<const uint8_t>(receiving_preview->metadata_key)
                                  : std::span<const uint8_t>(metadata_key),
                header_nonce,
                ad);
            if (decrypt_metadata_result.IsErr()) {
                {
                    auto _wipe_dh = SodiumInterop::SecureWipe(std::span(dh_public_key));
                    (void) _wipe_dh;
                } {
                    auto _wipe_meta = SodiumInterop::SecureWipe(std::span(metadata_key));
                    (void) _wipe_meta;
                }
                if (receiving_preview.has_value()) {
                    auto _wipe_preview_meta = SodiumInterop::SecureWipe(
                        std::span(receiving_preview->metadata_key));
                    (void) _wipe_preview_meta;
                    auto _wipe_preview_root = SodiumInterop::SecureWipe(
                        std::span(receiving_preview->new_root_key));
                    (void) _wipe_preview_root;
                }
                auto _wipe_ct = SodiumInterop::SecureWipe(std::span(kyber_ciphertext));
                (void) _wipe_ct;
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                    decrypt_metadata_result.UnwrapErr());
            }
            const auto &metadata = decrypt_metadata_result.Unwrap();
            std::vector<uint8_t> payload_nonce(
                metadata.nonce().begin(),
                metadata.nonce().end());
            if (receiving_preview.has_value()) {
                auto commit_result = connection->CommitReceivingRatchet(std::move(*receiving_preview));
                if (commit_result.IsErr()) {
                    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(commit_result.UnwrapErr());
                }
            }
            auto message_key_result = connection->ProcessReceivedMessage(
                metadata.ratchet_index(),
                payload_nonce);
            if (message_key_result.IsErr()) {
                {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(payload_nonce));
                    (void) _wipe;
                }
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                    message_key_result.UnwrapErr());
            }
            auto ratchet_key = message_key_result.Unwrap();
            encrypted_payload.assign(
                envelope.encrypted_payload().begin(),
                envelope.encrypted_payload().end());
            auto decrypt_result = ratchet_key.WithKeyMaterial<std::vector<uint8_t> >(
                [&encrypted_payload, &payload_nonce, &ad](
            std::span<const uint8_t> key_material) -> Result<std::vector<uint8_t>, EcliptixProtocolFailure> {
                    return AesGcm::Decrypt(key_material, payload_nonce, encrypted_payload, ad);
                }); {
                auto __wipe = SodiumInterop::SecureWipe(std::span(payload_nonce));
                (void) __wipe;
            }
            if (decrypt_result.IsErr()) {
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                    decrypt_result.UnwrapErr());
            }
            if (!metadata_key.empty()) {
                auto __wipe_meta = SodiumInterop::SecureWipe(std::span(metadata_key));
                (void) __wipe_meta;
            }
            if (!dh_public_key.empty()) {
                auto __wipe_dh = SodiumInterop::SecureWipe(std::span(dh_public_key));
                (void) __wipe_dh;
            }
            if (!kyber_ciphertext.empty()) {
                auto __wipe_ct = SodiumInterop::SecureWipe(std::span(kyber_ciphertext));
                (void) __wipe_ct;
            }
            return decrypt_result;
        } catch (const std::exception &ex) {
            {
                auto __wipe1 = SodiumInterop::SecureWipe(std::span(dh_public_key));
                (void) __wipe1;
            } {
                auto __wipe2 = SodiumInterop::SecureWipe(std::span(header_nonce));
                (void) __wipe2;
            } {
                auto __wipe3 = SodiumInterop::SecureWipe(std::span(metadata_key));
                (void) __wipe3;
            } {
                auto __wipe4 = SodiumInterop::SecureWipe(std::span(ad));
                (void) __wipe4;
            } {
                auto __wipe5 = SodiumInterop::SecureWipe(std::span(kyber_ciphertext));
                (void) __wipe5;
            }
            if (receiving_preview.has_value()) {
                auto __wipe_meta_preview = SodiumInterop::SecureWipe(
                    std::span(receiving_preview->metadata_key));
                (void) __wipe_meta_preview;
                auto __wipe_root_preview = SodiumInterop::SecureWipe(
                    std::span(receiving_preview->new_root_key));
                (void) __wipe_root_preview;
            }
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    std::format("Exception during message receive: {}", ex.what())));
        } {
            auto __wipe1 = SodiumInterop::SecureWipe(std::span(dh_public_key));
            (void) __wipe1;
        } {
            auto __wipe2 = SodiumInterop::SecureWipe(std::span(header_nonce));
            (void) __wipe2;
        } {
            auto __wipe3 = SodiumInterop::SecureWipe(std::span(metadata_key));
            (void) __wipe3;
        } {
            auto __wipe4 = SodiumInterop::SecureWipe(std::span(ad));
            (void) __wipe4;
        }
        if (receiving_preview.has_value()) {
            auto __wipe_meta_preview = SodiumInterop::SecureWipe(
                std::span(receiving_preview->metadata_key));
            (void) __wipe_meta_preview;
            auto __wipe_root_preview = SodiumInterop::SecureWipe(
                std::span(receiving_preview->new_root_key));
            (void) __wipe_root_preview;
        }
    }

    std::vector<uint8_t> EcliptixProtocolSystem::CreateAssociatedData(
        std::span<const uint8_t> local_identity,
        std::span<const uint8_t> peer_identity) {
        if (local_identity.size() > static_cast<size_t>(ProtocolConstants::MAX_IDENTITY_KEY_LENGTH) ||
            peer_identity.size() > static_cast<size_t>(ProtocolConstants::MAX_IDENTITY_KEY_LENGTH)) {
            throw std::invalid_argument(
                std::format("Identity key exceeds maximum length of {} bytes",
                            ProtocolConstants::MAX_IDENTITY_KEY_LENGTH));
        }
        if (local_identity.size() + peer_identity.size() >
            static_cast<size_t>(ProtocolConstants::MAX_ASSOCIATED_DATA_LENGTH)) {
            throw std::invalid_argument("Combined identity keys exceed maximum associated data length");
        }
        std::vector<uint8_t> ad;
        ad.reserve(local_identity.size() + peer_identity.size());
        ad.insert(ad.end(), local_identity.begin(), local_identity.end());
        ad.insert(ad.end(), peer_identity.begin(), peer_identity.end());
        return ad;
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolSystem::HandleDhRatchetIfNeeded(
        const proto::common::SecureEnvelope &envelope) const {
        if (envelope.dh_public_key().empty()) {
            return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
        }
        EcliptixProtocolConnection *connection = GetConnectionSafe();
        if (!connection) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Protocol connection not initialized"));
        }
        std::vector<uint8_t> received_dh_key(
            envelope.dh_public_key().begin(),
            envelope.dh_public_key().end());
        std::vector<uint8_t> received_kyber_ciphertext;
        if (!envelope.kyber_ciphertext().empty()) {
            received_kyber_ciphertext.assign(
                envelope.kyber_ciphertext().begin(),
                envelope.kyber_ciphertext().end());
        }
        try {
            auto current_key_result = connection->GetCurrentPeerDhPublicKey();
            if (current_key_result.IsErr()) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(received_dh_key));
                    (void) __wipe;
                    auto __wipe_ct = SodiumInterop::SecureWipe(std::span(received_kyber_ciphertext));
                    (void) __wipe_ct;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    current_key_result.UnwrapErr());
            }
            if (auto current_key_option = current_key_result.Unwrap(); current_key_option.has_value()) {
                auto current_key = current_key_option.value();
                auto comparison_result = SodiumInterop::ConstantTimeEquals(
                    received_dh_key,
                    current_key);
                if (comparison_result.IsOk() && comparison_result.Unwrap()) {
                    {
                        auto __wipe = SodiumInterop::SecureWipe(std::span(received_dh_key));
                        (void) __wipe;
                        auto __wipe_ct = SodiumInterop::SecureWipe(std::span(received_kyber_ciphertext));
                        (void) __wipe_ct;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
                }
            }
            if (received_kyber_ciphertext.empty()) {
                {
                    auto __wipe_dh = SodiumInterop::SecureWipe(std::span(received_dh_key));
                    (void) __wipe_dh;
                } {
                    auto __wipe_ct = SodiumInterop::SecureWipe(std::span(received_kyber_ciphertext));
                    (void) __wipe_ct;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Decode("Missing Kyber ciphertext for hybrid ratchet"));
            }
            auto ratchet_result = connection->PerformReceivingRatchet(
                received_dh_key,
                received_kyber_ciphertext); {
                auto __wipe = SodiumInterop::SecureWipe(std::span(received_dh_key));
                (void) __wipe;
                auto __wipe_ct = SodiumInterop::SecureWipe(std::span(received_kyber_ciphertext));
                (void) __wipe_ct;
            }
            return ratchet_result;
        } catch (const std::exception &ex) {
            {
                auto __wipe = SodiumInterop::SecureWipe(std::span(received_dh_key));
                (void) __wipe;
                auto __wipe_ct = SodiumInterop::SecureWipe(std::span(received_kyber_ciphertext));
                (void) __wipe_ct;
            }
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    std::format("Exception during DH ratchet: {}", ex.what())));
        }
    }
}
