#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/option.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/protocol/chain_step/ecliptix_protocol_chain_step.hpp"
#include "ecliptix/models/bundles/local_public_key_bundle.hpp"
#include "ecliptix/models/keys/ratchet_chain_key.hpp"
#include "ecliptix/configuration/ratchet_config.hpp"
#include "ecliptix/enums/pub_key_exchange_type.hpp"
#include "ecliptix/interfaces/i_protocol_event_handler.hpp"
#include "ecliptix/security/ratcheting/replay_protection.hpp"
#include "protocol/key_exchange.pb.h"
#include <cstdint>
#include <vector>
#include <chrono>
#include <memory>
#include <mutex>
#include <atomic>
#include <optional>

namespace ecliptix::proto::protocol {
    class RatchetState;
}

namespace ecliptix::protocol::connection {
    using protocol::Result;
    using protocol::Option;
    using protocol::Unit;
    using protocol::EcliptixProtocolFailure;
    using crypto::SecureMemoryHandle;
    using chain_step::EcliptixProtocolChainStep;
    using models::LocalPublicKeyBundle;
    using models::RatchetChainKey;
    using configuration::RatchetConfig;
    using enums::PubKeyExchangeType;

    class EcliptixProtocolConnection {
    public:
        [[nodiscard]] static Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure> Create(
            uint32_t connection_id,
            bool is_initiator);

        [[nodiscard]] static Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure> Create(
            uint32_t connection_id,
            bool is_initiator,
            const RatchetConfig &ratchet_config);

        [[nodiscard]] static Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>
        FromProtoState(
            uint32_t connection_id,
            const proto::protocol::RatchetState &proto,
            RatchetConfig ratchet_config,
            PubKeyExchangeType exchange_type);

        [[nodiscard]] static Result<std::vector<uint8_t>, EcliptixProtocolFailure>
        DeriveOpaqueMessagingRoot(
            std::span<const uint8_t> opaque_session_key,
            std::span<const uint8_t> user_context);

        // Bootstrap from pre-shared root + peer bundle (OPAQUE or other authenticated channel).
        [[nodiscard]] static Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>
        FromRootAndPeerBundle(
            std::span<const uint8_t> root_key,
            const proto::protocol::PublicKeyBundle &peer_bundle,
            bool is_initiator);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SetPeerBundle(
            const LocalPublicKeyBundle &peer_bundle);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> FinalizeChainAndDhKeys(
            std::span<const uint8_t> initial_root_key,
            std::span<const uint8_t> initial_peer_dh_public_key);

        // Finalize using a pre-shared root key (OPAQUE/bootstrap path) without an initial DH public key.
        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> FinalizeChainAndDhKeysWithRoot(
            std::span<const uint8_t> initial_root_key);

        [[nodiscard]] Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>
        PrepareNextSendMessage();

        struct ReceivingRatchetPreview {
            std::vector<uint8_t> metadata_key;
            std::vector<uint8_t> new_root_key;
            EcliptixProtocolChainStep receiving_step;
            std::vector<uint8_t> peer_dh_public_key;
            uint64_t new_receiving_epoch;
        };

        [[nodiscard]] Result<ReceivingRatchetPreview, EcliptixProtocolFailure>
        PrepareReceivingRatchet(
            std::span<const uint8_t> received_dh_public_key,
            std::span<const uint8_t> received_kyber_ciphertext);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure>
        CommitReceivingRatchet(ReceivingRatchetPreview &&preview);

        [[nodiscard]] Result<RatchetChainKey, EcliptixProtocolFailure>
        ProcessReceivedMessage(uint32_t received_index, std::span<const uint8_t> nonce);

        [[nodiscard]] Result<std::vector<uint8_t>, EcliptixProtocolFailure>
        GenerateNextNonce(std::optional<uint32_t> message_index = std::nullopt);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> CheckReplayProtection(
            std::span<const uint8_t> nonce,
            uint64_t message_index);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> PerformReceivingRatchet(
            std::span<const uint8_t> received_dh_public_key,
            std::span<const uint8_t> received_kyber_ciphertext);

        void NotifyRatchetRotation();

        void SetEventHandler(std::shared_ptr<IProtocolEventHandler> handler);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SyncWithRemoteState(
            uint32_t remote_sending_chain_length,
            uint32_t remote_receiving_chain_length);

        [[nodiscard]] uint32_t GetId() const noexcept;

        [[nodiscard]] bool IsInitiator() const noexcept;

        [[nodiscard]] PubKeyExchangeType ExchangeType() const noexcept;

        [[nodiscard]] Result<LocalPublicKeyBundle, EcliptixProtocolFailure> GetPeerBundle() const;

        [[nodiscard]] Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>
        GetCurrentPeerDhPublicKey() const;

        [[nodiscard]] Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>
        GetCurrentSenderDhPublicKey() const;

        [[nodiscard]] Result<std::vector<uint8_t>, EcliptixProtocolFailure>
        GetMetadataEncryptionKey() const;

        [[nodiscard]] Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>
        GetCurrentKyberCiphertext() const;

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SetLocalKyberKeyPair(
            SecureMemoryHandle secret_key_handle,
            std::span<const uint8_t> public_key);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SetHybridHandshakeSecrets(
            std::span<const uint8_t> kyber_ciphertext,
            std::span<const uint8_t> kyber_shared_secret);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> DeriveKyberSharedSecretFromCiphertext(
            std::span<const uint8_t> kyber_ciphertext);

        [[nodiscard]] std::vector<uint8_t> GetKyberPublicKeyCopy() const;
#ifdef ECLIPTIX_TEST_BUILD
        [[nodiscard]] std::vector<uint8_t> DebugGetRootKey() const;

        [[nodiscard]] std::vector<uint8_t> DebugGetCurrentDhPrivate() const;

        [[nodiscard]] std::vector<uint8_t> DebugGetKyberSharedSecret() const;

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> DebugSetPeerKyberPublicKey(
            std::span<const uint8_t> peer_kyber_public_key);
#endif

        [[nodiscard]] uint64_t GetSendingRatchetEpoch() const noexcept;

        [[nodiscard]] uint64_t GetReceivingRatchetEpoch() const noexcept;

        [[nodiscard]] Result<proto::protocol::RatchetState, EcliptixProtocolFailure>
        ToProtoState() const;

        EcliptixProtocolConnection(EcliptixProtocolConnection &&) = delete;

        EcliptixProtocolConnection &operator=(EcliptixProtocolConnection &&) = delete;

        EcliptixProtocolConnection(const EcliptixProtocolConnection &) = delete;

        EcliptixProtocolConnection &operator=(const EcliptixProtocolConnection &) = delete;

        ~EcliptixProtocolConnection();

    private:
        explicit EcliptixProtocolConnection(
            uint32_t connection_id,
            bool is_initiator,
            RatchetConfig ratchet_config,
            PubKeyExchangeType exchange_type,
            SecureMemoryHandle initial_sending_dh_private_handle,
            std::vector<uint8_t> initial_sending_dh_public,
            SecureMemoryHandle persistent_dh_private_handle,
            std::vector<uint8_t> persistent_dh_public,
            EcliptixProtocolChainStep sending_step);

        explicit EcliptixProtocolConnection(
            uint32_t connection_id,
            bool is_initiator,
            RatchetConfig ratchet_config,
            PubKeyExchangeType exchange_type,
            std::chrono::system_clock::time_point created_at,
            std::vector<uint8_t> session_id,
            uint64_t nonce_counter,
            SecureMemoryHandle root_key_handle,
            SecureMemoryHandle metadata_encryption_key_handle,
            EcliptixProtocolChainStep sending_step,
            std::optional<EcliptixProtocolChainStep> receiving_step,
            std::optional<LocalPublicKeyBundle> peer_bundle,
            std::optional<std::vector<uint8_t> > peer_dh_public_key,
            std::optional<std::vector<uint8_t> > peer_kyber_public_key,
            std::optional<std::vector<uint8_t> > kyber_ciphertext,
            std::optional<std::vector<uint8_t> > kyber_shared_secret,
            SecureMemoryHandle kyber_secret_key_handle,
            std::vector<uint8_t> kyber_public_key,
            SecureMemoryHandle initial_sending_dh_private_handle,
            std::vector<uint8_t> initial_sending_dh_public,
            SecureMemoryHandle current_sending_dh_private_handle,
            SecureMemoryHandle persistent_dh_private_handle,
            std::vector<uint8_t> persistent_dh_public,
            bool is_first_receiving_ratchet);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> CheckIfFinalized() const;

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> CheckIfNotFinalized() const;

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> CheckDisposed() const;

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> EnsureNotExpired() const;

        [[nodiscard]] Result<bool, EcliptixProtocolFailure> MaybePerformSendingDhRatchet();

        [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> DeriveRatchetKeys(
            std::span<const uint8_t> dh_secret,
            std::span<const uint8_t> current_root_key,
            std::span<uint8_t> new_root_key,
            std::span<uint8_t> new_chain_key);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure>
        DeriveMetadataEncryptionKey();

        [[nodiscard]] Result<std::vector<uint8_t>, EcliptixProtocolFailure>
        DeriveMetadataEncryptionKeyBytes(
            std::span<const uint8_t> root_bytes,
            std::span<const uint8_t> sender_dh_public,
            std::span<const uint8_t> peer_dh_public);

        [[nodiscard]] static Result<std::vector<uint8_t>, EcliptixProtocolFailure> DeriveStateMacKey(
            std::span<const uint8_t> root_key_bytes,
            std::span<const uint8_t> session_id,
            bool is_initiator,
            uint32_t connection_id,
            std::span<const uint8_t> initial_sending_dh_public,
            std::span<const uint8_t> current_sending_dh_public,
            std::span<const uint8_t> kyber_public_key,
            std::span<const uint8_t> peer_kyber_public_key,
            std::span<const uint8_t> kyber_ciphertext);

        [[nodiscard]] static Result<std::vector<uint8_t>, EcliptixProtocolFailure> ComputeStateMac(
            proto::protocol::RatchetState state,
            std::span<const uint8_t> mac_key);

        [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> VerifyStateMac(
            const proto::protocol::RatchetState &proto,
            uint32_t expected_connection_id);

        [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> ValidateInitialKeys(
            std::span<const uint8_t> root_key,
            std::span<const uint8_t> peer_dh_public_key);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure>
        PerformDhRatchet(bool is_sender,
                         std::span<const uint8_t> received_dh_public_key = {},
                         std::span<const uint8_t> received_kyber_ciphertext = {});

        void PerformCleanupIfNeeded(uint32_t received_index);

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> ValidateHybridPersistenceInvariants() const;

        [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> ValidateHybridPersistenceInvariants(
            const proto::protocol::RatchetState &proto);

        Result<Unit, EcliptixProtocolFailure> UpdateKyberSecretFromCiphertext(std::span<const uint8_t> kyber_ct);

        mutable std::unique_ptr<std::mutex> lock_;
        uint32_t id_;
        std::chrono::system_clock::time_point created_at_;
        std::vector<uint8_t> session_id_;
        bool is_initiator_;
        PubKeyExchangeType exchange_type_;
        RatchetConfig ratchet_config_;
        std::optional<SecureMemoryHandle> root_key_handle_;
        std::optional<SecureMemoryHandle> metadata_encryption_key_handle_;
        SecureMemoryHandle initial_sending_dh_private_handle_;
        std::vector<uint8_t> initial_sending_dh_public_;
        std::optional<SecureMemoryHandle> current_sending_dh_private_handle_;
        std::vector<uint8_t> current_sending_dh_public_; // Updated after each sender DH ratchet
        SecureMemoryHandle persistent_dh_private_handle_;
        std::vector<uint8_t> persistent_dh_public_;
        EcliptixProtocolChainStep sending_step_;
        std::optional<EcliptixProtocolChainStep> receiving_step_;
        std::optional<LocalPublicKeyBundle> peer_bundle_;
        std::optional<std::vector<uint8_t> > peer_dh_public_key_;
        std::optional<std::vector<uint8_t> > peer_kyber_public_key_;
        std::optional<std::vector<uint8_t> > kyber_ciphertext_;
        std::optional<std::vector<uint8_t> > kyber_shared_secret_;
        SecureMemoryHandle kyber_secret_key_handle_;
        std::vector<uint8_t> kyber_public_key_;
        security::ReplayProtection replay_protection_;
        std::atomic<uint64_t> nonce_counter_;
        std::optional<uint32_t> pending_send_index_;
        std::atomic<int64_t> rate_limit_window_start_ns_;
        std::atomic<uint32_t> nonces_in_current_window_;
        std::atomic<int64_t> dh_ratchet_rate_limit_window_start_ns_;
        std::atomic<uint32_t> dh_ratchets_in_current_window_;
        std::atomic<bool> disposed_;
        std::atomic<bool> is_first_receiving_ratchet_;
        std::atomic<bool> received_new_dh_key_;
        std::atomic<bool> ratchet_warning_triggered_;
        std::atomic<uint64_t> receiving_ratchet_epoch_; // Increments with each receiving DH ratchet
        std::atomic<uint64_t> sending_ratchet_epoch_;   // Increments with each sending DH ratchet
        std::shared_ptr<IProtocolEventHandler> event_handler_;
    };
}
