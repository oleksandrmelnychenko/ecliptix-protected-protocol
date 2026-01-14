#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/option.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/protocol/chain_step/chain_step.hpp"
#include "ecliptix/models/bundles/local_public_key_bundle.hpp"
#include "ecliptix/models/keys/chain_key.hpp"
#include "ecliptix/configuration/ratchet_config.hpp"
#include "ecliptix/enums/key_exchange_type.hpp"
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
#include <array>

namespace ecliptix::proto::protocol {
    class RatchetState;
}

namespace ecliptix::protocol::connection {
    using protocol::Result;
    using protocol::Option;
    using protocol::Unit;
    using protocol::ProtocolFailure;
    using crypto::SecureMemoryHandle;
    using chain_step::ChainStep;
    using models::LocalPublicKeyBundle;
    using models::ChainKey;
    using configuration::RatchetConfig;
    using enums::KeyExchangeType;

    class ProtocolConnection {
    public:
        [[nodiscard]] static Result<std::unique_ptr<ProtocolConnection>, ProtocolFailure> Create(
            uint32_t connection_id,
            bool is_initiator);

        [[nodiscard]] static Result<std::unique_ptr<ProtocolConnection>, ProtocolFailure> Create(
            uint32_t connection_id,
            bool is_initiator,
            const RatchetConfig &ratchet_config);

        [[nodiscard]] static Result<std::unique_ptr<ProtocolConnection>, ProtocolFailure>
        FromProtoState(
            uint32_t connection_id,
            const proto::protocol::RatchetState &proto,
            RatchetConfig ratchet_config,
            KeyExchangeType exchange_type);

        [[nodiscard]] static Result<std::vector<uint8_t>, ProtocolFailure>
        DeriveOpaqueMessagingRoot(
            std::span<const uint8_t> opaque_session_key,
            std::span<const uint8_t> user_context);

        [[nodiscard]] static Result<std::unique_ptr<ProtocolConnection>, ProtocolFailure>
        FromRootAndPeerBundle(
            uint32_t connection_id,
            std::span<const uint8_t> root_key,
            const proto::protocol::PublicKeyBundle &peer_bundle,
            bool is_initiator);

        [[nodiscard]] static Result<std::unique_ptr<ProtocolConnection>, ProtocolFailure>
        FromRootAndPeerBundle(
            uint32_t connection_id,
            std::span<const uint8_t> root_key,
            const proto::protocol::PublicKeyBundle &peer_bundle,
            bool is_initiator,
            std::span<const uint8_t> kyber_ciphertext,
            std::span<const uint8_t> kyber_shared_secret);

        [[nodiscard]] static Result<std::unique_ptr<ProtocolConnection>, ProtocolFailure>
        FromRootAndPeerBundle(
            uint32_t connection_id,
            std::span<const uint8_t> root_key,
            const proto::protocol::PublicKeyBundle &peer_bundle,
            bool is_initiator,
            std::span<const uint8_t> kyber_ciphertext,
            std::span<const uint8_t> kyber_shared_secret,
            std::span<const uint8_t> initial_dh_public_key,
            std::span<const uint8_t> initial_dh_private_key);

        [[nodiscard]] Result<Unit, ProtocolFailure> SetPeerBundle(
            const LocalPublicKeyBundle &peer_bundle);

        [[nodiscard]] Result<Unit, ProtocolFailure> FinalizeChainAndDhKeys(
            std::span<const uint8_t> initial_root_key,
            std::span<const uint8_t> initial_peer_dh_public_key);

        [[nodiscard]] Result<Unit, ProtocolFailure> FinalizeChainAndDhKeysWithRoot(
            std::span<const uint8_t> initial_root_key);

        [[nodiscard]] Result<std::pair<ChainKey, bool>, ProtocolFailure>
        PrepareNextSendMessage();

        struct ReceivingRatchetPreview {
            std::vector<uint8_t> metadata_key;
            std::vector<uint8_t> new_root_key;
            ChainStep receiving_step;
            std::vector<uint8_t> peer_dh_public_key;
            std::vector<uint8_t> kyber_ciphertext;
            std::vector<uint8_t> kyber_shared_secret;
            uint64_t new_receiving_epoch;
        };

        [[nodiscard]] Result<ReceivingRatchetPreview, ProtocolFailure>
        PrepareReceivingRatchet(
            std::span<const uint8_t> received_dh_public_key,
            std::span<const uint8_t> received_kyber_ciphertext);

        [[nodiscard]] Result<Unit, ProtocolFailure>
        CommitReceivingRatchet(ReceivingRatchetPreview &&preview);

        [[nodiscard]] Result<ChainKey, ProtocolFailure>
        ProcessReceivedMessage(uint32_t received_index, std::span<const uint8_t> nonce);

        [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure>
        GenerateNextNonce(std::optional<uint32_t> message_index = std::nullopt);

        [[nodiscard]] Result<Unit, ProtocolFailure> ValidateNotReplayed(
            std::span<const uint8_t> nonce,
            uint64_t message_index);

        [[nodiscard]] Result<Unit, ProtocolFailure> ExecuteReceivingRatchet(
            std::span<const uint8_t> received_dh_public_key,
            std::span<const uint8_t> received_kyber_ciphertext);

        void NotifyRatchetRotation();

        void SetEventHandler(std::shared_ptr<IProtocolEventHandler> handler);

        [[nodiscard]] Result<Unit, ProtocolFailure> SyncWithRemoteState(
            uint32_t remote_sending_chain_length,
            uint32_t remote_receiving_chain_length);

        [[nodiscard]] uint32_t GetId() const noexcept;

        [[nodiscard]] bool IsInitiator() const noexcept;

        [[nodiscard]] KeyExchangeType ExchangeType() const noexcept;

        [[nodiscard]] uint64_t GetSessionAgeSeconds() const noexcept;

        [[nodiscard]] Result<LocalPublicKeyBundle, ProtocolFailure> GetPeerBundle() const;

        [[nodiscard]] Result<Option<std::vector<uint8_t> >, ProtocolFailure>
        GetCurrentPeerDhPublicKey() const;

        [[nodiscard]] Result<Option<std::vector<uint8_t> >, ProtocolFailure>
        GetCurrentSenderDhPublicKey() const;

        [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure>
        GetMetadataEncryptionKey() const;

        [[nodiscard]] Result<Option<std::vector<uint8_t> >, ProtocolFailure>
        GetCurrentKyberCiphertext() const;

        [[nodiscard]] Result<Unit, ProtocolFailure> SetLocalKyberKeyPair(
            SecureMemoryHandle secret_key_handle,
            std::span<const uint8_t> public_key);

        [[nodiscard]] Result<Unit, ProtocolFailure> SetHybridHandshakeSecrets(
            std::span<const uint8_t> kyber_ciphertext,
            std::span<const uint8_t> kyber_shared_secret);

        [[nodiscard]] Result<Unit, ProtocolFailure> DeriveKyberSharedSecretFromCiphertext(
            std::span<const uint8_t> kyber_ciphertext);

        [[nodiscard]] std::vector<uint8_t> GetKyberPublicKeyCopy() const;
#ifdef ECLIPTIX_TEST_BUILD
        [[nodiscard]] std::vector<uint8_t> DebugGetRootKey() const;

        [[nodiscard]] std::vector<uint8_t> DebugGetCurrentDhPrivate() const;

        [[nodiscard]] std::vector<uint8_t> DebugGetKyberSharedSecret() const;

        [[nodiscard]] Result<Unit, ProtocolFailure> DebugSetPeerKyberPublicKey(
            std::span<const uint8_t> peer_kyber_public_key);
#endif

        [[nodiscard]] uint64_t GetSendingRatchetEpoch() const noexcept;

        [[nodiscard]] uint64_t GetReceivingRatchetEpoch() const noexcept;

        [[nodiscard]] Result<std::pair<uint32_t, uint32_t>, ProtocolFailure>
        GetChainIndices() const;

        [[nodiscard]] Result<proto::protocol::RatchetState, ProtocolFailure>
        ToProtoState() const;

        ProtocolConnection(ProtocolConnection &&) = delete;

        ProtocolConnection &operator=(ProtocolConnection &&) = delete;

        ProtocolConnection(const ProtocolConnection &) = delete;

        ProtocolConnection &operator=(const ProtocolConnection &) = delete;

        ~ProtocolConnection();

    private:
        explicit ProtocolConnection(
            uint32_t connection_id,
            bool is_initiator,
            RatchetConfig ratchet_config,
            KeyExchangeType exchange_type,
            SecureMemoryHandle initial_sending_dh_private_handle,
            const std::vector<uint8_t> &initial_sending_dh_public,
            SecureMemoryHandle persistent_dh_private_handle,
            std::vector<uint8_t> persistent_dh_public,
            ChainStep sending_step);

        explicit ProtocolConnection(
            uint32_t connection_id,
            bool is_initiator,
            RatchetConfig ratchet_config,
            KeyExchangeType exchange_type,
            std::chrono::system_clock::time_point created_at,
            std::vector<uint8_t> session_id,
            uint64_t nonce_counter,
            SecureMemoryHandle root_key_handle,
            SecureMemoryHandle metadata_encryption_key_handle,
            ChainStep sending_step,
            std::optional<ChainStep> receiving_step,
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

        [[nodiscard]] Result<Unit, ProtocolFailure> IsFinalized() const;

        [[nodiscard]] Result<Unit, ProtocolFailure> EnsureNotFinalized() const;

        [[nodiscard]] Result<Unit, ProtocolFailure> EnsureNotDisposed() const;

        [[nodiscard]] Result<Unit, ProtocolFailure> EnsureNotExpired() const;

        [[nodiscard]] Result<Unit, ProtocolFailure>
        DeriveMetadataEncryptionKey();

        [[nodiscard]] static Result<std::vector<uint8_t>, ProtocolFailure>
        DeriveMetadataEncryptionKeyBytes(
            std::span<const uint8_t> root_bytes,
            std::span<const uint8_t> sender_dh_public,
            std::span<const uint8_t> peer_dh_public,
            std::span<const uint8_t> kyber_shared_secret);

        [[nodiscard]] static Result<std::vector<uint8_t>, ProtocolFailure> DeriveStateMacKey(
            std::span<const uint8_t> root_key_bytes,
            std::span<const uint8_t> session_id,
            bool is_initiator,
            uint32_t connection_id,
            std::span<const uint8_t> initial_sending_dh_public,
            std::span<const uint8_t> current_sending_dh_public,
            std::span<const uint8_t> kyber_public_key,
            std::span<const uint8_t> peer_kyber_public_key,
            std::span<const uint8_t> kyber_ciphertext);

        [[nodiscard]] static Result<std::vector<uint8_t>, ProtocolFailure> ComputeStateMac(
            proto::protocol::RatchetState state,
            std::span<const uint8_t> mac_key);

        [[nodiscard]] static Result<Unit, ProtocolFailure> VerifyStateMac(
            const proto::protocol::RatchetState &proto,
            uint32_t expected_connection_id);

        [[nodiscard]] Result<Unit, ProtocolFailure>
        ExecuteDhRatchet(bool is_sender,
                         std::span<const uint8_t> received_dh_public_key = {},
                         std::span<const uint8_t> received_kyber_ciphertext = {});

        void CleanupIfNeeded(uint32_t received_index);

        [[nodiscard]] Result<Unit, ProtocolFailure> ValidateHybridPersistenceInvariants() const;

        [[nodiscard]] static Result<Unit, ProtocolFailure> ValidateHybridPersistenceInvariants(
            const proto::protocol::RatchetState &proto);

        Result<Unit, ProtocolFailure> UpdateKyberSecretFromCiphertext(std::span<const uint8_t> kyber_ct);

        [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure> DecapsulateKyberCiphertext(
            std::span<const uint8_t> kyber_ct) const;

        mutable std::unique_ptr<std::mutex> lock_;
        uint32_t id_;
        std::chrono::system_clock::time_point created_at_;
        std::vector<uint8_t> session_id_;
        bool is_initiator_;
        KeyExchangeType exchange_type_;
        RatchetConfig ratchet_config_;
        std::optional<SecureMemoryHandle> root_key_handle_;
        std::optional<SecureMemoryHandle> metadata_encryption_key_handle_;
        SecureMemoryHandle initial_sending_dh_private_handle_;
        std::vector<uint8_t> initial_sending_dh_public_;
        std::vector<uint8_t> initial_peer_dh_public_;
        std::optional<SecureMemoryHandle> current_sending_dh_private_handle_;
        std::vector<uint8_t> current_sending_dh_public_;
        SecureMemoryHandle persistent_dh_private_handle_;
        std::vector<uint8_t> persistent_dh_public_;
        ChainStep sending_step_;
        std::optional<ChainStep> receiving_step_;
        std::optional<LocalPublicKeyBundle> peer_bundle_;
        std::optional<std::vector<uint8_t> > peer_dh_public_key_;
        std::optional<std::vector<uint8_t> > peer_kyber_public_key_;
        std::optional<std::vector<uint8_t> > kyber_ciphertext_;
        std::optional<std::vector<uint8_t> > kyber_shared_secret_;
        SecureMemoryHandle kyber_secret_key_handle_;
        std::vector<uint8_t> kyber_public_key_;
        security::ReplayProtection replay_protection_;
        std::array<uint8_t, ProtocolConstants::NONCE_PREFIX_SIZE> nonce_prefix_;
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
        std::atomic<uint64_t> receiving_ratchet_epoch_;
        std::atomic<uint64_t> sending_ratchet_epoch_;
        std::shared_ptr<IProtocolEventHandler> event_handler_;
    };
}
