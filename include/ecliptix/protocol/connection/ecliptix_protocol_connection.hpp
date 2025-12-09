#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/option.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/protocol/chain_step/ecliptix_protocol_chain_step.hpp"
#include "ecliptix/models/bundles/local_public_key_bundle.hpp"
#include "ecliptix/models/keys/ratchet_chain_key.hpp"
#include "ecliptix/configuration/ratchet_config.hpp"
#include "ecliptix/enums/pub_key_exchange_type.hpp"
#include "ecliptix/interfaces/i_protocol_event_handler.hpp"
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
        const RatchetConfig& ratchet_config);
    [[nodiscard]] static Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure> FromProtoState(
        uint32_t connection_id,
        const proto::protocol::RatchetState& proto,
        RatchetConfig ratchet_config,
        PubKeyExchangeType exchange_type);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SetPeerBundle(
        const LocalPublicKeyBundle& peer_bundle);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> FinalizeChainAndDhKeys(
        std::span<const uint8_t> initial_root_key,
        std::span<const uint8_t> initial_peer_dh_public_key);
    [[nodiscard]] Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>
        PrepareNextSendMessage();
    [[nodiscard]] Result<RatchetChainKey, EcliptixProtocolFailure>
        ProcessReceivedMessage(uint32_t received_index);
    [[nodiscard]] Result<std::vector<uint8_t>, EcliptixProtocolFailure> GenerateNextNonce();
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> CheckReplayProtection(
        std::span<const uint8_t> nonce,
        uint64_t message_index);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> PerformReceivingRatchet(
        std::span<const uint8_t> received_dh_public_key);
    void NotifyRatchetRotation();
    void SetEventHandler(std::shared_ptr<IProtocolEventHandler> handler);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SyncWithRemoteState(
        uint32_t remote_sending_chain_length,
        uint32_t remote_receiving_chain_length);
    [[nodiscard]] bool IsInitiator() const noexcept;
    [[nodiscard]] PubKeyExchangeType ExchangeType() const noexcept;
    [[nodiscard]] Result<LocalPublicKeyBundle, EcliptixProtocolFailure> GetPeerBundle() const;
    [[nodiscard]] Result<Option<std::vector<uint8_t>>, EcliptixProtocolFailure>
        GetCurrentPeerDhPublicKey() const;
    [[nodiscard]] Result<Option<std::vector<uint8_t>>, EcliptixProtocolFailure>
        GetCurrentSenderDhPublicKey() const;
    [[nodiscard]] Result<std::vector<uint8_t>, EcliptixProtocolFailure>
        GetMetadataEncryptionKey() const;
    [[nodiscard]] Result<proto::protocol::RatchetState, EcliptixProtocolFailure>
        ToProtoState() const;
    EcliptixProtocolConnection(EcliptixProtocolConnection&&) = delete;
    EcliptixProtocolConnection& operator=(EcliptixProtocolConnection&&) = delete;
    EcliptixProtocolConnection(const EcliptixProtocolConnection&) = delete;
    EcliptixProtocolConnection& operator=(const EcliptixProtocolConnection&) = delete;
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
        std::optional<std::vector<uint8_t>> peer_dh_public_key,
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
    [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> ValidateInitialKeys(
        std::span<const uint8_t> root_key,
        std::span<const uint8_t> peer_dh_public_key);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure>
        PerformDhRatchet(bool is_sender, std::span<const uint8_t> received_dh_public_key = {});
    void PerformCleanupIfNeeded(uint32_t received_index);
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
    SecureMemoryHandle persistent_dh_private_handle_;       
    std::vector<uint8_t> persistent_dh_public_;             
    EcliptixProtocolChainStep sending_step_;                
    std::optional<EcliptixProtocolChainStep> receiving_step_;  
    std::optional<LocalPublicKeyBundle> peer_bundle_;       
    std::optional<std::vector<uint8_t>> peer_dh_public_key_;  
    std::atomic<uint64_t> nonce_counter_;
    std::atomic<int64_t> rate_limit_window_start_ns_;
    std::atomic<uint32_t> nonces_in_current_window_;
    std::atomic<bool> disposed_;
    std::atomic<bool> is_first_receiving_ratchet_;
    std::atomic<bool> received_new_dh_key_;
    std::atomic<bool> ratchet_warning_triggered_;
    std::shared_ptr<IProtocolEventHandler> event_handler_;  
};
} 
