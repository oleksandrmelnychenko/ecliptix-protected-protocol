#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/option.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/interfaces/i_key_provider.hpp"
#include "ecliptix/models/keys/chain_key.hpp"
#include "ecliptix/enums/chain_step_type.hpp"
#include <cstdint>
#include <vector>
#include <map>
#include <span>
#include <optional>
#include <mutex>
#include <memory>
namespace ecliptix::proto::protocol {
class ChainStepState;
}
namespace ecliptix::protocol::chain_step {
using protocol::Result;
using protocol::Option;
using protocol::Unit;
using protocol::ProtocolFailure;
using crypto::SecureMemoryHandle;
using interfaces::IKeyProvider;
using models::ChainKey;
using enums::ChainStepType;
class ChainStep : public IKeyProvider {
public:
    [[nodiscard]] static Result<ChainStep, ProtocolFailure> Create(
        ChainStepType step_type,
        std::span<const uint8_t> initial_chain_key,
        std::optional<std::span<const uint8_t>> dh_private_key = std::nullopt,
        std::optional<std::span<const uint8_t>> dh_public_key = std::nullopt);
    [[nodiscard]] static Result<ChainStep, ProtocolFailure> FromProtoState(
        ChainStepType step_type,
        const proto::protocol::ChainStepState& proto);
    [[nodiscard]] Result<Unit, ProtocolFailure> ExecuteWithKey(
        uint32_t index,
        std::function<Result<Unit, ProtocolFailure>(std::span<const uint8_t>)> operation) override;
    [[nodiscard]] Result<ChainKey, ProtocolFailure> GetOrDeriveKeyFor(uint32_t index);
    [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure> GetCurrentChainKey() const;
    [[nodiscard]] Result<uint32_t, ProtocolFailure> GetCurrentIndex() const;
    [[nodiscard]] Result<Unit, ProtocolFailure> SetCurrentIndex(uint32_t new_index);
    [[nodiscard]] Result<Unit, ProtocolFailure> SkipKeysUntil(uint32_t target_index);
    void PruneOldKeys();
    [[nodiscard]] Result<Unit, ProtocolFailure> UpdateKeysAfterDhRatchet(
        std::span<const uint8_t> new_chain_key,
        std::optional<std::span<const uint8_t>> new_dh_private_key = std::nullopt,
        std::optional<std::span<const uint8_t>> new_dh_public_key = std::nullopt);
    [[nodiscard]] Result<Option<std::vector<uint8_t>>, ProtocolFailure> ReadDhPublicKey() const;
    [[nodiscard]] Option<const SecureMemoryHandle*> GetDhPrivateKeyHandle() const;
    [[nodiscard]] Result<proto::protocol::ChainStepState, ProtocolFailure> ToProtoState() const;
    ChainStep(ChainStep&&) noexcept = default;
    ChainStep& operator=(ChainStep&&) noexcept = default;
    ChainStep(const ChainStep&) = delete;
    ChainStep& operator=(const ChainStep&) = delete;
    ~ChainStep();
private:
    explicit ChainStep(
        ChainStepType step_type,
        SecureMemoryHandle chain_key_handle,
        uint32_t initial_index,
        std::optional<SecureMemoryHandle> dh_private_key_handle,
        std::optional<std::vector<uint8_t>> dh_public_key);
    [[nodiscard]] static Result<Unit, ProtocolFailure> DeriveNextChainKeys(
        std::span<const uint8_t> current_chain_key,
        std::span<uint8_t> next_chain_key,
        std::span<uint8_t> message_key);
    [[nodiscard]] Result<Unit, ProtocolFailure> StoreMessageKey(
        uint32_t index,
        std::span<const uint8_t> message_key);
    [[nodiscard]] Result<Unit, ProtocolFailure> SkipKeysUntilLocked(uint32_t target_index);
    [[nodiscard]] Option<SecureMemoryHandle> TakeCachedMessageKey(uint32_t index);
    [[nodiscard]] Result<Unit, ProtocolFailure> EnsureNotDisposed() const;
    [[nodiscard]] static Result<Unit, ProtocolFailure> ValidateChainKey(
        std::span<const uint8_t> chain_key);
    mutable std::unique_ptr<std::mutex> lock_;
    ChainStepType step_type_;
    SecureMemoryHandle chain_key_handle_;
    uint32_t current_index_;
    std::optional<SecureMemoryHandle> dh_private_key_handle_;
    std::optional<std::vector<uint8_t>> dh_public_key_;
    std::map<uint32_t, SecureMemoryHandle> cached_message_keys_;
    bool disposed_;
};
} 
