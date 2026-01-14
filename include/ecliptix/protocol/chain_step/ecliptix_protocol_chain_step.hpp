#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/option.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/interfaces/i_key_provider.hpp"
#include "ecliptix/models/keys/ratchet_chain_key.hpp"
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
using protocol::EcliptixProtocolFailure;
using crypto::SecureMemoryHandle;
using interfaces::IKeyProvider;
using models::RatchetChainKey;
using enums::ChainStepType;
class EcliptixProtocolChainStep : public IKeyProvider {
public:
    [[nodiscard]] static Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> Create(
        ChainStepType step_type,
        std::span<const uint8_t> initial_chain_key,
        std::optional<std::span<const uint8_t>> dh_private_key = std::nullopt,
        std::optional<std::span<const uint8_t>> dh_public_key = std::nullopt);
    [[nodiscard]] static Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> FromProtoState(
        ChainStepType step_type,
        const proto::protocol::ChainStepState& proto);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> ExecuteWithKey(
        uint32_t index,
        std::function<Result<Unit, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation) override;
    [[nodiscard]] Result<RatchetChainKey, EcliptixProtocolFailure> GetOrDeriveKeyFor(uint32_t index);
    [[nodiscard]] Result<std::vector<uint8_t>, EcliptixProtocolFailure> GetCurrentChainKey() const;
    [[nodiscard]] Result<uint32_t, EcliptixProtocolFailure> GetCurrentIndex() const;
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SetCurrentIndex(uint32_t new_index);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SkipKeysUntil(uint32_t target_index);
    void PruneOldKeys();
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> UpdateKeysAfterDhRatchet(
        std::span<const uint8_t> new_chain_key,
        std::optional<std::span<const uint8_t>> new_dh_private_key = std::nullopt,
        std::optional<std::span<const uint8_t>> new_dh_public_key = std::nullopt);
    [[nodiscard]] Result<Option<std::vector<uint8_t>>, EcliptixProtocolFailure> ReadDhPublicKey() const;
    [[nodiscard]] Option<const SecureMemoryHandle*> GetDhPrivateKeyHandle() const;
    [[nodiscard]] Result<proto::protocol::ChainStepState, EcliptixProtocolFailure> ToProtoState() const;
    EcliptixProtocolChainStep(EcliptixProtocolChainStep&&) noexcept = default;
    EcliptixProtocolChainStep& operator=(EcliptixProtocolChainStep&&) noexcept = default;
    EcliptixProtocolChainStep(const EcliptixProtocolChainStep&) = delete;
    EcliptixProtocolChainStep& operator=(const EcliptixProtocolChainStep&) = delete;
    ~EcliptixProtocolChainStep();
private:
    explicit EcliptixProtocolChainStep(
        ChainStepType step_type,
        SecureMemoryHandle chain_key_handle,
        uint32_t initial_index,
        std::optional<SecureMemoryHandle> dh_private_key_handle,
        std::optional<std::vector<uint8_t>> dh_public_key);
    [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> DeriveNextChainKeys(
        std::span<const uint8_t> current_chain_key,
        std::span<uint8_t> next_chain_key,
        std::span<uint8_t> message_key);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> StoreMessageKey(
        uint32_t index,
        std::span<const uint8_t> message_key);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SkipKeysUntilLocked(uint32_t target_index);
    [[nodiscard]] Option<SecureMemoryHandle> TakeCachedMessageKey(uint32_t index);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> CheckDisposed() const;
    [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> ValidateChainKey(
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
