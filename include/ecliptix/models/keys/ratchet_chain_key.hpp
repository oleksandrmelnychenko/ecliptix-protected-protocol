#pragma once

#include "ecliptix/interfaces/i_key_provider.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"

#include <cstdint>
#include <functional>
#include <span>

namespace ecliptix::protocol::models {

using protocol::Result;
using protocol::Unit;
using protocol::EcliptixProtocolFailure;
using interfaces::IKeyProvider;

/**
 * @brief Lightweight reference to a chain key at a specific index
 *
 * **IKeyProvider Pattern**:
 * Instead of exposing raw key material, RatchetChainKey holds a reference to
 * an IKeyProvider (typically the ChainStep) and defers all key access through
 * the provider's ExecuteWithKey method.
 *
 * **Design Benefits**:
 * 1. **No Key Exposure**: Keys never escape the provider's secure context
 * 2. **Lazy Evaluation**: Keys are only derived when actually needed
 * 3. **Automatic Cleanup**: Provider ensures keys are wiped after use
 * 4. **Testability**: Can mock IKeyProvider for testing
 *
 * **Thread Safety**:
 * Thread-safety depends on the provider implementation. If the provider
 * (ChainStep) uses locking, all operations through RatchetChainKey are
 * thread-safe.
 *
 * **Usage Example**:
 * ```cpp
 * // ChainStep provides the key material
 * EcliptixProtocolChainStep sending_chain = ...;
 *
 * // Get a reference to the next message key
 * auto key_result = sending_chain.GetOrDeriveKeyFor(5);
 * RatchetChainKey key = key_result.Unwrap();
 *
 * // Use the key (without ever seeing the actual bytes)
 * auto encrypted = key.Encrypt(plaintext, associated_data).Unwrap();
 * ```
 *
 * **Lifetime Requirements**:
 * The provider MUST outlive any RatchetChainKey instances that reference it.
 * This is guaranteed by the connection lifecycle management.
 */
class RatchetChainKey {
public:
    /**
     * @brief Construct a chain key reference
     *
     * @param provider Non-owning pointer to the key provider (must outlive this object)
     * @param index The chain index for this key
     *
     * @note The provider pointer is non-owning and must remain valid
     */
    RatchetChainKey(IKeyProvider* provider, uint32_t index) noexcept
        : provider_(provider), index_(index) {}

    /**
     * @brief Get the chain index
     *
     * @return The index this key corresponds to
     */
    [[nodiscard]] uint32_t Index() const noexcept {
        return index_;
    }

    /**
     * @brief Execute an operation with access to the key material
     *
     * Provides temporary access to the raw key bytes through a callback.
     * The key material is only valid during the callback execution.
     *
     * @param operation Callback that receives std::span<const uint8_t> containing the key
     * @return Result from the operation
     *
     * @note The key span is ONLY valid during the callback
     * @note Do NOT store the span or copy its contents outside the callback
     *
     * **Example**:
     * ```cpp
     * auto result = chain_key.WithKeyMaterial([](std::span<const uint8_t> key) {
     *     // Use key for encryption, HKDF, etc.
     *     return SomeOperation(key);
     * });
     * ```
     */
    template<typename T>
    [[nodiscard]] Result<T, EcliptixProtocolFailure> WithKeyMaterial(
        std::function<Result<T, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation) const {

        if (provider_ == nullptr) {
            return Result<T, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Key provider is null"));
        }

        return provider_->ExecuteWithKeyTyped<T>(index_, operation);
    }

    /**
     * @brief Equality comparison based on index
     *
     * @note Two keys are considered equal if they have the same index,
     *       even if they come from different providers
     */
    [[nodiscard]] bool operator==(const RatchetChainKey& other) const noexcept {
        return index_ == other.index_;
    }

    [[nodiscard]] bool operator!=(const RatchetChainKey& other) const noexcept {
        return !(*this == other);
    }

    /**
     * @brief Less-than comparison for ordered containers
     */
    [[nodiscard]] bool operator<(const RatchetChainKey& other) const noexcept {
        return index_ < other.index_;
    }

    // Copyable and movable (cheap - just a pointer and an integer)
    RatchetChainKey(const RatchetChainKey&) = default;
    RatchetChainKey& operator=(const RatchetChainKey&) = default;
    RatchetChainKey(RatchetChainKey&&) noexcept = default;
    RatchetChainKey& operator=(RatchetChainKey&&) noexcept = default;
    ~RatchetChainKey() = default;

private:
    IKeyProvider* provider_;  ///< Non-owning pointer to key provider (ChainStep)
    uint32_t index_;           ///< Chain index for this key
};

} // namespace ecliptix::protocol::models
