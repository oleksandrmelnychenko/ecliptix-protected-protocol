#pragma once

#include "ecliptix/interfaces/i_key_provider.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"

#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace ecliptix::protocol::models {

using protocol::Result;
using protocol::Unit;
using protocol::EcliptixProtocolFailure;
using interfaces::IKeyProvider;

/**
 * @brief Lightweight reference to a message encryption key at a specific index
 *
 * MessageKey is semantically identical to RatchetChainKey but provides a
 * stronger type distinction for message-specific operations. This prevents
 * accidentally using a chain key where a message key is expected.
 *
 * **Derivation**:
 * ```
 * MessageKey[N] = HKDF-SHA256(ChainKey[N], info="Ecliptix-Msg")
 * ```
 *
 * **Usage in Protocol**:
 * - Each message is encrypted with a unique message key derived from the chain key
 * - Message keys can be cached for out-of-order delivery
 * - Once used, message keys should be deleted (single-use property)
 *
 * **AES-256-GCM Encryption**:
 * Message keys are used with AES-256-GCM for authenticated encryption:
 * ```
 * Ciphertext = AES-256-GCM-Encrypt(
 *     key = MessageKey[N],
 *     nonce = GenerateNonce(),
 *     plaintext = message,
 *     associated_data = header || sender_identity
 * )
 * ```
 *
 * **Example**:
 * ```cpp
 * // Get message key for encryption
 * auto msg_key_result = sending_chain.GetOrDeriveKeyFor(42);
 * MessageKey msg_key = msg_key_result.Unwrap();
 *
 * // Encrypt message (key never exposed)
 * std::vector<uint8_t> plaintext = {...};
 * std::vector<uint8_t> ad = {...};
 * auto ciphertext = msg_key.Encrypt(plaintext, ad).Unwrap();
 * ```
 */
class MessageKey {
public:
    /**
     * @brief Construct a message key reference
     *
     * @param provider Non-owning pointer to the key provider (must outlive this object)
     * @param index The message index for this key
     */
    MessageKey(IKeyProvider* provider, uint32_t index) noexcept
        : provider_(provider), index_(index) {}

    /**
     * @brief Get the message index
     *
     * @return The index this key corresponds to
     */
    [[nodiscard]] uint32_t Index() const noexcept {
        return index_;
    }

    /**
     * @brief Execute an operation with access to the message key material
     *
     * @tparam T Return type of the operation
     * @param operation Callback that receives std::span<const uint8_t> containing the key
     * @return Result from the operation
     *
     * @note The key span is ONLY valid during the callback
     * @note Do NOT store the span or copy its contents outside the callback
     *
     * **Example**:
     * ```cpp
     * auto encrypted = msg_key.WithKeyMaterial<std::vector<uint8_t>>(
     *     [&](std::span<const uint8_t> key) {
     *         return AesGcmEncrypt(key, plaintext, nonce, ad);
     *     }
     * );
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
     */
    [[nodiscard]] bool operator==(const MessageKey& other) const noexcept {
        return index_ == other.index_;
    }

    [[nodiscard]] bool operator!=(const MessageKey& other) const noexcept {
        return !(*this == other);
    }

    /**
     * @brief Less-than comparison for ordered containers
     */
    [[nodiscard]] bool operator<(const MessageKey& other) const noexcept {
        return index_ < other.index_;
    }

    // Copyable and movable (cheap - just a pointer and an integer)
    MessageKey(const MessageKey&) = default;
    MessageKey& operator=(const MessageKey&) = default;
    MessageKey(MessageKey&&) noexcept = default;
    MessageKey& operator=(MessageKey&&) noexcept = default;
    ~MessageKey() = default;

private:
    IKeyProvider* provider_;  ///< Non-owning pointer to key provider (ChainStep)
    uint32_t index_;           ///< Message index for this key
};

} // namespace ecliptix::protocol::models
