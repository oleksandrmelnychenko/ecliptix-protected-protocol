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

// Forward declaration for protobuf
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

/**
 * @brief Symmetric ratchet implementation for the Double Ratchet protocol
 *
 * **Core Responsibility**: Manages one direction of the ratchet (sending OR receiving)
 *
 * **Symmetric Ratchet Algorithm**:
 * ```
 * For each message at index N:
 *   MessageKey[N] = HKDF-SHA256(ChainKey[N], info="Ecliptix-Msg")
 *   ChainKey[N+1] = HKDF-SHA256(ChainKey[N], info="Ecliptix-Chain")
 * ```
 *
 * **Key Features**:
 * 1. **Forward Secrecy**: Old chain keys can't be recovered from new ones
 * 2. **Out-of-Order Delivery**: Caches message keys for reordering
 * 3. **IKeyProvider Interface**: Safe key access without exposure
 * 4. **DH Ratchet Integration**: Accepts new chain keys from asymmetric ratchet
 * 5. **State Persistence**: Serializes to/from protobuf for recovery
 *
 * **State Maintained**:
 * - Current chain key (in secure memory)
 * - Current message index
 * - DH key pair (optional, for sending chain)
 * - Cached message keys (for out-of-order messages)
 *
 * **Thread Safety**: All methods protected by internal mutex
 *
 * **Memory Safety**:
 * - Chain key stored in libsodium secure memory (locked, guarded)
 * - Cached keys also in secure memory
 * - Move-only semantics prevent accidental copies
 * - RAII cleanup on destruction
 *
 * **Usage Example**:
 * ```cpp
 * // Create sending chain
 * std::vector<uint8_t> initial_chain_key = {...};
 * auto result = EcliptixProtocolChainStep::Create(
 *     ChainStepType::SENDER,
 *     initial_chain_key,
 *     dh_private_key,
 *     dh_public_key
 * );
 * auto sending_chain = std::move(result).Unwrap();
 *
 * // Get key for next message
 * auto key_result = sending_chain.GetOrDeriveKeyFor(5);
 * RatchetChainKey key = key_result.Unwrap();
 *
 * // Use key through IKeyProvider interface
 * key.WithKeyMaterial([](std::span<const uint8_t> key_bytes) {
 *     // Encrypt message with key_bytes
 *     return EncryptMessage(key_bytes, plaintext);
 * });
 * ```
 */
class EcliptixProtocolChainStep : public IKeyProvider {
public:
    // ========================================================================
    // Factory Methods
    // ========================================================================

    /**
     * @brief Create a new chain step with initial chain key
     *
     * @param step_type SENDER or RECEIVER
     * @param initial_chain_key Initial chain key (32 bytes, will be securely copied)
     * @param dh_private_key Optional DH private key (32 bytes, for SENDER only)
     * @param dh_public_key Optional DH public key (32 bytes)
     *
     * @return Result containing the chain step or an error
     *
     * @note initial_chain_key is wiped by the caller after this call
     * @note DH keys are required for SENDER, optional for RECEIVER
     */
    [[nodiscard]] static Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> Create(
        ChainStepType step_type,
        std::span<const uint8_t> initial_chain_key,
        std::optional<std::span<const uint8_t>> dh_private_key = std::nullopt,
        std::optional<std::span<const uint8_t>> dh_public_key = std::nullopt);

    /**
     * @brief Restore chain step from protobuf state
     *
     * @param step_type SENDER or RECEIVER
     * @param proto Protobuf ChainStepState message
     *
     * @return Result containing the restored chain step or an error
     */
    [[nodiscard]] static Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> FromProtoState(
        ChainStepType step_type,
        const proto::protocol::ChainStepState& proto);

    // ========================================================================
    // IKeyProvider Interface Implementation
    // ========================================================================

    /**
     * @brief Execute operation with key material for a specific index
     *
     * Implements the IKeyProvider interface. Provides temporary access to
     * the message key at the given index.
     *
     * **Algorithm**:
     * ```
     * if (index == current_index):
     *     return current message key (derive on-demand)
     * else if (index in cache):
     *     return cached message key (single-use, then removed)
     * else:
     *     return error (key not available)
     * ```
     *
     * @param index Message index
     * @param operation Callback that receives the message key bytes
     *
     * @return Result from the operation or error
     */
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> ExecuteWithKey(
        uint32_t index,
        std::function<Result<Unit, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation) override;

    // ========================================================================
    // Key Derivation and Access
    // ========================================================================

    /**
     * @brief Get or derive a RatchetChainKey for a specific index
     *
     * This is the primary method for obtaining keys for encryption/decryption.
     * Returns a lightweight RatchetChainKey that defers to this ChainStep
     * through the IKeyProvider interface.
     *
     * **Behavior**:
     * - If index == current_index: Advances the ratchet and returns key for current index
     * - If index < current_index: Returns cached key (if available)
     * - If index > current_index: Derives and caches keys up to index (SkipKeysUntil)
     *
     * @param index The message index to get a key for
     *
     * @return RatchetChainKey for the requested index
     *
     * @note The returned key is a lightweight reference - this ChainStep must outlive it
     */
    [[nodiscard]] Result<RatchetChainKey, EcliptixProtocolFailure> GetOrDeriveKeyFor(uint32_t index);

    /**
     * @brief Read the current chain key bytes (DANGEROUS - use sparingly)
     *
     * Returns a copy of the current chain key. The caller MUST securely wipe
     * the returned vector after use.
     *
     * @return Current chain key (32 bytes)
     *
     * @warning Only use this for serialization or DH ratchet operations
     * @warning Caller MUST call SodiumInterop::SecureWipe() on the result
     */
    [[nodiscard]] Result<std::vector<uint8_t>, EcliptixProtocolFailure> GetCurrentChainKey() const;

    // ========================================================================
    // Index Management
    // ========================================================================

    /**
     * @brief Get the current message index
     *
     * @return Current index value
     */
    [[nodiscard]] Result<uint32_t, EcliptixProtocolFailure> GetCurrentIndex() const;

    /**
     * @brief Set the current message index (internal use only)
     *
     * @param new_index New index value
     *
     * @return Ok on success, error on failure
     *
     * @note Usually called after processing a message
     */
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SetCurrentIndex(uint32_t new_index);

    // ========================================================================
    // Out-of-Order Message Support
    // ========================================================================

    /**
     * @brief Derive and cache message keys from current index to target index
     *
     * When receiving an out-of-order message at index N but current index is M
     * (where M < N), we need to derive and cache keys for indices M+1 through N-1.
     *
     * **Algorithm**:
     * ```
     * for i in (current_index + 1) .. target_index:
     *     MessageKey[i] = HKDF(ChainKey[i-1], "Ecliptix-Msg")
     *     ChainKey[i] = HKDF(ChainKey[i-1], "Ecliptix-Chain")
     *     cache[i] = MessageKey[i]
     * ```
     *
     * @param target_index Index to skip up to (exclusive)
     *
     * @return Ok on success, error if gap too large (> MAX_SKIP_MESSAGE_KEYS)
     *
     * @note Prevents DoS by limiting max skip to 1000 messages
     */
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SkipKeysUntil(uint32_t target_index);

    /**
     * @brief Remove old cached message keys to prevent unbounded growth
     *
     * Removes cached keys older than (current_index - MESSAGE_KEY_CACHE_WINDOW).
     * Called periodically to prevent memory exhaustion.
     *
     * @note Cache window is typically 2000 messages
     */
    void PruneOldKeys();

    // ========================================================================
    // DH Ratchet Integration
    // ========================================================================

    /**
     * @brief Update chain state after DH ratchet
     *
     * Called when the asymmetric (DH) ratchet completes. Replaces the current
     * chain key with a new one derived from the DH ratchet, and optionally
     * updates the DH key pair.
     *
     * **Effects**:
     * - Replaces current chain key
     * - Resets current index to 0
     * - Clears cached message keys
     * - Updates DH keys (if provided)
     *
     * @param new_chain_key New chain key from DH ratchet (32 bytes, will be copied)
     * @param new_dh_private_key Optional new DH private key (SENDER only)
     * @param new_dh_public_key Optional new DH public key
     *
     * @return Ok on success, error on failure
     *
     * @note Caller must securely wipe new_chain_key after this call
     */
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> UpdateKeysAfterDhRatchet(
        std::span<const uint8_t> new_chain_key,
        std::optional<std::span<const uint8_t>> new_dh_private_key = std::nullopt,
        std::optional<std::span<const uint8_t>> new_dh_public_key = std::nullopt);

    // ========================================================================
    // DH Key Access
    // ========================================================================

    /**
     * @brief Get a copy of the DH public key (if available)
     *
     * @return Option containing the public key (32 bytes) or None
     */
    [[nodiscard]] Result<Option<std::vector<uint8_t>>, EcliptixProtocolFailure> ReadDhPublicKey() const;

    /**
     * @brief Get a reference to the DH private key handle (SENDER only)
     *
     * @return Option containing a const reference to the secure handle or None
     *
     * @note Used by Connection for DH operations during ratchet
     */
    [[nodiscard]] Option<const SecureMemoryHandle*> GetDhPrivateKeyHandle() const;

    // ========================================================================
    // Serialization
    // ========================================================================

    /**
     * @brief Serialize current state to protobuf
     *
     * @return Protobuf ChainStepState message
     */
    [[nodiscard]] Result<proto::protocol::ChainStepState, EcliptixProtocolFailure> ToProtoState() const;

    // ========================================================================
    // Move/Copy Semantics and Cleanup
    // ========================================================================

    // Movable (for Result return), but non-copyable
    EcliptixProtocolChainStep(EcliptixProtocolChainStep&&) noexcept = default;
    EcliptixProtocolChainStep& operator=(EcliptixProtocolChainStep&&) noexcept = default;
    EcliptixProtocolChainStep(const EcliptixProtocolChainStep&) = delete;
    EcliptixProtocolChainStep& operator=(const EcliptixProtocolChainStep&) = delete;

    /**
     * @brief Destructor - securely wipes all key material
     *
     * - Wipes chain key (libsodium automatic)
     * - Wipes DH private key (libsodium automatic)
     * - Wipes all cached message keys (libsodium automatic)
     * - Wipes DH public key (sodium_memzero)
     */
    ~EcliptixProtocolChainStep();

private:
    // ========================================================================
    // Private Constructor
    // ========================================================================

    /**
     * @brief Private constructor - use factory methods
     */
    explicit EcliptixProtocolChainStep(
        ChainStepType step_type,
        SecureMemoryHandle chain_key_handle,
        uint32_t initial_index,
        std::optional<SecureMemoryHandle> dh_private_key_handle,
        std::optional<std::vector<uint8_t>> dh_public_key);

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * @brief Derive next chain key and message key from current chain key
     *
     * Implements the core symmetric ratchet algorithm:
     * ```
     * MessageKey[N] = HKDF(ChainKey[N], "Ecliptix-Msg")
     * ChainKey[N+1] = HKDF(ChainKey[N], "Ecliptix-Chain")
     * ```
     *
     * @param current_chain_key Current chain key (input)
     * @param index Index for logging/debugging
     * @param[out] next_chain_key Output: next chain key (32 bytes)
     * @param[out] message_key Output: message key (32 bytes)
     *
     * @return Ok on success, error on HKDF failure
     *
     * @note Caller must wipe all buffers after use
     */
    [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> DeriveNextChainKeys(
        std::span<const uint8_t> current_chain_key,
        uint32_t index,
        std::span<uint8_t> next_chain_key,
        std::span<uint8_t> message_key);

    /**
     * @brief Store a message key in the cache
     *
     * @param index Index to cache the key at
     * @param message_key Key material to cache (32 bytes, will be copied to secure memory)
     *
     * @return Ok on success, error on allocation failure
     */
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> StoreMessageKey(
        uint32_t index,
        std::span<const uint8_t> message_key);

    /**
     * @brief Retrieve and remove a cached message key
     *
     * @param index Index to retrieve
     *
     * @return Option containing the secure handle (moved out) or None if not found
     *
     * @note Single-use: key is removed from cache after retrieval
     */
    [[nodiscard]] Option<SecureMemoryHandle> TakeCachedMessageKey(uint32_t index);

    /**
     * @brief Check if disposed (for RAII safety)
     */
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> CheckDisposed() const;

    /**
     * @brief Validate chain key size
     */
    [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> ValidateChainKey(
        std::span<const uint8_t> chain_key);

    // ========================================================================
    // Member Variables
    // ========================================================================

    mutable std::unique_ptr<std::mutex> lock_;         ///< Protects all mutable state
    ChainStepType step_type_;                          ///< SENDER or RECEIVER
    SecureMemoryHandle chain_key_handle_;              ///< Current chain key (secure memory)
    uint32_t current_index_;                           ///< Current message index
    std::optional<SecureMemoryHandle> dh_private_key_handle_;  ///< DH private key (SENDER only)
    std::optional<std::vector<uint8_t>> dh_public_key_;        ///< DH public key
    std::map<uint32_t, SecureMemoryHandle> cached_message_keys_;  ///< Out-of-order message keys
    bool disposed_;                                    ///< Disposal flag for safety
};

} // namespace ecliptix::protocol::chain_step
