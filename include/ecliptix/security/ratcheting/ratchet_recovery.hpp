#pragma once

#include "ecliptix/core/result.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include <unordered_map>
#include <span>
#include <cstdint>
#include <mutex>
#include <optional>

namespace ecliptix::protocol::security {

// Import SecureMemoryHandle into this namespace for convenience
using crypto::SecureMemoryHandle;

/**
 * @brief Handles out-of-order message delivery via key caching
 *
 * In the Double Ratchet protocol, messages may arrive out of order.
 * To decrypt such messages, we need to cache skipped message keys
 * for later use.
 *
 * This class:
 * - Caches message keys for skipped message indices
 * - Provides deferred key access without exposing raw keys
 * - Manages memory securely (keys in locked memory)
 * - Prevents unbounded growth (max 1000 skipped keys)
 * - Cleans up old keys based on window advancement
 *
 * Thread-safe for concurrent access.
 */
class RatchetRecovery {
public:
    /**
     * @brief Construct recovery handler with default settings
     *
     * Default max skipped keys: 1000
     */
    RatchetRecovery();

    /**
     * @brief Construct with custom max skipped keys
     *
     * @param max_skipped_keys Maximum number of skipped keys to cache
     */
    explicit RatchetRecovery(uint32_t max_skipped_keys);

    // Non-copyable, non-movable (contains mutexes and secure memory)
    RatchetRecovery(const RatchetRecovery&) = delete;
    RatchetRecovery& operator=(const RatchetRecovery&) = delete;
    RatchetRecovery(RatchetRecovery&&) = delete;
    RatchetRecovery& operator=(RatchetRecovery&&) = delete;

    ~RatchetRecovery() = default;

    /**
     * @brief Store skipped message keys for later retrieval
     *
     * When a message arrives with index N+M (where M > 1), we need to
     * cache keys for indices N+1 through N+M-1 in case those messages
     * arrive later.
     *
     * @param current_chain_key The current chain key at index from_index
     * @param from_index Start index (inclusive)
     * @param to_index End index (exclusive)
     * @return Ok(Unit) if successful, Err if limit exceeded or derivation fails
     *
     * Security:
     * - Each message key is derived using HKDF
     * - Keys stored in libsodium secure memory (locked, guard-paged)
     * - Chain key is advanced for each skipped index
     * - Enforces max_skipped_keys limit to prevent DoS
     */
    Result<Unit, EcliptixProtocolFailure> StoreSkippedMessageKeys(
        std::span<const uint8_t> current_chain_key,
        uint32_t from_index,
        uint32_t to_index);

    /**
     * @brief Try to retrieve a cached message key
     *
     * @param message_index The message index to look up
     * @return Ok(Some(key)) if key found, Ok(None) if not cached, Err on failure
     *
     * Note: Key is removed from cache after retrieval (one-time use)
     */
    Result<std::optional<SecureMemoryHandle>, EcliptixProtocolFailure>
        TryGetSkippedMessageKey(uint32_t message_index);

    /**
     * @brief Check if a message key is cached
     *
     * @param message_index The index to check
     * @return true if key exists in cache
     */
    bool HasSkippedMessageKey(uint32_t message_index) const;

    /**
     * @brief Get count of currently cached keys
     *
     * Useful for monitoring memory usage and diagnostics
     */
    size_t GetSkippedKeyCount() const;

    /**
     * @brief Clean up keys below a minimum index
     *
     * As the receiving window advances, old keys can be purged.
     * This prevents unbounded memory growth.
     *
     * @param min_index_to_keep Minimum index to retain (inclusive)
     */
    void CleanupOldKeys(uint32_t min_index_to_keep);

    /**
     * @brief Clear all cached keys
     *
     * USE WITH CAUTION: Removes all skipped message keys.
     * Any messages relying on these keys will fail to decrypt.
     *
     * Typically used when resetting protocol state.
     */
    void Reset();

    /**
     * @brief Get maximum allowed skipped keys
     */
    uint32_t GetMaxSkippedKeys() const { return max_skipped_keys_; }

private:
    /**
     * @brief Derive a message key from chain key at specific index
     *
     * Uses HKDF with domain separation to derive message key.
     *
     * @param chain_key The chain key to derive from
     * @param message_index The message index for domain separation
     * @return Ok(handle) with message key in secure memory, or Err on failure
     */
    Result<SecureMemoryHandle, EcliptixProtocolFailure> DeriveMessageKey(
        std::span<const uint8_t> chain_key,
        uint32_t message_index);

    /**
     * @brief Advance chain key in-place
     *
     * Uses HKDF to derive next chain key from current one.
     *
     * @param chain_key_buffer Buffer containing chain key (modified in-place)
     * @return Ok(Unit) on success, Err on failure
     */
    Result<Unit, EcliptixProtocolFailure> AdvanceChainKey(
        std::span<uint8_t> chain_key_buffer);

    // Configuration
    uint32_t max_skipped_keys_;

    // Cached skipped message keys (index -> key)
    mutable std::mutex lock_;
    std::unordered_map<uint32_t, SecureMemoryHandle> skipped_message_keys_;
};

} // namespace ecliptix::protocol::security
