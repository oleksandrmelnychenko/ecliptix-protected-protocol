#pragma once

#include "ecliptix/core/result.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/core/failures.hpp"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <span>
#include <chrono>
#include <mutex>
#include <cstdint>
#include <string>

namespace ecliptix::protocol::security {

/**
 * @brief Protects against message replay attacks
 *
 * Implements two-level protection:
 * 1. Nonce deduplication - Prevents exact message replay
 * 2. Message window tracking - Prevents out-of-order replay
 *
 * Thread-safe for concurrent access.
 *
 * Security guarantees:
 * - Nonces are tracked with timestamps for automatic cleanup
 * - Per-chain message windows prevent index reuse
 * - Adaptive window sizing handles burst traffic
 * - Constant-time lookups with hash maps
 */
class ReplayProtection {
public:
    /**
     * @brief Construct replay protection with default settings
     *
     * Default parameters:
     * - Window size: 1000 messages
     * - Cleanup interval: 1 minute
     * - Nonce lifetime: 5 minutes
     */
    ReplayProtection();

    /**
     * @brief Construct with custom parameters
     *
     * @param initial_window_size Initial message window size per chain
     * @param cleanup_interval_minutes How often to cleanup expired nonces
     * @param nonce_lifetime_minutes How long nonces remain valid
     */
    explicit ReplayProtection(
        uint32_t initial_window_size,
        std::chrono::minutes cleanup_interval_minutes,
        std::chrono::minutes nonce_lifetime_minutes);

    // Non-copyable, non-movable (contains mutexes)
    ReplayProtection(const ReplayProtection&) = delete;
    ReplayProtection& operator=(const ReplayProtection&) = delete;
    ReplayProtection(ReplayProtection&&) = delete;
    ReplayProtection& operator=(ReplayProtection&&) = delete;

    ~ReplayProtection() = default;

    /**
     * @brief Check and record a message, preventing replay attacks
     *
     * Validates:
     * 1. Nonce has not been seen before (replay detection)
     * 2. Message index is within acceptable window (ordering validation)
     * 3. Updates tracking state if valid
     *
     * @param nonce The message nonce (must be unique per message)
     * @param message_index The message index within the chain
     * @param chain_index The chain identifier (default 0)
     * @return Ok(Unit) if message is valid and recorded, Err otherwise
     *
     * Thread-safe: Multiple threads can call concurrently
     *
     * Error cases:
     * - Nonce already seen (replay attack detected)
     * - Message index outside valid window (potential replay)
     * - Message index already processed in this chain
     */
    Result<Unit, EcliptixProtocolFailure> CheckAndRecordMessage(
        std::span<const uint8_t> nonce,
        uint64_t message_index,
        uint64_t chain_index = 0);

    /**
     * @brief Remove expired nonces from tracking
     *
     * Call periodically to prevent unbounded memory growth.
     * Automatically called based on cleanup_interval.
     *
     * Thread-safe: Can be called from cleanup thread
     */
    void CleanupExpiredNonces();

    /**
     * @brief Get current window size for a chain
     *
     * @param chain_index The chain to query
     * @return Current window size (may be adaptively increased)
     */
    uint32_t GetWindowSize(uint64_t chain_index = 0) const;

    /**
     * @brief Get number of tracked nonces
     *
     * Useful for monitoring memory usage
     */
    size_t GetTrackedNonceCount() const;

    /**
     * @brief Clear all tracked state
     *
     * USE WITH CAUTION: Resets all replay protection.
     * Only use when reinitializing protocol state.
     */
    void Reset();

private:
    /**
     * @brief Nonce key for tracking processed nonces
     *
     * Combines nonce bytes with chain index for unique identification
     */
    struct NonceKey {
        std::vector<uint8_t> nonce_bytes;
        uint64_t chain_index;

        bool operator==(const NonceKey& other) const {
            return chain_index == other.chain_index &&
                   nonce_bytes == other.nonce_bytes;
        }

        // Hash function for use in unordered_map
        struct Hash {
            size_t operator()(const NonceKey& key) const;
        };
    };

    /**
     * @brief Message window for tracking valid indices per chain
     *
     * Maintains a sliding window of acceptable message indices
     * to detect out-of-order replay attempts.
     */
    struct MessageWindow {
        uint64_t highest_index_seen = 0;
        uint64_t lowest_valid_index = 0;
        uint32_t current_window_size;
        std::unordered_set<uint64_t> processed_indices;

        // Adaptive window sizing
        std::chrono::system_clock::time_point last_adjustment;
        uint32_t messages_since_adjustment = 0;

        explicit MessageWindow(uint32_t window_size)
            : current_window_size(window_size)
            , last_adjustment(std::chrono::system_clock::now()) {}
    };

    /**
     * @brief Check if message index is within valid window for chain
     *
     * @param chain_index The chain to check
     * @param message_index The message index to validate
     * @return Ok if within window, Err if outside or already seen
     */
    Result<Unit, EcliptixProtocolFailure> CheckMessageWindow(
        uint64_t chain_index,
        uint64_t message_index);

    /**
     * @brief Update message window after successful validation
     *
     * @param chain_index The chain to update
     * @param message_index The newly processed message index
     */
    void UpdateMessageWindow(
        uint64_t chain_index,
        uint64_t message_index);

    /**
     * @brief Adjust window size based on traffic patterns
     *
     * Increases window size if seeing many out-of-order messages
     * within the acceptable range.
     *
     * @param window The window to adjust
     */
    void AdjustWindowSize(MessageWindow& window);

    /**
     * @brief Check if cleanup is needed based on last cleanup time
     */
    bool ShouldCleanup() const;

    /**
     * @brief Internal cleanup that assumes lock is already held
     */
    void CleanupExpiredNoncesInternal();

    // Configuration
    uint32_t initial_window_size_;
    std::chrono::minutes cleanup_interval_;
    std::chrono::minutes nonce_lifetime_;

    // Tracking state
    mutable std::mutex lock_;
    std::unordered_map<NonceKey, std::chrono::system_clock::time_point, NonceKey::Hash> processed_nonces_;
    std::unordered_map<uint64_t, MessageWindow> message_windows_;
    std::chrono::system_clock::time_point last_cleanup_;
};

} // namespace ecliptix::protocol::security
