#include "ecliptix/security/ratcheting/replay_protection.hpp"
#include <algorithm>
#include <functional>

namespace ecliptix::protocol::security {

// NonceKey::Hash implementation
size_t ReplayProtection::NonceKey::Hash::operator()(const NonceKey& key) const {
    // Combine nonce bytes and chain_index into single hash
    size_t hash = std::hash<uint64_t>{}(key.chain_index);

    // Hash nonce bytes (simple FNV-1a hash)
    for (uint8_t byte : key.nonce_bytes) {
        hash ^= static_cast<size_t>(byte);
        hash *= 0x100000001b3; // FNV prime
    }

    return hash;
}

// Constructors
ReplayProtection::ReplayProtection()
    : ReplayProtection(
        ProtocolConstants::DEFAULT_CACHE_WINDOW_SIZE,
        ProtocolConstants::CLEANUP_INTERVAL,
        ProtocolConstants::NONCE_LIFETIME)
{
}

ReplayProtection::ReplayProtection(
    uint32_t initial_window_size,
    std::chrono::minutes cleanup_interval_minutes,
    std::chrono::minutes nonce_lifetime_minutes)
    : initial_window_size_(initial_window_size)
    , cleanup_interval_(cleanup_interval_minutes)
    , nonce_lifetime_(nonce_lifetime_minutes)
    , last_cleanup_(std::chrono::system_clock::now())
{
}

Result<Unit, EcliptixProtocolFailure> ReplayProtection::CheckAndRecordMessage(
    std::span<const uint8_t> nonce,
    uint64_t message_index,
    uint64_t chain_index) {

    std::lock_guard<std::mutex> guard(lock_);

    // Create nonce key
    NonceKey nonce_key{
        .nonce_bytes = std::vector<uint8_t>(nonce.begin(), nonce.end()),
        .chain_index = chain_index
    };

    // Check 1: Nonce deduplication
    auto nonce_it = processed_nonces_.find(nonce_key);
    if (nonce_it != processed_nonces_.end()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                "Replay attack detected: nonce already processed"));
    }

    // Check 2: Message window validation
    auto window_result = CheckMessageWindow(chain_index, message_index);
    if (window_result.IsErr()) {
        return window_result;
    }

    // Record nonce with current timestamp
    auto now = std::chrono::system_clock::now();
    processed_nonces_[nonce_key] = now;

    // Update message window
    UpdateMessageWindow(chain_index, message_index);

    // Cleanup if needed (internal version that doesn't re-lock)
    if (ShouldCleanup()) {
        last_cleanup_ = now;
        CleanupExpiredNoncesInternal();
    }

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

Result<Unit, EcliptixProtocolFailure> ReplayProtection::CheckMessageWindow(
    uint64_t chain_index,
    uint64_t message_index) {

    // Get or create message window for this chain
    auto window_it = message_windows_.find(chain_index);

    if (window_it == message_windows_.end()) {
        // First message on this chain - always valid
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    MessageWindow& window = window_it->second;

    // Check if message is too old (below window)
    if (message_index < window.lowest_valid_index) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                "Message index too old (below valid window)"));
    }

    // Check if message is within window and already processed
    if (window.processed_indices.count(message_index) > 0) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                "Message index already processed in this chain"));
    }

    // Check if message is too far ahead (potential attack or clock skew)
    uint64_t max_valid_index = window.highest_index_seen + window.current_window_size;
    if (message_index > max_valid_index) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                "Message index too far ahead of current window"));
    }

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

void ReplayProtection::UpdateMessageWindow(
    uint64_t chain_index,
    uint64_t message_index) {

    // Get or create window
    auto [window_it, created] = message_windows_.try_emplace(
        chain_index,
        MessageWindow(initial_window_size_));

    MessageWindow& window = window_it->second;

    // Update highest index seen
    if (message_index > window.highest_index_seen) {
        window.highest_index_seen = message_index;

        // Slide window forward
        uint64_t new_lowest = 0;
        if (window.highest_index_seen > window.current_window_size) {
            new_lowest = window.highest_index_seen - window.current_window_size;
        }

        // Remove indices that are now below the window
        if (new_lowest > window.lowest_valid_index) {
            auto it = window.processed_indices.begin();
            while (it != window.processed_indices.end()) {
                if (*it < new_lowest) {
                    it = window.processed_indices.erase(it);
                } else {
                    ++it;
                }
            }
            window.lowest_valid_index = new_lowest;
        }
    }

    // Record this index as processed
    window.processed_indices.insert(message_index);

    // Adaptive window sizing
    window.messages_since_adjustment++;
    if (window.messages_since_adjustment >= ProtocolConstants::CLEANUP_THRESHOLD) {
        AdjustWindowSize(window);
        window.messages_since_adjustment = 0;
    }
}

void ReplayProtection::AdjustWindowSize(MessageWindow& window) {
    auto now = std::chrono::system_clock::now();
    auto time_since_last = std::chrono::duration_cast<std::chrono::minutes>(
        now - window.last_adjustment);

    // Only adjust if enough time has passed
    if (time_since_last < ProtocolConstants::WINDOW_ADJUSTMENT_INTERVAL) {
        return;
    }

    // Calculate out-of-order ratio
    size_t total_tracked = window.processed_indices.size();
    if (total_tracked > 0) {
        // If we're tracking many indices (indicating lots of out-of-order),
        // increase window size
        double fill_ratio = static_cast<double>(total_tracked) /
                          static_cast<double>(window.current_window_size);

        if (fill_ratio > 0.75) {
            // Increase window by 50% (capped at max)
            uint32_t new_size = window.current_window_size +
                              (window.current_window_size / 2);
            window.current_window_size = std::min(
                new_size,
                ProtocolConstants::MESSAGE_KEY_CACHE_WINDOW);
        } else if (fill_ratio < 0.25 &&
                   window.current_window_size > initial_window_size_) {
            // Decrease window back towards initial size
            uint32_t new_size = window.current_window_size -
                              (window.current_window_size / 4);
            window.current_window_size = std::max(
                new_size,
                initial_window_size_);
        }
    }

    window.last_adjustment = now;
}

void ReplayProtection::CleanupExpiredNonces() {
    std::lock_guard<std::mutex> guard(lock_);
    CleanupExpiredNoncesInternal();
}

void ReplayProtection::CleanupExpiredNoncesInternal() {
    // NOTE: Assumes lock is already held by caller

    auto now = std::chrono::system_clock::now();
    auto expiry_threshold = now - nonce_lifetime_;

    // Remove expired nonces
    auto it = processed_nonces_.begin();
    while (it != processed_nonces_.end()) {
        if (it->second < expiry_threshold) {
            it = processed_nonces_.erase(it);
        } else {
            ++it;
        }
    }
}

bool ReplayProtection::ShouldCleanup() const {
    auto now = std::chrono::system_clock::now();
    auto time_since_cleanup = std::chrono::duration_cast<std::chrono::minutes>(
        now - last_cleanup_);

    return time_since_cleanup >= cleanup_interval_;
}

uint32_t ReplayProtection::GetWindowSize(uint64_t chain_index) const {
    std::lock_guard<std::mutex> guard(lock_);

    auto it = message_windows_.find(chain_index);
    if (it != message_windows_.end()) {
        return it->second.current_window_size;
    }

    return initial_window_size_;
}

size_t ReplayProtection::GetTrackedNonceCount() const {
    std::lock_guard<std::mutex> guard(lock_);
    return processed_nonces_.size();
}

void ReplayProtection::Reset() {
    std::lock_guard<std::mutex> guard(lock_);

    processed_nonces_.clear();
    message_windows_.clear();
    last_cleanup_ = std::chrono::system_clock::now();
}

} // namespace ecliptix::protocol::security
