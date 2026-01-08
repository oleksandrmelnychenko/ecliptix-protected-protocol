#include "ecliptix/security/ratcheting/replay_protection.hpp"
#include <algorithm>
#include <functional>

namespace ecliptix::protocol::security {
    size_t ReplayProtection::NonceKey::Hash::operator()(const NonceKey &key) const {
        size_t hash = std::hash<uint32_t>{}(key.session_scope);
        hash ^= std::hash<uint64_t>{}(key.chain_index) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        for (const uint8_t byte: key.nonce_bytes) {
            hash ^= static_cast<size_t>(byte);
            hash *= CryptoHashConstants::FNV_PRIME;
        }
        return hash;
    }

    ReplayProtection::ReplayProtection()
        : ReplayProtection(
            ProtocolConstants::DEFAULT_CACHE_WINDOW_SIZE,
            ProtocolConstants::CLEANUP_INTERVAL,
            ProtocolConstants::NONCE_LIFETIME,
            ProtocolConstants::MAX_REPLAY_TRACKED_NONCES,
            ProtocolConstants::MAX_REPLAY_CHAINS,
            0) {
    }

    ReplayProtection::ReplayProtection(const uint32_t session_scope)
        : ReplayProtection(
            ProtocolConstants::DEFAULT_CACHE_WINDOW_SIZE,
            ProtocolConstants::CLEANUP_INTERVAL,
            ProtocolConstants::NONCE_LIFETIME,
            ProtocolConstants::MAX_REPLAY_TRACKED_NONCES,
            ProtocolConstants::MAX_REPLAY_CHAINS,
            session_scope) {
    }

    ReplayProtection::ReplayProtection(
        const uint32_t initial_window_size,
        const std::chrono::minutes cleanup_interval_minutes,
        const std::chrono::minutes nonce_lifetime_minutes,
        const size_t max_tracked_nonces,
        const size_t max_tracked_chains,
        const uint32_t session_scope)
        : initial_window_size_(initial_window_size)
          , session_scope_(session_scope)
          , max_tracked_nonces_(max_tracked_nonces)
          , max_tracked_chains_(max_tracked_chains)
          , cleanup_interval_(cleanup_interval_minutes)
          , nonce_lifetime_(nonce_lifetime_minutes)
          , last_cleanup_(std::chrono::steady_clock::now()) {
    }

    Result<Unit, EcliptixProtocolFailure> ReplayProtection::CheckAndRecordMessage(
        std::span<const uint8_t> nonce,
        const uint64_t message_index,
        const uint64_t chain_index) {
        std::lock_guard guard(lock_);
        if (!ValidateInput(nonce, chain_index)) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Invalid nonce or chain index"));
        }
        const NonceKey nonce_key{
            .nonce_bytes = std::vector(nonce.begin(), nonce.end()),
            .session_scope = session_scope_,
            .chain_index = chain_index
        };
        if (processed_nonces_.size() >= max_tracked_nonces_) {
            CleanupExpiredNoncesInternal();
            if (processed_nonces_.size() >= max_tracked_nonces_) {
                EvictOldestNonce();
            }
        }
        if (const auto nonce_it = processed_nonces_.find(nonce_key); nonce_it != processed_nonces_.end()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Replay attack detected: nonce already processed"));
        }
        if (message_windows_.find(chain_index) == message_windows_.end() &&
            message_windows_.size() >= max_tracked_chains_) {
            EvictOldestChainWindow();
        }
        
        
        
        
        if (auto window_result = CheckMessageWindow(chain_index, message_index); window_result.IsErr()) {
            return window_result;
        }
        const auto now = std::chrono::steady_clock::now();
        processed_nonces_[nonce_key] = now;
        UpdateMessageWindow(chain_index, message_index);
        if (ShouldCleanup()) {
            last_cleanup_ = now;
            CleanupExpiredNoncesInternal();
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure> ReplayProtection::CheckMessageWindow(
        const uint64_t chain_index,
        const uint64_t message_index) {
        const auto window_it = message_windows_.find(chain_index);
        if (window_it == message_windows_.end()) {
            return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
        }
        const MessageWindow &window = window_it->second;
        if (message_index < window.lowest_valid_index) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Message index too old (below valid window)"));
        }
        if (window.processed_indices.count(message_index) > ProtocolConstants::ZERO_VALUE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Message index already processed in this chain"));
        }
        const uint64_t max_valid_index = window.highest_index_seen + window.current_window_size;
        if (message_index > max_valid_index) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Message index too far ahead of current window"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    bool ReplayProtection::ValidateInput(const std::span<const uint8_t> nonce, const uint64_t chain_index) const {
        if (nonce.size() != Constants::AES_GCM_NONCE_SIZE) {
            return false;
        }
        if (chain_index >= max_tracked_chains_ * 8ULL) {
            return false;
        }
        return true;
    }

    void ReplayProtection::UpdateMessageWindow(
        const uint64_t chain_index,
        const uint64_t message_index) {
        auto [window_it, created] = message_windows_.try_emplace(
            chain_index,
            MessageWindow(initial_window_size_));
        MessageWindow &window = window_it->second;
        if (message_index > window.highest_index_seen) {
            window.highest_index_seen = message_index;
            uint64_t new_lowest = 0;
            if (window.highest_index_seen > window.current_window_size) {
                new_lowest = window.highest_index_seen - window.current_window_size;
            }
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
        window.processed_indices.insert(message_index);
        window.messages_since_adjustment++;
        window.last_used = std::chrono::steady_clock::now();
        if (window.messages_since_adjustment >= ProtocolConstants::CLEANUP_THRESHOLD) {
            AdjustWindowSize(window);
            window.messages_since_adjustment = 0;
        }
    }

    void ReplayProtection::AdjustWindowSize(MessageWindow &window) const {
        const auto now = std::chrono::steady_clock::now();
        const auto time_since_last = std::chrono::duration_cast<std::chrono::minutes>(
            now - window.last_adjustment);
        if (time_since_last < ProtocolConstants::WINDOW_ADJUSTMENT_INTERVAL) {
            return;
        }
        const size_t total_tracked = window.processed_indices.size();
        if (total_tracked > ProtocolConstants::ZERO_VALUE) {
            const double fill_ratio = static_cast<double>(total_tracked) /
                                      static_cast<double>(window.current_window_size);
            if (fill_ratio > ComparisonConstants::WINDOW_FILL_RATIO_HIGH) {
                const uint32_t new_size = window.current_window_size +
                                          window.current_window_size / 2;
                window.current_window_size = std::min(
                    new_size,
                    ProtocolConstants::MESSAGE_KEY_CACHE_WINDOW);
            } else if (fill_ratio < ComparisonConstants::WINDOW_FILL_RATIO_LOW &&
                       window.current_window_size > initial_window_size_) {
                const uint32_t new_size = window.current_window_size -
                                          window.current_window_size / 4;
                window.current_window_size = std::max(
                    new_size,
                    initial_window_size_);
            }
        }
        window.last_adjustment = now;
    }

    void ReplayProtection::CleanupExpiredNonces() {
        std::lock_guard guard(lock_);
        CleanupExpiredNoncesInternal();
    }

    void ReplayProtection::CleanupExpiredNoncesInternal() {
        const auto now = std::chrono::steady_clock::now();
        const auto expiry_threshold = now - nonce_lifetime_;
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
        const auto now = std::chrono::steady_clock::now();
        const auto time_since_cleanup = std::chrono::duration_cast<std::chrono::minutes>(
            now - last_cleanup_);
        return time_since_cleanup >= cleanup_interval_;
    }

    uint32_t ReplayProtection::GetWindowSize(const uint64_t chain_index) const {
        std::lock_guard guard(lock_);
        const auto it = message_windows_.find(chain_index);
        if (it != message_windows_.end()) {
            return it->second.current_window_size;
        }
        return initial_window_size_;
    }

    size_t ReplayProtection::GetTrackedNonceCount() const {
        std::lock_guard guard(lock_);
        return processed_nonces_.size();
    }

    void ReplayProtection::Reset() {
        std::lock_guard guard(lock_);
        processed_nonces_.clear();
        message_windows_.clear();
        last_cleanup_ = std::chrono::steady_clock::now();
    }

    void ReplayProtection::ResetMessageWindows() {
        std::lock_guard guard(lock_);
        message_windows_.clear();
    }

    void ReplayProtection::EvictOldestNonce() {
        if (processed_nonces_.empty()) {
            return;
        }
        auto oldest_it = processed_nonces_.begin();
        for (auto it = processed_nonces_.begin(); it != processed_nonces_.end(); ++it) {
            if (it->second < oldest_it->second) {
                oldest_it = it;
            }
        }
        processed_nonces_.erase(oldest_it);
    }

    void ReplayProtection::EvictOldestChainWindow() {
        if (message_windows_.empty()) {
            return;
        }
        auto oldest_it = message_windows_.begin();
        for (auto it = message_windows_.begin(); it != message_windows_.end(); ++it) {
            if (it->second.last_used < oldest_it->second.last_used) {
                oldest_it = it;
            }
        }
        const uint64_t evicted_chain = oldest_it->first;
        message_windows_.erase(oldest_it);
        for (auto it = processed_nonces_.begin(); it != processed_nonces_.end();) {
            if (it->first.chain_index == evicted_chain) {
                it = processed_nonces_.erase(it);
            } else {
                ++it;
            }
        }
    }
}
