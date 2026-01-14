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
class ReplayProtection {
public:
    ReplayProtection();
    explicit ReplayProtection(
        uint32_t initial_window_size,
        std::chrono::minutes cleanup_interval_minutes,
        std::chrono::minutes nonce_lifetime_minutes,
        size_t max_tracked_nonces = ProtocolConstants::MAX_REPLAY_TRACKED_NONCES,
        size_t max_tracked_chains = ProtocolConstants::MAX_REPLAY_CHAINS,
        uint32_t session_scope = 0);
    explicit ReplayProtection(uint32_t session_scope);
    ReplayProtection(const ReplayProtection&) = delete;
    ReplayProtection& operator=(const ReplayProtection&) = delete;
    ReplayProtection(ReplayProtection&&) = delete;
    ReplayProtection& operator=(ReplayProtection&&) = delete;
    ~ReplayProtection() = default;
    Result<Unit, ProtocolFailure> CheckAndRecordMessage(
        std::span<const uint8_t> nonce,
        uint64_t message_index,
        uint64_t chain_index = 0);
    void CleanupExpiredNonces();
    uint32_t GetWindowSize(uint64_t chain_index = 0) const;
    size_t GetTrackedNonceCount() const;
    void Reset();
    void ResetMessageWindows();
private:
    struct NonceKey {
        std::vector<uint8_t> nonce_bytes;
        uint32_t session_scope;
        uint64_t chain_index;
        bool operator==(const NonceKey& other) const {
            return session_scope == other.session_scope &&
                   chain_index == other.chain_index &&
                   nonce_bytes == other.nonce_bytes;
        }
        struct Hash {
            size_t operator()(const NonceKey& key) const;
        };
    };
    struct MessageWindow {
        uint64_t highest_index_seen = 0;
        uint64_t lowest_valid_index = 0;
        uint32_t current_window_size;
        std::unordered_set<uint64_t> processed_indices;
        std::chrono::steady_clock::time_point last_adjustment;
        std::chrono::steady_clock::time_point last_used;
        uint32_t messages_since_adjustment = 0;
        explicit MessageWindow(const uint32_t window_size)
            : current_window_size(window_size)
            , last_adjustment(std::chrono::steady_clock::now())
            , last_used(std::chrono::steady_clock::now()) {}
    };
    bool ValidateInput(std::span<const uint8_t> nonce, uint64_t chain_index) const;
    Result<Unit, ProtocolFailure> CheckMessageWindow(
        uint64_t chain_index,
        uint64_t message_index);
    void UpdateMessageWindow(
        uint64_t chain_index,
        uint64_t message_index);
    void AdjustWindowSize(MessageWindow& window) const;
    bool ShouldCleanup() const;
    void CleanupExpiredNoncesInternal();
    void EvictOldestNonce();
    void EvictOldestChainWindow();
    uint32_t initial_window_size_;
    uint32_t session_scope_;
    size_t max_tracked_nonces_;
    size_t max_tracked_chains_;
    std::chrono::minutes cleanup_interval_;
    std::chrono::minutes nonce_lifetime_;
    mutable std::mutex lock_;
    std::unordered_map<NonceKey, std::chrono::steady_clock::time_point, NonceKey::Hash> processed_nonces_;
    std::unordered_map<uint64_t, MessageWindow> message_windows_;
    std::chrono::steady_clock::time_point last_cleanup_;
};
} 
