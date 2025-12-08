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
        std::chrono::minutes nonce_lifetime_minutes);
    ReplayProtection(const ReplayProtection&) = delete;
    ReplayProtection& operator=(const ReplayProtection&) = delete;
    ReplayProtection(ReplayProtection&&) = delete;
    ReplayProtection& operator=(ReplayProtection&&) = delete;
    ~ReplayProtection() = default;
    Result<Unit, EcliptixProtocolFailure> CheckAndRecordMessage(
        std::span<const uint8_t> nonce,
        uint64_t message_index,
        uint64_t chain_index = 0);
    void CleanupExpiredNonces();
    uint32_t GetWindowSize(uint64_t chain_index = 0) const;
    size_t GetTrackedNonceCount() const;
    void Reset();
private:
    struct NonceKey {
        std::vector<uint8_t> nonce_bytes;
        uint64_t chain_index;
        bool operator==(const NonceKey& other) const {
            return chain_index == other.chain_index &&
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
        std::chrono::system_clock::time_point last_adjustment;
        uint32_t messages_since_adjustment = 0;
        explicit MessageWindow(uint32_t window_size)
            : current_window_size(window_size)
            , last_adjustment(std::chrono::system_clock::now()) {}
    };
    Result<Unit, EcliptixProtocolFailure> CheckMessageWindow(
        uint64_t chain_index,
        uint64_t message_index);
    void UpdateMessageWindow(
        uint64_t chain_index,
        uint64_t message_index);
    void AdjustWindowSize(MessageWindow& window);
    bool ShouldCleanup() const;
    void CleanupExpiredNoncesInternal();
    uint32_t initial_window_size_;
    std::chrono::minutes cleanup_interval_;
    std::chrono::minutes nonce_lifetime_;
    mutable std::mutex lock_;
    std::unordered_map<NonceKey, std::chrono::system_clock::time_point, NonceKey::Hash> processed_nonces_;
    std::unordered_map<uint64_t, MessageWindow> message_windows_;
    std::chrono::system_clock::time_point last_cleanup_;
};
} 
