#pragma once
#include "ecliptix/core/constants.hpp"
#include <cstdint>
#include <algorithm>
namespace ecliptix::protocol::configuration {
class RatchetConfig {
public:
    static constexpr uint32_t MIN_MESSAGE_COUNT = 1;
    static constexpr uint32_t MAX_MESSAGE_COUNT = 100'000;

    RatchetConfig() noexcept
        : message_count_before_ratchet_(ProtocolConstants::DEFAULT_MESSAGE_COUNT_BEFORE_RATCHET) {}
    explicit RatchetConfig(const uint32_t message_count_before_ratchet) noexcept
        : message_count_before_ratchet_(
            std::clamp(message_count_before_ratchet, MIN_MESSAGE_COUNT, MAX_MESSAGE_COUNT)) {}
    [[nodiscard]] static RatchetConfig Default() noexcept {
        return RatchetConfig(ProtocolConstants::DEFAULT_MESSAGE_COUNT_BEFORE_RATCHET);
    }
    [[nodiscard]] static RatchetConfig HighSecurity() noexcept {
        return RatchetConfig(ProtocolConstants::HIGH_SECURITY_MESSAGE_COUNT_BEFORE_RATCHET);
    }
    [[nodiscard]] static RatchetConfig HighPerformance() noexcept {
        return RatchetConfig(ProtocolConstants::HIGH_PERFORMANCE_MESSAGE_COUNT_BEFORE_RATCHET);
    }
    [[nodiscard]] bool ShouldRatchet(const uint32_t next_message_index, const bool received_new_dh_key) const noexcept {
        const bool periodic_trigger = (next_message_index > ProtocolConstants::ZERO_VALUE) &&
                               (next_message_index % message_count_before_ratchet_ == ProtocolConstants::ZERO_VALUE);
        const bool reactive_trigger = received_new_dh_key;
        return periodic_trigger || reactive_trigger;
    }
    [[nodiscard]] uint32_t GetMessageCountBeforeRatchet() const noexcept {
        return message_count_before_ratchet_;
    }
    [[nodiscard]] bool operator==(const RatchetConfig& other) const noexcept {
        return message_count_before_ratchet_ == other.message_count_before_ratchet_;
    }
    [[nodiscard]] bool operator!=(const RatchetConfig& other) const noexcept {
        return !(*this == other);
    }
private:
    uint32_t message_count_before_ratchet_;
};
} 
