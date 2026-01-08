#pragma once
#include <cstdint>
namespace ecliptix::protocol::enums {
enum class ChainStepType : uint8_t {
    SENDER = 0,
    RECEIVER = 1
};
constexpr const char* ToString(const ChainStepType type) noexcept {
    switch (type) {
        case ChainStepType::SENDER:
            return "SENDER";
        case ChainStepType::RECEIVER:
            return "RECEIVER";
        default:
            return "UNKNOWN";
    }
}
} 
