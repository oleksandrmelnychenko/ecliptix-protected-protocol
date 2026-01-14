#pragma once
#include <cstdint>
namespace ecliptix::protocol::enums {
enum class ChainStepType : uint8_t {
    Sender = 0,
    Receiver = 1
};
constexpr const char* ToString(const ChainStepType type) noexcept {
    switch (type) {
        case ChainStepType::Sender:
            return "SENDER";
        case ChainStepType::Receiver:
            return "RECEIVER";
        default:
            return "UNKNOWN";
    }
}
} 
