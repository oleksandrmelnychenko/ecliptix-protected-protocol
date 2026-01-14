#pragma once
#include <cstdint>
namespace ecliptix::protocol::enums {
enum class KeyExchangeType : uint8_t {
    X3DH = 0,
    ServerStreaming = 1
};
inline const char* ToString(const KeyExchangeType type) {
    switch (type) {
        case KeyExchangeType::X3DH:
            return "X3DH";
        case KeyExchangeType::ServerStreaming:
            return "ServerStreaming";
        default:
            return "UNKNOWN";
    }
}
} 
