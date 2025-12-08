#pragma once
#include <cstdint>
namespace ecliptix::protocol::enums {
enum class PubKeyExchangeType : uint8_t {
    X3DH = 0,
    SERVER_STREAMING = 1
};
inline const char* ToString(PubKeyExchangeType type) {
    switch (type) {
        case PubKeyExchangeType::X3DH:
            return "X3DH";
        case PubKeyExchangeType::SERVER_STREAMING:
            return "SERVER_STREAMING";
        default:
            return "UNKNOWN";
    }
}
} 
