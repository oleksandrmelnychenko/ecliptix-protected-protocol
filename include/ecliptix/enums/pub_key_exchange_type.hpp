#pragma once

#include <cstdint>

namespace ecliptix::protocol::enums {

/**
 * @brief Type of public key exchange protocol used
 *
 * Determines the key agreement mechanism for establishing shared secrets.
 */
enum class PubKeyExchangeType : uint8_t {
    /**
     * @brief Extended Triple Diffie-Hellman (X3DH)
     *
     * Signal Protocol's standard key agreement:
     * - 4 DH operations for forward secrecy
     * - Identity, prekey, and ephemeral keys
     * - Asynchronous (recipient offline during initiation)
     */
    X3DH = 0,

    /**
     * @brief Server streaming mode
     *
     * Simplified key agreement for server-to-client streaming:
     * - Reduced key material requirements
     * - Optimized for one-way communication
     */
    SERVER_STREAMING = 1
};

/**
 * @brief Convert enum to string for debugging/logging
 */
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

} // namespace ecliptix::protocol::enums
