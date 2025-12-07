#pragma once

#include <cstdint>

namespace ecliptix::protocol::enums {

/**
 * @brief Type of chain step in the Double Ratchet protocol
 *
 * Each connection maintains two independent ratchet chains:
 * - SENDER: For encrypting outgoing messages
 * - RECEIVER: For decrypting incoming messages
 *
 * **Design Rationale**:
 * Separating sending and receiving chains provides:
 * 1. **Forward Secrecy**: Compromise of one chain doesn't affect the other
 * 2. **Bidirectional Communication**: Both parties can send simultaneously
 * 3. **Independent State**: Each chain has its own index and key material
 */
enum class ChainStepType : uint8_t {
    /**
     * @brief Sending chain - used for encrypting outgoing messages
     *
     * State maintained:
     * - Current chain key (for deriving message keys)
     * - Current index (monotonically increasing)
     * - Current DH private key (for DH ratchet)
     * - Current DH public key (sent with messages)
     * - Cached message keys (for retransmission)
     */
    SENDER = 0,

    /**
     * @brief Receiving chain - used for decrypting incoming messages
     *
     * State maintained:
     * - Current chain key (for deriving message keys)
     * - Current index (tracks peer's sending index)
     * - Peer's DH public key (for DH ratchet)
     * - Cached message keys (for out-of-order delivery)
     */
    RECEIVER = 1
};

/**
 * @brief Convert ChainStepType to string for logging/debugging
 */
constexpr const char* ToString(ChainStepType type) noexcept {
    switch (type) {
        case ChainStepType::SENDER:
            return "SENDER";
        case ChainStepType::RECEIVER:
            return "RECEIVER";
        default:
            return "UNKNOWN";
    }
}

} // namespace ecliptix::protocol::enums
