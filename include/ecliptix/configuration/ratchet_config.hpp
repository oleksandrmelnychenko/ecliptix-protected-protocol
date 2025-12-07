#pragma once

#include "ecliptix/core/constants.hpp"
#include <cstdint>

namespace ecliptix::protocol::configuration {

/**
 * @brief Configuration for DH ratchet trigger logic
 *
 * Controls when the asymmetric (DH) ratchet should be performed during
 * the Double Ratchet protocol. The DH ratchet provides forward secrecy
 * by generating new ephemeral key pairs and deriving new root keys.
 *
 * **Trigger Conditions**:
 * A DH ratchet is triggered when EITHER:
 * 1. Message count reaches threshold (e.g., every 100 messages)
 * 2. Received a new DH public key from peer
 *
 * **Design Rationale**:
 * - **Periodic ratcheting**: Ensures forward secrecy even in one-way communication
 * - **Reactive ratcheting**: Maintains synchronization when peer initiates ratchet
 * - **Configurable threshold**: Allows tuning performance vs. security trade-off
 *
 * **Performance Considerations**:
 * - DH operations are expensive (~50-100μs per ratchet on modern CPUs)
 * - Higher thresholds = better performance, lower forward secrecy
 * - Lower thresholds = worse performance, better forward secrecy
 *
 * **Recommended Values**:
 * - High-security: 50 messages (more frequent ratcheting)
 * - Balanced: 100 messages (default)
 * - High-performance: 500 messages (less frequent ratcheting)
 *
 * **Usage Example**:
 * ```cpp
 * // Default configuration (100 messages)
 * auto config = RatchetConfig::Default();
 *
 * // Custom configuration (50 messages for high security)
 * auto secure_config = RatchetConfig(50);
 *
 * // Check if ratchet needed
 * uint32_t current_index = 101;
 * bool received_new_key = true;
 * if (config.ShouldRatchet(current_index, received_new_key)) {
 *     PerformDhRatchet();
 * }
 * ```
 */
class RatchetConfig {
public:
    /**
     * @brief Construct with custom message count threshold
     *
     * @param message_count_before_ratchet Number of messages to send before
     *                                      triggering a DH ratchet
     *
     * @note Must be > 0. Recommended range: 50-500
     */
    explicit RatchetConfig(uint32_t message_count_before_ratchet) noexcept
        : message_count_before_ratchet_(message_count_before_ratchet) {}

    /**
     * @brief Default configuration (100 messages before ratchet)
     *
     * @return RatchetConfig with balanced security/performance settings
     */
    [[nodiscard]] static RatchetConfig Default() noexcept {
        return RatchetConfig(ProtocolConstants::DEFAULT_MESSAGE_COUNT_BEFORE_RATCHET);
    }

    /**
     * @brief High-security configuration (50 messages before ratchet)
     *
     * Provides stronger forward secrecy at the cost of more frequent
     * DH operations. Use for high-value communications.
     *
     * @return RatchetConfig optimized for security
     */
    [[nodiscard]] static RatchetConfig HighSecurity() noexcept {
        return RatchetConfig(50);
    }

    /**
     * @brief High-performance configuration (500 messages before ratchet)
     *
     * Reduces overhead from DH operations at the cost of weaker forward
     * secrecy. Use for high-throughput scenarios.
     *
     * @return RatchetConfig optimized for performance
     */
    [[nodiscard]] static RatchetConfig HighPerformance() noexcept {
        return RatchetConfig(500);
    }

    /**
     * @brief Determine if DH ratchet should be performed
     *
     * Checks both trigger conditions:
     * 1. Has the message index reached the threshold?
     * 2. Did we receive a new DH key from the peer?
     *
     * @param next_message_index The index that will be used for the next message
     * @param received_new_dh_key True if peer sent a new DH public key
     *
     * @return True if DH ratchet should be performed, false otherwise
     *
     * **Logic**:
     * ```
     * should_ratchet = (next_message_index % threshold == 0) OR received_new_dh_key
     * ```
     *
     * **Examples**:
     * - next_index=100, threshold=100, no_new_key → TRUE (periodic)
     * - next_index=50, threshold=100, new_key → TRUE (reactive)
     * - next_index=50, threshold=100, no_new_key → FALSE (no trigger)
     */
    [[nodiscard]] bool ShouldRatchet(uint32_t next_message_index, bool received_new_dh_key) const noexcept {
        // Trigger 1: Periodic ratcheting based on message count
        bool periodic_trigger = (next_message_index > 0) &&
                               (next_message_index % message_count_before_ratchet_ == 0);

        // Trigger 2: Reactive ratcheting when peer sends new DH key
        bool reactive_trigger = received_new_dh_key;

        return periodic_trigger || reactive_trigger;
    }

    /**
     * @brief Get the configured message count threshold
     *
     * @return Number of messages before automatic DH ratchet
     */
    [[nodiscard]] uint32_t GetMessageCountBeforeRatchet() const noexcept {
        return message_count_before_ratchet_;
    }

    /**
     * @brief Equality comparison
     */
    [[nodiscard]] bool operator==(const RatchetConfig& other) const noexcept {
        return message_count_before_ratchet_ == other.message_count_before_ratchet_;
    }

    [[nodiscard]] bool operator!=(const RatchetConfig& other) const noexcept {
        return !(*this == other);
    }

private:
    uint32_t message_count_before_ratchet_;  ///< Threshold for periodic DH ratcheting
};

} // namespace ecliptix::protocol::configuration
