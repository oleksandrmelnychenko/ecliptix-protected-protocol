#pragma once

#include <vector>
#include <cstdint>
#include <span>

namespace ecliptix::protocol::models {

/**
 * @brief One-time pre-key record (public only)
 *
 * Contains only the public portion of a one-time pre-key.
 * Used for:
 * - Public key bundles sent to peers
 * - Serialization/network transmission
 * - Storage of peer's pre-keys
 *
 * Does NOT contain the secret key.
 */
class OneTimePreKeyRecord {
public:
    /**
     * @brief Construct from ID and public key
     *
     * @param pre_key_id Unique identifier
     * @param public_key 32-byte X25519 public key
     */
    OneTimePreKeyRecord(uint32_t pre_key_id, std::vector<uint8_t> public_key);

    // Copyable and movable
    OneTimePreKeyRecord(const OneTimePreKeyRecord&) = default;
    OneTimePreKeyRecord(OneTimePreKeyRecord&&) noexcept = default;
    OneTimePreKeyRecord& operator=(const OneTimePreKeyRecord&) = default;
    OneTimePreKeyRecord& operator=(OneTimePreKeyRecord&&) noexcept = default;

    ~OneTimePreKeyRecord() = default;

    /**
     * @brief Get pre-key ID
     */
    [[nodiscard]] uint32_t GetPreKeyId() const noexcept {
        return pre_key_id_;
    }

    /**
     * @brief Get copy of public key
     */
    [[nodiscard]] std::vector<uint8_t> GetPublicKeyCopy() const {
        return public_key_;
    }

    /**
     * @brief Get const reference to public key
     */
    [[nodiscard]] const std::vector<uint8_t>& GetPublicKey() const noexcept {
        return public_key_;
    }

    /**
     * @brief Get span view of public key
     */
    [[nodiscard]] std::span<const uint8_t> GetPublicKeySpan() const noexcept {
        return std::span<const uint8_t>(public_key_);
    }

private:
    uint32_t pre_key_id_;
    std::vector<uint8_t> public_key_;
};

} // namespace ecliptix::protocol::models
