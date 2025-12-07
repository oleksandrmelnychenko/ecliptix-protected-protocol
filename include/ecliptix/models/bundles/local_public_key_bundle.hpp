#pragma once

#include "ecliptix/models/keys/one_time_pre_key_record.hpp"

#include <vector>
#include <cstdint>
#include <optional>

namespace ecliptix::protocol::models {

/**
 * @brief Bundle of public keys for X3DH key exchange
 *
 * Contains all public key material needed for a peer to initiate
 * a secure session using the X3DH protocol:
 *
 * - Identity key (Ed25519) - For signature verification
 * - Identity key (X25519) - For key agreement
 * - Signed pre-key - With signature proving ownership
 * - One-time pre-keys (optional) - For forward secrecy
 * - Ephemeral key (optional) - For initiator
 *
 * This bundle is sent to peers who want to establish a session.
 */
class LocalPublicKeyBundle {
public:
    /**
     * @brief Construct public key bundle
     *
     * @param ed25519_public Ed25519 identity public key (32 bytes)
     * @param identity_x25519_public X25519 identity public key (32 bytes)
     * @param signed_pre_key_id Signed pre-key identifier
     * @param signed_pre_key_public Signed pre-key public key (32 bytes)
     * @param signed_pre_key_signature Signature of signed pre-key (64 bytes)
     * @param one_time_pre_keys Vector of one-time pre-key records
     * @param ephemeral_x25519_public Optional ephemeral key (for initiator)
     */
    LocalPublicKeyBundle(
        std::vector<uint8_t> ed25519_public,
        std::vector<uint8_t> identity_x25519_public,
        uint32_t signed_pre_key_id,
        std::vector<uint8_t> signed_pre_key_public,
        std::vector<uint8_t> signed_pre_key_signature,
        std::vector<OneTimePreKeyRecord> one_time_pre_keys,
        std::optional<std::vector<uint8_t>> ephemeral_x25519_public = std::nullopt);

    // Copyable and movable
    LocalPublicKeyBundle(const LocalPublicKeyBundle&) = default;
    LocalPublicKeyBundle(LocalPublicKeyBundle&&) noexcept = default;
    LocalPublicKeyBundle& operator=(const LocalPublicKeyBundle&) = default;
    LocalPublicKeyBundle& operator=(LocalPublicKeyBundle&&) noexcept = default;

    ~LocalPublicKeyBundle() = default;

    // ========================================================================
    // Identity Keys
    // ========================================================================

    [[nodiscard]] const std::vector<uint8_t>& GetEd25519Public() const noexcept {
        return ed25519_public_;
    }

    [[nodiscard]] const std::vector<uint8_t>& GetIdentityX25519() const noexcept {
        return identity_x25519_;
    }

    [[nodiscard]] std::vector<uint8_t> GetIdentityX25519Copy() const {
        return identity_x25519_;
    }

    // ========================================================================
    // Signed Pre-Key
    // ========================================================================

    [[nodiscard]] uint32_t GetSignedPreKeyId() const noexcept {
        return signed_pre_key_id_;
    }

    [[nodiscard]] const std::vector<uint8_t>& GetSignedPreKeyPublic() const noexcept {
        return signed_pre_key_public_;
    }

    [[nodiscard]] std::vector<uint8_t> GetSignedPreKeyPublicCopy() const {
        return signed_pre_key_public_;
    }

    [[nodiscard]] const std::vector<uint8_t>& GetSignedPreKeySignature() const noexcept {
        return signed_pre_key_signature_;
    }

    // ========================================================================
    // One-Time Pre-Keys
    // ========================================================================

    [[nodiscard]] const std::vector<OneTimePreKeyRecord>& GetOneTimePreKeys() const noexcept {
        return one_time_pre_keys_;
    }

    [[nodiscard]] size_t GetOneTimePreKeyCount() const noexcept {
        return one_time_pre_keys_.size();
    }

    [[nodiscard]] bool HasOneTimePreKeys() const noexcept {
        return !one_time_pre_keys_.empty();
    }

    // ========================================================================
    // Ephemeral Key
    // ========================================================================

    [[nodiscard]] const std::optional<std::vector<uint8_t>>& GetEphemeralX25519Public() const noexcept {
        return ephemeral_x25519_public_;
    }

    [[nodiscard]] bool HasEphemeralKey() const noexcept {
        return ephemeral_x25519_public_.has_value();
    }

private:
    // Identity keys
    std::vector<uint8_t> ed25519_public_;
    std::vector<uint8_t> identity_x25519_;

    // Signed pre-key
    uint32_t signed_pre_key_id_;
    std::vector<uint8_t> signed_pre_key_public_;
    std::vector<uint8_t> signed_pre_key_signature_;

    // One-time pre-keys
    std::vector<OneTimePreKeyRecord> one_time_pre_keys_;

    // Optional ephemeral key (for initiator)
    std::optional<std::vector<uint8_t>> ephemeral_x25519_public_;
};

} // namespace ecliptix::protocol::models
