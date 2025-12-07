#pragma once

#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"

#include <vector>
#include <cstdint>

namespace ecliptix::protocol::models {

/**
 * @brief X25519 (Curve25519) key material
 *
 * Holds a Diffie-Hellman key exchange key pair:
 * - Secret key: 32 bytes (stored in secure memory)
 * - Public key: 32 bytes
 *
 * Used for key agreement (e.g., identity key, ephemeral keys)
 */
class X25519KeyMaterial {
public:
    /**
     * @brief Construct from secure handle and public key
     *
     * Takes ownership of the secure memory handle.
     *
     * @param secret_key_handle Secure handle containing 32-byte secret key
     * @param public_key 32-byte public key
     */
    X25519KeyMaterial(
        crypto::SecureMemoryHandle secret_key_handle,
        std::vector<uint8_t> public_key);

    // Move-only semantics
    X25519KeyMaterial(X25519KeyMaterial&&) noexcept = default;
    X25519KeyMaterial& operator=(X25519KeyMaterial&&) noexcept = default;

    // Non-copyable
    X25519KeyMaterial(const X25519KeyMaterial&) = delete;
    X25519KeyMaterial& operator=(const X25519KeyMaterial&) = delete;

    /**
     * @brief Get const reference to secret key handle
     */
    [[nodiscard]] const crypto::SecureMemoryHandle& GetSecretKeyHandle() const noexcept {
        return secret_key_handle_;
    }

    /**
     * @brief Get mutable reference to secret key handle
     */
    [[nodiscard]] crypto::SecureMemoryHandle& GetSecretKeyHandle() noexcept {
        return secret_key_handle_;
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
     * @brief Move out the secret key handle (consuming operation)
     */
    [[nodiscard]] crypto::SecureMemoryHandle TakeSecretKeyHandle() && {
        return std::move(secret_key_handle_);
    }

    /**
     * @brief Move out the public key (consuming operation)
     */
    [[nodiscard]] std::vector<uint8_t> TakePublicKey() && {
        return std::move(public_key_);
    }

private:
    crypto::SecureMemoryHandle secret_key_handle_;
    std::vector<uint8_t> public_key_;
};

} // namespace ecliptix::protocol::models
