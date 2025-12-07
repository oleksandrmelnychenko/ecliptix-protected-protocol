#pragma once

#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"

#include <vector>
#include <cstdint>

namespace ecliptix::protocol::models {

/**
 * @brief Ed25519 (EdDSA) key material
 *
 * Holds a signing key pair:
 * - Secret key: 64 bytes (stored in secure memory)
 * - Public key: 32 bytes
 *
 * Used for digital signatures (e.g., signing pre-keys)
 */
class Ed25519KeyMaterial {
public:
    /**
     * @brief Construct from secure handle and public key
     *
     * Takes ownership of the secure memory handle.
     *
     * @param secret_key_handle Secure handle containing 64-byte secret key
     * @param public_key 32-byte public key
     */
    Ed25519KeyMaterial(
        crypto::SecureMemoryHandle secret_key_handle,
        std::vector<uint8_t> public_key);

    // Move-only semantics
    Ed25519KeyMaterial(Ed25519KeyMaterial&&) noexcept = default;
    Ed25519KeyMaterial& operator=(Ed25519KeyMaterial&&) noexcept = default;

    // Non-copyable (contains secure memory)
    Ed25519KeyMaterial(const Ed25519KeyMaterial&) = delete;
    Ed25519KeyMaterial& operator=(const Ed25519KeyMaterial&) = delete;

    /**
     * @brief Get const reference to secret key handle
     */
    [[nodiscard]] const crypto::SecureMemoryHandle& GetSecretKeyHandle() const noexcept {
        return secret_key_handle_;
    }

    /**
     * @brief Get mutable reference to secret key handle
     *
     * USE WITH CAUTION - only for internal operations
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
     *
     * Transfers ownership of the secure memory handle.
     * This object becomes invalid after this call.
     */
    [[nodiscard]] crypto::SecureMemoryHandle TakeSecretKeyHandle() && {
        return std::move(secret_key_handle_);
    }

    /**
     * @brief Move out the public key (consuming operation)
     *
     * Transfers ownership of the public key.
     * This object becomes invalid after this call.
     */
    [[nodiscard]] std::vector<uint8_t> TakePublicKey() && {
        return std::move(public_key_);
    }

private:
    crypto::SecureMemoryHandle secret_key_handle_;
    std::vector<uint8_t> public_key_;
};

} // namespace ecliptix::protocol::models
