#pragma once

#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"

#include <vector>
#include <cstdint>

namespace ecliptix::protocol::models {

/**
 * @brief Signed pre-key material
 *
 * Holds a signed X25519 key pair used in X3DH:
 * - Key ID: uint32_t identifier
 * - Secret key: 32 bytes (stored in secure memory)
 * - Public key: 32 bytes
 * - Signature: 64 bytes (Ed25519 signature of public key)
 *
 * The signature proves that the pre-key was created by the identity key owner.
 */
class SignedPreKeyMaterial {
public:
    /**
     * @brief Construct signed pre-key material
     *
     * @param id Unique pre-key identifier
     * @param secret_key_handle Secure handle containing 32-byte secret key
     * @param public_key 32-byte public key
     * @param signature 64-byte Ed25519 signature of public key
     */
    SignedPreKeyMaterial(
        uint32_t id,
        crypto::SecureMemoryHandle secret_key_handle,
        std::vector<uint8_t> public_key,
        std::vector<uint8_t> signature);

    // Move-only semantics
    SignedPreKeyMaterial(SignedPreKeyMaterial&&) noexcept = default;
    SignedPreKeyMaterial& operator=(SignedPreKeyMaterial&&) noexcept = default;

    // Non-copyable
    SignedPreKeyMaterial(const SignedPreKeyMaterial&) = delete;
    SignedPreKeyMaterial& operator=(const SignedPreKeyMaterial&) = delete;

    /**
     * @brief Get pre-key ID
     */
    [[nodiscard]] uint32_t GetId() const noexcept {
        return id_;
    }

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
     * @brief Get copy of signature
     */
    [[nodiscard]] std::vector<uint8_t> GetSignatureCopy() const {
        return signature_;
    }

    /**
     * @brief Get const reference to signature
     */
    [[nodiscard]] const std::vector<uint8_t>& GetSignature() const noexcept {
        return signature_;
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

    /**
     * @brief Move out the signature (consuming operation)
     */
    [[nodiscard]] std::vector<uint8_t> TakeSignature() && {
        return std::move(signature_);
    }

private:
    uint32_t id_;
    crypto::SecureMemoryHandle secret_key_handle_;
    std::vector<uint8_t> public_key_;
    std::vector<uint8_t> signature_;
};

} // namespace ecliptix::protocol::models
