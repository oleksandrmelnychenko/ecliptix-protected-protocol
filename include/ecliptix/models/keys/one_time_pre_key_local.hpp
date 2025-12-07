#pragma once

#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/core/constants.hpp"

#include <vector>
#include <cstdint>
#include <span>

namespace ecliptix::protocol::models {

/**
 * @brief One-time pre-key (local) with secret key
 *
 * Represents a single-use pre-key for X3DH key agreement.
 * Contains both the secret key (in secure memory) and public key.
 *
 * One-time pre-keys are:
 * - Generated in batches
 * - Used once and then discarded
 * - Not signed (unlike signed pre-keys)
 * - Optional in X3DH (provides forward secrecy)
 */
class OneTimePreKeyLocal {
public:
    /**
     * @brief Generate a new one-time pre-key
     *
     * Creates a random X25519 key pair for one-time use.
     *
     * @param pre_key_id Unique identifier for this pre-key
     * @return Ok(OneTimePreKeyLocal) or Err on generation failure
     */
    static Result<OneTimePreKeyLocal, EcliptixProtocolFailure> Generate(uint32_t pre_key_id);

    /**
     * @brief Create from existing parts
     *
     * Used when deserializing from storage.
     *
     * @param pre_key_id Pre-key identifier
     * @param private_key_handle Secure handle containing 32-byte private key
     * @param public_key 32-byte public key
     * @return OneTimePreKeyLocal instance
     */
    static OneTimePreKeyLocal CreateFromParts(
        uint32_t pre_key_id,
        crypto::SecureMemoryHandle private_key_handle,
        std::vector<uint8_t> public_key);

    // Move-only semantics
    OneTimePreKeyLocal(OneTimePreKeyLocal&&) noexcept = default;
    OneTimePreKeyLocal& operator=(OneTimePreKeyLocal&&) noexcept = default;

    // Non-copyable
    OneTimePreKeyLocal(const OneTimePreKeyLocal&) = delete;
    OneTimePreKeyLocal& operator=(const OneTimePreKeyLocal&) = delete;

    // Destructor
    ~OneTimePreKeyLocal() = default;

    /**
     * @brief Get pre-key ID
     */
    [[nodiscard]] uint32_t GetPreKeyId() const noexcept {
        return pre_key_id_;
    }

    /**
     * @brief Get const reference to private key handle
     */
    [[nodiscard]] const crypto::SecureMemoryHandle& GetPrivateKeyHandle() const noexcept {
        return private_key_handle_;
    }

    /**
     * @brief Get mutable reference to private key handle
     *
     * USE WITH CAUTION - for internal operations only
     */
    [[nodiscard]] crypto::SecureMemoryHandle& GetPrivateKeyHandle() noexcept {
        return private_key_handle_;
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
    // Private constructor - use factory methods
    OneTimePreKeyLocal(
        uint32_t pre_key_id,
        crypto::SecureMemoryHandle private_key_handle,
        std::vector<uint8_t> public_key);

    uint32_t pre_key_id_;
    crypto::SecureMemoryHandle private_key_handle_;
    std::vector<uint8_t> public_key_;
};

} // namespace ecliptix::protocol::models
