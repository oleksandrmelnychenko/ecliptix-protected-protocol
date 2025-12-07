#pragma once

#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"

#include <vector>
#include <string>
#include <string_view>
#include <span>
#include <cstdint>

namespace ecliptix::protocol::crypto {

/**
 * @brief Derive cryptographic keys from a master key
 *
 * Uses BLAKE2b (via libsodium's crypto_generichash) to derive
 * context-specific keys from a master seed and membership ID.
 *
 * This ensures:
 * - Each user gets unique keys even with the same master seed
 * - Keys are versioned (allows future algorithm upgrades)
 * - Different key types are cryptographically separated
 */
class MasterKeyDerivation {
public:
    /**
     * @brief Derive Ed25519 seed from master key
     *
     * Used to deterministically generate Ed25519 signing keys.
     *
     * @param master_key Master seed material
     * @param membership_id Unique user/membership identifier
     * @return 32-byte seed for Ed25519 key generation
     */
    static std::vector<uint8_t> DeriveEd25519Seed(
        std::span<const uint8_t> master_key,
        std::string_view membership_id);

    /**
     * @brief Derive X25519 seed from master key
     *
     * Used to deterministically generate X25519 key exchange keys.
     *
     * @param master_key Master seed material
     * @param membership_id Unique user/membership identifier
     * @return 32-byte seed for X25519 key generation
     */
    static std::vector<uint8_t> DeriveX25519Seed(
        std::span<const uint8_t> master_key,
        std::string_view membership_id);

    /**
     * @brief Derive signed pre-key seed from master key
     *
     * Used to deterministically generate signed pre-keys.
     * Output includes both a key ID (first 4 bytes) and key material.
     *
     * @param master_key Master seed material
     * @param membership_id Unique user/membership identifier
     * @return 32-byte seed (first 4 bytes = key ID, rest = key material)
     */
    static std::vector<uint8_t> DeriveSignedPreKeySeed(
        std::span<const uint8_t> master_key,
        std::string_view membership_id);

    // Context strings for domain separation
    static constexpr std::string_view ED_25519_CONTEXT = "ecliptix-ed25519-v1";
    static constexpr std::string_view X_25519_CONTEXT = "ecliptix-x25519-v1";
    static constexpr std::string_view SIGNED_PRE_KEY_CONTEXT = "ecliptix-spk-v1";

private:
    static constexpr int KEY_SIZE = 32;
    static constexpr int CURRENT_VERSION = 1;

    /**
     * @brief Internal generic hash function using BLAKE2b
     *
     * @param key Master key (used as BLAKE2b key)
     * @param data Context data (version + context string + membership ID)
     * @param output_size Output size in bytes
     * @return Derived key material
     */
    static std::vector<uint8_t> HashWithGenericHash(
        std::span<const uint8_t> key,
        std::span<const uint8_t> data,
        size_t output_size);

    /**
     * @brief Build context data for key derivation
     *
     * Format: [version (4 bytes)] [context string] [membership ID]
     *
     * @param context Context string for domain separation
     * @param membership_id User identifier
     * @return Combined context data
     */
    static std::vector<uint8_t> BuildContextData(
        std::string_view context,
        std::string_view membership_id);

    MasterKeyDerivation() = delete;  // Static class
};

} // namespace ecliptix::protocol::crypto
