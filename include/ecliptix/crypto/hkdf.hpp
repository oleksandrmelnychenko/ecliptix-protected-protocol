#pragma once

#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"

#include <span>
#include <vector>
#include <cstdint>
#include <optional>

namespace ecliptix::protocol::crypto {

/**
 * @brief HKDF (HMAC-based Key Derivation Function) wrapper
 *
 * Implements RFC 5869 HKDF using SHA-256.
 * Used for deriving cryptographic keys from shared secrets and other key material.
 *
 * HKDF has two phases:
 * 1. Extract: Creates a pseudo-random key (PRK) from input key material
 * 2. Expand: Expands PRK into multiple output keys
 *
 * In most cases, you'll use DeriveKey() which combines both phases.
 */
class Hkdf {
public:
    /**
     * @brief Derive key using HKDF-SHA256
     *
     * Combines Extract and Expand phases into a single operation.
     *
     * @param ikm Input key material (shared secret, master key, etc.)
     * @param output Output buffer to fill with derived key
     * @param salt Optional salt (can be empty for no salt)
     * @param info Optional context/application-specific info
     * @return Ok on success, Err on failure
     */
    static Result<Unit, EcliptixProtocolFailure> DeriveKey(
        std::span<const uint8_t> ikm,
        std::span<uint8_t> output,
        std::span<const uint8_t> salt = {},
        std::span<const uint8_t> info = {});

    /**
     * @brief Derive key and return as vector
     *
     * Convenience method that allocates the output buffer.
     *
     * @param ikm Input key material
     * @param output_size Desired output size in bytes
     * @param salt Optional salt
     * @param info Optional context info
     * @return Ok(derived_key) or Err
     */
    static Result<std::vector<uint8_t>, EcliptixProtocolFailure> DeriveKeyBytes(
        std::span<const uint8_t> ikm,
        size_t output_size,
        std::span<const uint8_t> salt = {},
        std::span<const uint8_t> info = {});

    /**
     * @brief HKDF Extract phase
     *
     * Extracts a fixed-length pseudorandom key from input key material.
     * Output is always 32 bytes (SHA-256 output size).
     *
     * @param ikm Input key material
     * @param salt Salt value (can be empty)
     * @return Ok(prk) where prk is 32 bytes, or Err
     */
    static Result<std::vector<uint8_t>, EcliptixProtocolFailure> Extract(
        std::span<const uint8_t> ikm,
        std::span<const uint8_t> salt = {});

    /**
     * @brief HKDF Expand phase
     *
     * Expands a pseudorandom key into the desired length.
     *
     * @param prk Pseudorandom key from Extract (must be 32 bytes)
     * @param output Output buffer to fill
     * @param info Optional context info
     * @return Ok on success, Err on failure
     */
    static Result<Unit, EcliptixProtocolFailure> Expand(
        std::span<const uint8_t> prk,
        std::span<uint8_t> output,
        std::span<const uint8_t> info = {});

    // Constants
    static constexpr size_t HASH_LEN = 32;  // SHA-256 output size
    static constexpr size_t MAX_OUTPUT_LEN = 255 * HASH_LEN;  // RFC 5869 limit

private:
    Hkdf() = delete;  // Static class
};

} // namespace ecliptix::protocol::crypto
