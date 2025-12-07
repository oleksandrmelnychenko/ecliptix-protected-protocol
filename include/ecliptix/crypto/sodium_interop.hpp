#pragma once

#include "ecliptix/core/result.hpp"
#include "ecliptix/core/option.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/core/constants.hpp"

#include <sodium.h>
#include <span>
#include <cstddef>
#include <memory>

namespace ecliptix::protocol::crypto {

// Forward declaration
class SecureMemoryHandle;

/**
 * @brief Interop layer for libsodium cryptographic operations
 *
 * Provides RAII wrappers and safe interfaces to libsodium functionality.
 * All methods ensure proper error handling and secure memory management.
 */
class SodiumInterop {
public:
    // ========================================================================
    // Initialization
    // ========================================================================

    /**
     * @brief Initialize libsodium library
     *
     * Must be called before any other sodium operations.
     * Thread-safe and idempotent.
     *
     * @return Ok if initialization succeeded, Err otherwise
     */
    static Result<Unit, SodiumFailure> Initialize();

    /**
     * @brief Check if libsodium is initialized
     */
    static bool IsInitialized() noexcept;

    // ========================================================================
    // Secure Memory Operations
    // ========================================================================

    /**
     * @brief Securely wipe a buffer
     *
     * Uses sodium_memzero for large buffers (pinned memory)
     * Uses std::fill + volatile for small buffers
     *
     * @param buffer Buffer to wipe
     * @return Ok on success, Err on failure
     */
    static Result<Unit, SodiumFailure> SecureWipe(std::span<uint8_t> buffer);

    /**
     * @brief Securely wipe a buffer (overload for const span)
     *
     * Needed because we often need to wipe temporaries
     */
    static Result<Unit, SodiumFailure> SecureWipe(std::span<const uint8_t> buffer);

    /**
     * @brief Constant-time comparison of two buffers
     *
     * CRITICAL: Always use for cryptographic comparisons to prevent timing attacks
     *
     * @param a First buffer
     * @param b Second buffer
     * @return Ok(true) if equal, Ok(false) if different, Err on failure
     */
    static Result<bool, SodiumFailure> ConstantTimeEquals(
        std::span<const uint8_t> a,
        std::span<const uint8_t> b);

    // ========================================================================
    // Key Generation
    // ========================================================================

    /**
     * @brief Generate X25519 (Curve25519) key pair
     *
     * Creates a new keypair for Diffie-Hellman key exchange.
     * Secret key is stored in secure memory (SecureMemoryHandle)
     *
     * @param key_purpose Description for error messages
     * @return Ok((SecureMemoryHandle, public_key_bytes)) or Err
     */
    static Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>, EcliptixProtocolFailure>
    GenerateX25519KeyPair(std::string_view key_purpose);

    /**
     * @brief Generate Ed25519 (EdDSA) key pair
     *
     * Creates a new keypair for digital signatures
     *
     * @return Ok((secret_key, public_key)) or Err
     */
    static Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, EcliptixProtocolFailure>
    GenerateEd25519KeyPair();

    // ========================================================================
    // Random Number Generation
    // ========================================================================

    /**
     * @brief Generate cryptographically secure random bytes
     *
     * @param size Number of bytes to generate
     * @return Vector of random bytes
     */
    static std::vector<uint8_t> GetRandomBytes(size_t size);

    /**
     * @brief Generate random uint32_t
     *
     * @param ensure_non_zero If true, guarantees result != 0
     * @return Random uint32_t value
     */
    static uint32_t GenerateRandomUInt32(bool ensure_non_zero = false);

    // ========================================================================
    // Memory Allocation (Internal)
    // ========================================================================

    /**
     * @brief Allocate secure memory using sodium_malloc
     *
     * Memory is:
     * - Guard-paged (inaccessible pages before/after)
     * - Protected from swap
     * - Locked in RAM
     * - Automatically zeroed on free
     *
     * @param size Size in bytes
     * @return Pointer to secure memory, or nullptr on failure
     */
    static void* AllocateSecure(size_t size) noexcept;

    /**
     * @brief Free secure memory allocated by AllocateSecure
     *
     * @param ptr Pointer returned by AllocateSecure
     */
    static void FreeSecure(void* ptr) noexcept;

    // ========================================================================
    // Constants
    // ========================================================================

    static constexpr size_t MAX_BUFFER_SIZE = 1'000'000'000;  // 1 GB limit

private:
    // Initialization state
    static inline std::atomic<bool> initialized_{false};
    static inline std::once_flag init_flag_;

    // Internal helpers
    static Result<Unit, SodiumFailure> WipeSmallBuffer(std::span<uint8_t> buffer);
    static Result<Unit, SodiumFailure> WipeLargeBuffer(std::span<uint8_t> buffer);

    // Not instantiable
    SodiumInterop() = delete;
    ~SodiumInterop() = delete;
    SodiumInterop(const SodiumInterop&) = delete;
    SodiumInterop& operator=(const SodiumInterop&) = delete;
};

} // namespace ecliptix::protocol::crypto
