#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <vector>
#include <cstdint>
#include <span>
namespace ecliptix::protocol::crypto {
using protocol::Result;
using protocol::EcliptixProtocolFailure;

/**
 * AES-256-GCM Authenticated Encryption with Associated Data (AEAD)
 *
 * ⚠️ SECURITY CRITICAL: NONCE UNIQUENESS REQUIREMENT ⚠️
 *
 * The caller MUST ensure that the nonce is UNIQUE for each encryption
 * operation with the same key. Reusing a (key, nonce) pair catastrophically
 * breaks GCM security:
 *
 * 1. CONFIDENTIALITY BREACH: Attackers can XOR two ciphertexts encrypted
 *    with the same (key, nonce) to recover plaintext relationships
 *
 * 2. AUTHENTICATION BYPASS: GCM authentication tags become predictable,
 *    allowing tag forgery and message tampering
 *
 * 3. KEY RECOVERY: With 2+ reused nonces, the GCM authentication key H
 *    can be algebraically recovered, completely compromising the key
 *
 * NIST SP 800-38D mandates: "The total number of invocations of the
 * authenticated encryption function shall not exceed 2^32 for a given key."
 *
 * HOW THIS LIBRARY PREVENTS NONCE REUSE:
 * ========================================
 *
 * This crypto layer provides NO nonce management - it is a stateless
 * primitive. Nonce uniqueness is enforced by the protocol layer
 * (EcliptixProtocolConnection) through:
 *
 * 1. ATOMIC COUNTER: 64-bit atomic counter (2^64 messages before wraparound)
 * 2. RANDOM PREFIX: 4 bytes of cryptographic randomness per nonce
 * 3. OVERFLOW PROTECTION: Mandatory key rotation at 95% of counter max
 * 4. DOUBLE RATCHET: Periodic DH ratchet steps generate fresh keys,
 *    resetting nonce counters (configurable: every 50-500 messages)
 *
 * Structure of protocol-layer nonce (12 bytes):
 *   [0..7]   = RANDOM_PREFIX (8 bytes from libsodium CSPRNG, 64-bit entropy)
 *   [8..11]  = COUNTER (4 bytes, little-endian uint32_t)
 *
 * The combination of random prefix + monotonic counter + periodic key
 * rotation provides defense-in-depth against nonce reuse across:
 * - Process restarts (random prefix)
 * - Clock resets (counter persistence not required)
 * - Long-lived sessions (mandatory ratchet)
 *
 * CALLER RESPONSIBILITIES:
 * ========================
 *
 * ❌ DO NOT call Encrypt() with the same (key, nonce) twice
 * ❌ DO NOT use random-only nonces (birthday paradox at ~2^48 messages)
 * ❌ DO NOT implement custom nonce generation without cryptographic review
 *
 * ✅ DO use EcliptixProtocolConnection's managed encryption
 * ✅ DO enforce key rotation before 2^32 messages (protocol does this)
 * ✅ DO use the Double Ratchet for forward secrecy and key freshness
 *
 * TESTING NOTE:
 * =============
 *
 * This class intentionally does NOT detect or prevent nonce reuse at the
 * crypto layer - doing so would require statefulness incompatible with a
 * pure cryptographic primitive. Nonce reuse tests exist at the protocol
 * layer (test_connection.cpp) where state management occurs.
 */
class AesGcm {
public:
    [[nodiscard]] static Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    Encrypt(
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> associated_data = {});
    [[nodiscard]] static Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    Decrypt(
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> ciphertext_with_tag,
        std::span<const uint8_t> associated_data = {});
private:
    AesGcm() = delete;
};
} 
