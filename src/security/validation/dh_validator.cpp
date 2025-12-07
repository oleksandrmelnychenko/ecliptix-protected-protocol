#include "ecliptix/security/validation/dh_validator.hpp"
#include <algorithm>
#include <cstring>
#include <format>

namespace ecliptix::protocol::security {

Result<Unit, EcliptixProtocolFailure> DhValidator::ValidateX25519PublicKey(
    std::span<const uint8_t> public_key) {

    // Step 1: Validate size
    if (public_key.size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                std::format(
                    "Invalid X25519 public key size: expected {}, got {}",
                    Constants::X_25519_PUBLIC_KEY_SIZE,
                    public_key.size())
            ));
    }

    // Step 2: Check for small-order points
    if (HasSmallOrder(public_key)) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                "X25519 public key is a small-order point (invalid for DH)"
            ));
    }

    // Step 3: Validate field element
    if (!IsValidCurve25519Point(public_key)) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                "X25519 public key is not a valid Curve25519 field element"
            ));
    }

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

bool DhValidator::HasSmallOrder(std::span<const uint8_t> public_key) {
    // Check against all known small-order points using constant-time comparison
    for (const auto& small_order_point : SMALL_ORDER_POINTS) {
        std::span<const uint8_t> point_span{small_order_point.data(), small_order_point.size()};
        if (ConstantTimeEquals(public_key, point_span)) {
            return true;
        }
    }
    return false;
}

bool DhValidator::IsValidCurve25519Point(std::span<const uint8_t> public_key) {
    // Curve25519 field elements must be < prime (2^255 - 19)
    // Compare as 256-bit little-endian integers by comparing 32-bit words

    if (public_key.size() != Constants::CURVE_25519_FIELD_ELEMENT_SIZE) {
        return false;
    }

    // Convert to 32-bit words for comparison (little-endian)
    std::array<uint32_t, Constants::FIELD_256_WORD_COUNT> key_words{};
    std::array<uint32_t, Constants::FIELD_256_WORD_COUNT> prime_words{};

    // Load key bytes into words (little-endian)
    for (size_t i = 0; i < Constants::FIELD_256_WORD_COUNT; ++i) {
        size_t byte_offset = i * Constants::WORD_SIZE;
        key_words[i] = static_cast<uint32_t>(public_key[byte_offset]) |
                      (static_cast<uint32_t>(public_key[byte_offset + 1]) << 8) |
                      (static_cast<uint32_t>(public_key[byte_offset + 2]) << 16) |
                      (static_cast<uint32_t>(public_key[byte_offset + 3]) << 24);
    }

    // Load prime bytes into words (little-endian)
    for (size_t i = 0; i < Constants::FIELD_256_WORD_COUNT; ++i) {
        size_t byte_offset = i * Constants::WORD_SIZE;
        prime_words[i] = static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset]) |
                        (static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset + 1]) << 8) |
                        (static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset + 2]) << 16) |
                        (static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset + 3]) << 24);
    }

    // Compare from most significant word to least (reverse order for little-endian)
    for (int i = Constants::FIELD_256_WORD_COUNT - 1; i >= 0; --i) {
        // Apply field element mask to handle sign bit
        uint32_t masked_key_word = key_words[i] & Constants::FIELD_ELEMENT_MASK;
        uint32_t masked_prime_word = prime_words[i] & Constants::FIELD_ELEMENT_MASK;

        if (masked_key_word < masked_prime_word) {
            return true;  // Key is definitely less than prime
        }
        if (masked_key_word > masked_prime_word) {
            return false;  // Key is definitely greater than prime
        }
        // Equal, continue to next word
    }

    // All words are equal - key equals prime, which is invalid
    return false;
}

bool DhValidator::ConstantTimeEquals(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b) {

    if (a.size() != b.size()) {
        return false;
    }

    // Constant-time comparison using bitwise operations
    // XOR all bytes and accumulate - result will be 0 only if all bytes match
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= a[i] ^ b[i];
    }

    // Return true if diff is 0 (all bytes matched)
    return diff == 0;
}

} // namespace ecliptix::protocol::security
