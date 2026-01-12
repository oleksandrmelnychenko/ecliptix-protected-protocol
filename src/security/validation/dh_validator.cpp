#include "ecliptix/security/validation/dh_validator.hpp"
#include "ecliptix/core/format.hpp"
#include <algorithm>
#include <cstring>
namespace ecliptix::protocol::security {
Result<Unit, EcliptixProtocolFailure> DhValidator::ValidateX25519PublicKey(
    const std::span<const uint8_t> public_key) {
    if (public_key.size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                ecliptix::compat::format(
                    "Invalid X25519 public key size: expected {}, got {}",
                    Constants::X_25519_PUBLIC_KEY_SIZE,
                    public_key.size())
            ));
    }
    if (HasSmallOrder(public_key)) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                "X25519 public key is a small-order point (invalid for DH)"
            ));
    }
    if (!IsValidCurve25519Point(public_key)) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                "X25519 public key is not a valid Curve25519 field element"
            ));
    }
    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}
bool DhValidator::HasSmallOrder(const std::span<const uint8_t> public_key) {
    for (const auto& small_order_point : SMALL_ORDER_POINTS) {
        std::span<const uint8_t> point_span{small_order_point.data(), small_order_point.size()};
        if (ConstantTimeEquals(public_key, point_span)) {
            return true;
        }
    }
    return false;
}
bool DhValidator::IsValidCurve25519Point(const std::span<const uint8_t> public_key) {
    if (public_key.size() != Constants::CURVE_25519_FIELD_ELEMENT_SIZE) {
        return false;
    }
    std::array<uint32_t, Constants::FIELD_256_WORD_COUNT> key_words{};
    std::array<uint32_t, Constants::FIELD_256_WORD_COUNT> prime_words{};
    for (size_t i = 0; i < Constants::FIELD_256_WORD_COUNT; ++i) {
        size_t byte_offset = i * Constants::WORD_SIZE;
        key_words[i] = static_cast<uint32_t>(public_key[byte_offset]) |
                      (static_cast<uint32_t>(public_key[byte_offset + 1]) << 8) |
                      (static_cast<uint32_t>(public_key[byte_offset + 2]) << 16) |
                      (static_cast<uint32_t>(public_key[byte_offset + 3]) << 24);
    }
    for (size_t i = 0; i < Constants::FIELD_256_WORD_COUNT; ++i) {
        size_t byte_offset = i * Constants::WORD_SIZE;
        prime_words[i] = static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset]) |
                        (static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset + 1]) << 8) |
                        (static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset + 2]) << 16) |
                        (static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset + 3]) << 24);
    }
    for (int i = Constants::FIELD_256_WORD_COUNT - 1; i >= 0; --i) {
        if (key_words[i] < prime_words[i]) {
            return true;
        }
        if (key_words[i] > prime_words[i]) {
            return false;
        }
    }
    return false;
}
bool DhValidator::ConstantTimeEquals(
    const std::span<const uint8_t> a,
    const std::span<const uint8_t> b) {
    if (a.size() != b.size()) {
        return false;
    }
    uint8_t diff = ProtocolConstants::ZERO_VALUE;
    for (size_t i = ProtocolConstants::ZERO_VALUE; i < a.size(); ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == ComparisonConstants::EQUAL;
}
} 
