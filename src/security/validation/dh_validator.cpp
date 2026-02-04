#include "ecliptix/security/validation/dh_validator.hpp"
#include "ecliptix/core/format.hpp"
#include <cstdint>
#include <cstring>

namespace ecliptix::protocol::security {
    Result<Unit, ProtocolFailure> DhValidator::ValidateX25519PublicKey(
        const std::span<const uint8_t> public_key) {
        if (public_key.size() != kX25519PublicKeyBytes) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput(
                    compat::format(
                        "Invalid X25519 public key size: expected {}, got {}",
                        kX25519PublicKeyBytes,
                        public_key.size())
                ));
        }
        if (HasSmallOrder(public_key)) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput(
                    "X25519 public key is a small-order point (invalid for DH)"
                ));
        }
        if (!IsValidCurve25519Point(public_key)) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput(
                    "X25519 public key is not a valid Curve25519 field element"
                ));
        }
        return Result<Unit, ProtocolFailure>::Ok(Unit{});
    }

    bool DhValidator::HasSmallOrder(const std::span<const uint8_t> public_key) {
        for (const auto &small_order_point: SMALL_ORDER_POINTS) {
            if (const std::span point_span{small_order_point.data(), small_order_point.size()}; ConstantTimeEquals(
                public_key, point_span)) {
                return true;
            }
        }
        return false;
    }

    bool DhValidator::IsValidCurve25519Point(const std::span<const uint8_t> public_key) {
        if (public_key.size() != Constants::CURVE_25519_FIELD_ELEMENT_SIZE) {
            return false;
        }
        uint32_t borrow = 0;
        for (size_t i = 0; i < Constants::FIELD_256_WORD_COUNT; ++i) {
            const size_t byte_offset = i * Constants::WORD_SIZE;
            const uint32_t key_word = static_cast<uint32_t>(public_key[byte_offset]) |
                           (static_cast<uint32_t>(public_key[byte_offset + 1]) << 8) |
                           (static_cast<uint32_t>(public_key[byte_offset + 2]) << 16) |
                           (static_cast<uint32_t>(public_key[byte_offset + 3]) << 24);
            const uint32_t prime_word = static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset]) |
                             (static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset + 1]) << 8) |
                             (static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset + 2]) << 16) |
                             (static_cast<uint32_t>(CURVE_25519_PRIME[byte_offset + 3]) << 24);
            const uint64_t diff = static_cast<uint64_t>(key_word) - static_cast<uint64_t>(prime_word) - borrow;
            borrow = static_cast<uint32_t>(diff >> 63);
        }
        return borrow == 1;
    }

    bool DhValidator::ConstantTimeEquals(
        const std::span<const uint8_t> a,
        const std::span<const uint8_t> b) {
        if (a.size() != b.size()) {
            return false;
        }
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= a[i] ^ b[i];
        }
        return diff == ComparisonConstants::EQUAL;
    }
}
