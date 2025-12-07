#include <catch2/catch_test_macros.hpp>
#include "ecliptix/security/validation/dh_validator.hpp"
#include "ecliptix/core/constants.hpp"
#include <vector>
#include <array>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::security;

TEST_CASE("DhValidator - Valid X25519 public keys", "[dh_validator][security]") {
    SECTION("Valid random public key") {
        // A valid X25519 public key (32 bytes, not small-order, valid field element)
        std::array<uint8_t, 32> valid_key = {
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
            0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
            0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
            0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
        };

        auto result = DhValidator::ValidateX25519PublicKey(valid_key);
        REQUIRE(result.IsOk());
    }

    SECTION("Another valid public key") {
        std::array<uint8_t, 32> valid_key = {
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
            0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
            0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
            0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
        };

        auto result = DhValidator::ValidateX25519PublicKey(valid_key);
        REQUIRE(result.IsOk());
    }
}

TEST_CASE("DhValidator - Invalid key size", "[dh_validator][security]") {
    SECTION("Too short") {
        std::vector<uint8_t> short_key(31, 0x42);
        auto result = DhValidator::ValidateX25519PublicKey(short_key);

        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().type == EcliptixProtocolFailureType::InvalidInput);
        REQUIRE(result.UnwrapErr().message.find("Invalid X25519 public key size") != std::string::npos);
    }

    SECTION("Too long") {
        std::vector<uint8_t> long_key(33, 0x42);
        auto result = DhValidator::ValidateX25519PublicKey(long_key);

        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().type == EcliptixProtocolFailureType::InvalidInput);
    }

    SECTION("Empty") {
        std::vector<uint8_t> empty_key;
        auto result = DhValidator::ValidateX25519PublicKey(empty_key);

        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().type == EcliptixProtocolFailureType::InvalidInput);
    }
}

TEST_CASE("DhValidator - Small-order points detection", "[dh_validator][security]") {
    SECTION("Order 1 point (identity)") {
        std::array<uint8_t, 32> identity = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        auto result = DhValidator::ValidateX25519PublicKey(identity);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("small-order point") != std::string::npos);
    }

    SECTION("Order 2 point") {
        std::array<uint8_t, 32> order2 = {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        auto result = DhValidator::ValidateX25519PublicKey(order2);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("small-order point") != std::string::npos);
    }

    SECTION("Order 4 point (variant 1)") {
        std::array<uint8_t, 32> order4_v1 = {
            0x5F, 0x9C, 0x95, 0xBC, 0xA3, 0x50, 0x8C, 0x24,
            0xB1, 0xD0, 0xB1, 0x55, 0x9C, 0x83, 0xEF, 0x5B,
            0x04, 0x44, 0x5C, 0xC4, 0x58, 0x1C, 0x8E, 0x86,
            0xD8, 0x22, 0x4E, 0xDD, 0xD0, 0x9F, 0x11, 0x57
        };

        auto result = DhValidator::ValidateX25519PublicKey(order4_v1);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("small-order point") != std::string::npos);
    }

    SECTION("Order 4 point (variant 2)") {
        std::array<uint8_t, 32> order4_v2 = {
            0xE0, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE,
            0x16, 0x56, 0xE3, 0xFA, 0xF1, 0x9F, 0xC4, 0x6A,
            0xDA, 0x09, 0x8D, 0xEB, 0x9C, 0x32, 0xB1, 0xFD,
            0x86, 0x62, 0x05, 0x16, 0x5F, 0x49, 0xB8, 0x00
        };

        auto result = DhValidator::ValidateX25519PublicKey(order4_v2);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("small-order point") != std::string::npos);
    }

    SECTION("Order 8 point (variant 1)") {
        std::array<uint8_t, 32> order8_v1 = {
            0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        };

        auto result = DhValidator::ValidateX25519PublicKey(order8_v1);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("small-order point") != std::string::npos);
    }

    SECTION("Order 8 point (variant 2)") {
        std::array<uint8_t, 32> order8_v2 = {
            0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        };

        auto result = DhValidator::ValidateX25519PublicKey(order8_v2);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("small-order point") != std::string::npos);
    }

    SECTION("Order 8 point (variant 3)") {
        std::array<uint8_t, 32> order8_v3 = {
            0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        };

        auto result = DhValidator::ValidateX25519PublicKey(order8_v3);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("small-order point") != std::string::npos);
    }

    SECTION("Order 8 point (variant 4)") {
        std::array<uint8_t, 32> order8_v4 = {
            0xCD, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE,
            0x16, 0x56, 0xE3, 0xFA, 0xF1, 0x9F, 0xC4, 0x6A,
            0xDA, 0x09, 0x8D, 0xEB, 0x9C, 0x32, 0xB1, 0xFD,
            0x86, 0x62, 0x05, 0x16, 0x5F, 0x49, 0xB8, 0x00
        };

        auto result = DhValidator::ValidateX25519PublicKey(order8_v4);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("small-order point") != std::string::npos);
    }
}

TEST_CASE("DhValidator - Invalid field elements", "[dh_validator][security]") {
    SECTION("Field prime (exactly p = 2^255 - 19)") {
        // This is the field prime itself, which is invalid
        std::array<uint8_t, 32> prime = {
            0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        };

        auto result = DhValidator::ValidateX25519PublicKey(prime);
        // Note: This point is also a small-order point (order 8 variant 2),
        // so it will be caught by small-order check first
        REQUIRE(result.IsErr());
    }

    SECTION("Value greater than prime") {
        // All 0xFF bytes is > prime
        std::array<uint8_t, 32> too_large = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };

        auto result = DhValidator::ValidateX25519PublicKey(too_large);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("not a valid Curve25519 field element") != std::string::npos);
    }

    SECTION("Another value greater than prime") {
        // Just slightly larger than prime
        std::array<uint8_t, 32> slightly_too_large = {
            0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        };

        auto result = DhValidator::ValidateX25519PublicKey(slightly_too_large);
        // Note: This is also a small-order point (order 8 variant 3),
        // so it will be caught by small-order check first
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("DhValidator - Edge cases", "[dh_validator][security]") {
    SECTION("Maximum valid field element (p - 1)") {
        // 2^255 - 20 (prime - 1)
        std::array<uint8_t, 32> max_valid = {
            0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        };

        auto result = DhValidator::ValidateX25519PublicKey(max_valid);
        // Note: This is also a small-order point (order 8 variant 1),
        // so it will be rejected
        REQUIRE(result.IsErr());
    }

    SECTION("All zeros except one byte") {
        std::array<uint8_t, 32> single_byte = {};
        single_byte[0] = 0x09; // Curve25519 base point x-coordinate

        auto result = DhValidator::ValidateX25519PublicKey(single_byte);
        REQUIRE(result.IsOk());
    }
}
