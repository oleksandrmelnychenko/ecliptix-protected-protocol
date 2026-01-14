#include <catch2/catch_test_macros.hpp>
#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/core/constants.hpp"
#include <sodium.h>
#include <vector>
#include <thread>
#include <array>

using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol;

TEST_CASE("HKDF RFC 5869 Test Vectors", "[security][hkdf][conformance]") {

    SECTION("RFC 5869 Test Case 1 - Basic test case with SHA-256") {
        const std::array<uint8_t, 22> ikm = {
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
        };

        const std::array<uint8_t, 13> salt = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c
        };

        const std::array<uint8_t, 10> info = {
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9
        };

        const std::array<uint8_t, 42> expected_okm = {
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
            0x58, 0x65
        };
        const std::array<uint8_t, 32> expected_prk = {
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
            0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
            0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
            0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
        };

        auto result = Hkdf::DeriveKeyBytes(ikm, 42, salt, info);
        REQUIRE(result.IsOk());

        const auto okm = std::move(result).Unwrap();
        REQUIRE(okm.size() == 42);
        REQUIRE(std::equal(okm.begin(), okm.end(), expected_okm.begin()));

        auto prk_result = Hkdf::Extract(ikm, salt);
        REQUIRE(prk_result.IsOk());
        const auto prk = std::move(prk_result).Unwrap();
        REQUIRE(prk.size() == expected_prk.size());
        REQUIRE(std::equal(prk.begin(), prk.end(), expected_prk.begin()));

        std::vector<uint8_t> expanded_okm(expected_okm.size());
        auto expand_result = Hkdf::Expand(prk, expanded_okm, info);
        REQUIRE(expand_result.IsOk());
        REQUIRE(std::equal(expanded_okm.begin(), expanded_okm.end(), expected_okm.begin()));
    }

    SECTION("RFC 5869 Test Case 2 - Longer inputs and outputs") {
        const std::array<uint8_t, 80> ikm = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
        };

        const std::array<uint8_t, 80> salt = {
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
            0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
            0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
            0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
        };

        const std::array<uint8_t, 80> info = {
            0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
            0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
            0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
            0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
            0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
            0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
            0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
        };

        const std::array<uint8_t, 82> expected_okm = {
            0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
            0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
            0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
            0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
            0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
            0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
            0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
            0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
            0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
            0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
            0x1d, 0x87
        };

        auto result = Hkdf::DeriveKeyBytes(ikm, 82, salt, info);
        REQUIRE(result.IsOk());

        const auto okm = std::move(result).Unwrap();
        REQUIRE(okm.size() == 82);
        REQUIRE(std::equal(okm.begin(), okm.end(), expected_okm.begin()));
    }

    SECTION("RFC 5869 Test Case 3 - Zero-length salt and info") {
        const std::array<uint8_t, 22> ikm = {
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
        };

        const std::array<uint8_t, 42> expected_okm = {
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
            0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
            0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
            0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
            0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
            0x96, 0xc8
        };

        auto result = Hkdf::DeriveKeyBytes(ikm, 42, {}, {});
        REQUIRE(result.IsOk());

        const auto okm = std::move(result).Unwrap();
        REQUIRE(okm.size() == 42);
        REQUIRE(std::equal(okm.begin(), okm.end(), expected_okm.begin()));
    }
}

TEST_CASE("HKDF Weak Input Material Detection", "[security][hkdf][weak-input]") {

    SECTION("Empty IKM must fail") {
        std::vector<uint8_t> empty_ikm;
        std::vector<uint8_t> output(32);

        auto result = Hkdf::DeriveKey(empty_ikm, output);
        REQUIRE(result.IsErr());

        auto err = std::move(result).UnwrapErr();
        REQUIRE(err.type == ProtocolFailureType::InvalidInput);
    }

    SECTION("All-zero IKM should still work but be discouraged") {
        std::vector<uint8_t> weak_ikm(32, 0x00);

        auto result1 = Hkdf::DeriveKeyBytes(weak_ikm, 32);
        REQUIRE(result1.IsOk());

        auto result2 = Hkdf::DeriveKeyBytes(weak_ikm, 32);
        REQUIRE(result2.IsOk());

        const auto output1 = std::move(result1).Unwrap();
        const auto output2 = std::move(result2).Unwrap();

        REQUIRE(std::equal(output1.begin(), output1.end(), output2.begin()));
    }

    SECTION("Low entropy IKM with different salts produces different outputs") {
        std::vector<uint8_t> weak_ikm(32, 0xAA);

        std::vector<uint8_t> salt1(16, 0x01);
        std::vector<uint8_t> salt2(16, 0x02);

        auto result1 = Hkdf::DeriveKeyBytes(weak_ikm, 32, salt1);
        auto result2 = Hkdf::DeriveKeyBytes(weak_ikm, 32, salt2);

        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());

        const auto output1 = std::move(result1).Unwrap();
        const auto output2 = std::move(result2).Unwrap();

        REQUIRE_FALSE(std::equal(output1.begin(), output1.end(), output2.begin()));
    }

    SECTION("Single byte IKM should work") {
        std::vector<uint8_t> minimal_ikm = {0x42};

        auto result = Hkdf::DeriveKeyBytes(minimal_ikm, 32);
        REQUIRE(result.IsOk());

        const auto output = std::move(result).Unwrap();
        REQUIRE(output.size() == 32);
    }
}

TEST_CASE("HKDF Salt Reuse Resistance", "[security][hkdf][salt-reuse]") {

    SECTION("Same salt with different IKM produces different outputs") {
        std::vector<uint8_t> salt(16);
        randombytes_buf(salt.data(), salt.size());

        std::vector<uint8_t> ikm1(32);
        std::vector<uint8_t> ikm2(32);
        randombytes_buf(ikm1.data(), ikm1.size());
        randombytes_buf(ikm2.data(), ikm2.size());

        auto result1 = Hkdf::DeriveKeyBytes(ikm1, 32, salt);
        auto result2 = Hkdf::DeriveKeyBytes(ikm2, 32, salt);

        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());

        const auto output1 = std::move(result1).Unwrap();
        const auto output2 = std::move(result2).Unwrap();

        REQUIRE_FALSE(std::equal(output1.begin(), output1.end(), output2.begin()));
    }

    SECTION("No salt vs empty salt produces same output") {
        std::vector<uint8_t> ikm(32);
        randombytes_buf(ikm.data(), ikm.size());

        std::vector<uint8_t> empty_salt;

        auto result1 = Hkdf::DeriveKeyBytes(ikm, 32);
        auto result2 = Hkdf::DeriveKeyBytes(ikm, 32, empty_salt);

        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());

        const auto output1 = std::move(result1).Unwrap();
        const auto output2 = std::move(result2).Unwrap();

        REQUIRE(std::equal(output1.begin(), output1.end(), output2.begin()));
    }

    SECTION("Salt reuse with same IKM produces deterministic output") {
        std::vector<uint8_t> ikm(32);
        std::vector<uint8_t> salt(16);
        randombytes_buf(ikm.data(), ikm.size());
        randombytes_buf(salt.data(), salt.size());

        auto result1 = Hkdf::DeriveKeyBytes(ikm, 32, salt);
        auto result2 = Hkdf::DeriveKeyBytes(ikm, 32, salt);

        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());

        const auto output1 = std::move(result1).Unwrap();
        const auto output2 = std::move(result2).Unwrap();

        REQUIRE(std::equal(output1.begin(), output1.end(), output2.begin()));
    }
}

TEST_CASE("HKDF Info String Manipulation Attacks", "[security][hkdf][info-manipulation]") {

    SECTION("Different info strings produce different outputs") {
        std::vector<uint8_t> ikm(32);
        std::vector<uint8_t> salt(16);
        randombytes_buf(ikm.data(), ikm.size());
        randombytes_buf(salt.data(), salt.size());

        std::vector<uint8_t> info1 = {0x01, 0x02, 0x03};
        std::vector<uint8_t> info2 = {0x04, 0x05, 0x06};

        auto result1 = Hkdf::DeriveKeyBytes(ikm, 32, salt, info1);
        auto result2 = Hkdf::DeriveKeyBytes(ikm, 32, salt, info2);

        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());

        const auto output1 = std::move(result1).Unwrap();
        const auto output2 = std::move(result2).Unwrap();

        REQUIRE_FALSE(std::equal(output1.begin(), output1.end(), output2.begin()));
    }

    SECTION("Info string prefix attack - info1 prefix of info2 produces different outputs") {
        std::vector<uint8_t> ikm(32);
        std::vector<uint8_t> salt(16);
        randombytes_buf(ikm.data(), ikm.size());
        randombytes_buf(salt.data(), salt.size());

        std::vector<uint8_t> info1 = {0x01, 0x02};
        std::vector<uint8_t> info2 = {0x01, 0x02, 0x03};

        auto result1 = Hkdf::DeriveKeyBytes(ikm, 32, salt, info1);
        auto result2 = Hkdf::DeriveKeyBytes(ikm, 32, salt, info2);

        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());

        const auto output1 = std::move(result1).Unwrap();
        const auto output2 = std::move(result2).Unwrap();

        REQUIRE_FALSE(std::equal(output1.begin(), output1.end(), output2.begin()));
    }

    SECTION("Empty info vs no info produces same output") {
        std::vector<uint8_t> ikm(32);
        std::vector<uint8_t> salt(16);
        randombytes_buf(ikm.data(), ikm.size());
        randombytes_buf(salt.data(), salt.size());

        std::vector<uint8_t> empty_info;

        auto result1 = Hkdf::DeriveKeyBytes(ikm, 32, salt);
        auto result2 = Hkdf::DeriveKeyBytes(ikm, 32, salt, empty_info);

        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());

        const auto output1 = std::move(result1).Unwrap();
        const auto output2 = std::move(result2).Unwrap();

        REQUIRE(std::equal(output1.begin(), output1.end(), output2.begin()));
    }

    SECTION("Large info string (1KB) should work") {
        std::vector<uint8_t> ikm(32);
        std::vector<uint8_t> salt(16);
        std::vector<uint8_t> large_info(1024);
        randombytes_buf(ikm.data(), ikm.size());
        randombytes_buf(salt.data(), salt.size());
        randombytes_buf(large_info.data(), large_info.size());

        auto result = Hkdf::DeriveKeyBytes(ikm, 32, salt, large_info);
        REQUIRE(result.IsOk());

        const auto output = std::move(result).Unwrap();
        REQUIRE(output.size() == 32);
    }
}

TEST_CASE("HKDF Output Length Boundary Attacks", "[security][hkdf][output-length]") {

    SECTION("Zero output length edge case") {
        std::vector<uint8_t> ikm(32);
        randombytes_buf(ikm.data(), ikm.size());

        auto result = Hkdf::DeriveKeyBytes(ikm, 0);

        if (result.IsOk()) {
            const auto output = std::move(result).Unwrap();
            REQUIRE(output.empty());
        }
    }

    SECTION("Single byte output should work") {
        std::vector<uint8_t> ikm(32);
        randombytes_buf(ikm.data(), ikm.size());

        auto result = Hkdf::DeriveKeyBytes(ikm, 1);
        REQUIRE(result.IsOk());

        const auto output = std::move(result).Unwrap();
        REQUIRE(output.size() == 1);
    }

    SECTION("Maximum allowed output length (255 * 32 = 8160 bytes)") {
        std::vector<uint8_t> ikm(32);
        randombytes_buf(ikm.data(), ikm.size());

        constexpr size_t max_output = 255 * 32;

        auto result = Hkdf::DeriveKeyBytes(ikm, max_output);
        REQUIRE(result.IsOk());

        const auto output = std::move(result).Unwrap();
        REQUIRE(output.size() == max_output);
    }

    SECTION("Output length exceeding maximum must fail") {
        std::vector<uint8_t> ikm(32);
        randombytes_buf(ikm.data(), ikm.size());

        constexpr size_t too_large = (255 * 32) + 1;

        auto result = Hkdf::DeriveKeyBytes(ikm, too_large);
        REQUIRE(result.IsErr());

        auto err = std::move(result).UnwrapErr();
        REQUIRE(err.type == ProtocolFailureType::InvalidInput);
    }

    SECTION("Multiple standard key sizes should all work") {
        std::vector<uint8_t> ikm(32);
        randombytes_buf(ikm.data(), ikm.size());

        std::vector<size_t> key_sizes = {16, 24, 32, 48, 64, 128, 256, 512};

        for (const auto size : key_sizes) {
            auto result = Hkdf::DeriveKeyBytes(ikm, size);
            REQUIRE(result.IsOk());

            const auto output = std::move(result).Unwrap();
            REQUIRE(output.size() == size);
        }
    }
}

TEST_CASE("HKDF Extract-Expand Separation Security", "[security][hkdf][extract-expand]") {

    SECTION("Extract produces 32-byte PRK") {
        std::vector<uint8_t> ikm(32);
        std::vector<uint8_t> salt(16);
        randombytes_buf(ikm.data(), ikm.size());
        randombytes_buf(salt.data(), salt.size());

        auto result = Hkdf::Extract(ikm, salt);
        REQUIRE(result.IsOk());

        const auto prk = std::move(result).Unwrap();
        REQUIRE(prk.size() == 32);
    }

    SECTION("Expand with invalid PRK size must fail") {
        std::vector<uint8_t> invalid_prk(16);
        randombytes_buf(invalid_prk.data(), invalid_prk.size());

        std::vector<uint8_t> output(32);

        auto result = Hkdf::Expand(invalid_prk, output);
        REQUIRE(result.IsErr());

        auto err = std::move(result).UnwrapErr();
        REQUIRE(err.type == ProtocolFailureType::InvalidInput);
    }

    SECTION("Extract-then-Expand workflow") {
        std::vector<uint8_t> ikm(32);
        std::vector<uint8_t> salt(16);
        std::vector<uint8_t> info(10);
        randombytes_buf(ikm.data(), ikm.size());
        randombytes_buf(salt.data(), salt.size());
        randombytes_buf(info.data(), info.size());

        auto extract_result = Hkdf::Extract(ikm, salt);
        REQUIRE(extract_result.IsOk());

        const auto prk = std::move(extract_result).Unwrap();
        REQUIRE(prk.size() == 32);

        std::vector<uint8_t> output1(32);
        auto expand_result = Hkdf::Expand(prk, output1, info);
        REQUIRE(expand_result.IsOk());

        std::vector<uint8_t> output2(64);
        auto expand_result2 = Hkdf::Expand(prk, output2, info);
        REQUIRE(expand_result2.IsOk());

        REQUIRE(std::equal(output1.begin(), output1.end(), output2.begin()));
        REQUIRE(output2.size() > output1.size());
    }

    SECTION("Same PRK with different info produces different outputs") {
        std::vector<uint8_t> ikm(32);
        std::vector<uint8_t> salt(16);
        randombytes_buf(ikm.data(), ikm.size());
        randombytes_buf(salt.data(), salt.size());

        auto extract_result = Hkdf::Extract(ikm, salt);
        REQUIRE(extract_result.IsOk());

        const auto prk = std::move(extract_result).Unwrap();

        std::vector<uint8_t> info1 = {0x01};
        std::vector<uint8_t> info2 = {0x02};

        std::vector<uint8_t> output1(32);
        std::vector<uint8_t> output2(32);

        auto expand1 = Hkdf::Expand(prk, output1, info1);
        auto expand2 = Hkdf::Expand(prk, output2, info2);

        REQUIRE(expand1.IsOk());
        REQUIRE(expand2.IsOk());

        REQUIRE_FALSE(std::equal(output1.begin(), output1.end(), output2.begin()));
    }
}

TEST_CASE("HKDF Concurrent Derivation Safety", "[security][hkdf][concurrency]") {

    SECTION("Concurrent derivations with different IKM produce correct outputs") {
        constexpr size_t num_threads = 100;

        std::vector<std::thread> threads;
        std::vector<std::vector<uint8_t>> results(num_threads);

        std::vector<uint8_t> base_ikm(32);
        randombytes_buf(base_ikm.data(), base_ikm.size());

        for (size_t i = 0; i < num_threads; ++i) {
            threads.emplace_back([i, &base_ikm, &results]() {
                std::vector<uint8_t> ikm = base_ikm;
                ikm[0] = static_cast<uint8_t>(i);

                auto result = Hkdf::DeriveKeyBytes(ikm, 32);
                if (result.IsOk()) {
                    results[i] = std::move(result).Unwrap();
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        for (size_t i = 0; i < num_threads; ++i) {
            REQUIRE(results[i].size() == 32);

            for (size_t j = i + 1; j < num_threads; ++j) {
                REQUIRE_FALSE(std::equal(results[i].begin(), results[i].end(),
                                        results[j].begin()));
            }
        }
    }

    SECTION("Concurrent derivations with same IKM produce same output") {
        constexpr size_t num_threads = 100;

        std::vector<std::thread> threads;
        std::vector<std::vector<uint8_t>> results(num_threads);

        std::vector<uint8_t> ikm(32);
        std::vector<uint8_t> salt(16);
        std::vector<uint8_t> info(10);
        randombytes_buf(ikm.data(), ikm.size());
        randombytes_buf(salt.data(), salt.size());
        randombytes_buf(info.data(), info.size());

        for (size_t i = 0; i < num_threads; ++i) {
            threads.emplace_back([i, &ikm, &salt, &info, &results]() {
                auto result = Hkdf::DeriveKeyBytes(ikm, 32, salt, info);
                if (result.IsOk()) {
                    results[i] = std::move(result).Unwrap();
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        for (size_t i = 0; i < num_threads; ++i) {
            REQUIRE(results[i].size() == 32);
        }

        for (size_t i = 1; i < num_threads; ++i) {
            REQUIRE(std::equal(results[0].begin(), results[0].end(),
                              results[i].begin()));
        }
    }
}

TEST_CASE("HKDF Key Stretching Resistance", "[security][hkdf][key-stretching]") {

    SECTION("Large output from small IKM should work") {
        std::vector<uint8_t> small_ikm(16);
        randombytes_buf(small_ikm.data(), small_ikm.size());

        constexpr size_t large_output = 4096;

        auto result = Hkdf::DeriveKeyBytes(small_ikm, large_output);
        REQUIRE(result.IsOk());

        const auto output = std::move(result).Unwrap();
        REQUIRE(output.size() == large_output);
    }

    SECTION("Verify output has high entropy") {
        std::vector<uint8_t> ikm(32);
        randombytes_buf(ikm.data(), ikm.size());

        auto result = Hkdf::DeriveKeyBytes(ikm, 1024);
        REQUIRE(result.IsOk());

        const auto output = std::move(result).Unwrap();

        std::array<size_t, 256> byte_counts = {};
        for (const auto byte : output) {
            byte_counts[byte]++;
        }

        bool has_reasonable_distribution = true;
        for (const auto count : byte_counts) {
            if (count > output.size() / 32) {
                has_reasonable_distribution = false;
                break;
            }
        }

        REQUIRE(has_reasonable_distribution);
    }

    SECTION("Multiple derivations from same IKM with different info are independent") {
        std::vector<uint8_t> ikm(32);
        randombytes_buf(ikm.data(), ikm.size());

        std::vector<uint8_t> info1 = {0x01};
        std::vector<uint8_t> info2 = {0x02};
        std::vector<uint8_t> info3 = {0x03};

        auto result1 = Hkdf::DeriveKeyBytes(ikm, 32, {}, info1);
        auto result2 = Hkdf::DeriveKeyBytes(ikm, 32, {}, info2);
        auto result3 = Hkdf::DeriveKeyBytes(ikm, 32, {}, info3);

        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());
        REQUIRE(result3.IsOk());

        const auto output1 = std::move(result1).Unwrap();
        const auto output2 = std::move(result2).Unwrap();
        const auto output3 = std::move(result3).Unwrap();

        REQUIRE_FALSE(std::equal(output1.begin(), output1.end(), output2.begin()));
        REQUIRE_FALSE(std::equal(output1.begin(), output1.end(), output3.begin()));
        REQUIRE_FALSE(std::equal(output2.begin(), output2.end(), output3.begin()));
    }
}
