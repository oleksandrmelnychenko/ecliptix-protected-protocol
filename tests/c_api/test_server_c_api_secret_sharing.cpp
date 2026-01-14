#include <catch2/catch_test_macros.hpp>
#include "ecliptix/c_api/epp_server_api.h"
#include <cstring>
#include <vector>

TEST_CASE("Server C API - Secret sharing", "[c_api][server][secret-sharing]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Split rejects null outputs") {
        std::vector<uint8_t> secret(16, 0x11);
        size_t share_length = 0;
        EppError error{};

        auto result = epp_shamir_split(
            secret.data(),
            secret.size(),
            2,
            3,
            nullptr,
            0,
            nullptr,
            &share_length,
            &error);
        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) {
            epp_error_free(&error);
        }

        EppBuffer* shares = epp_buffer_alloc(0);
        result = epp_shamir_split(
            secret.data(),
            secret.size(),
            2,
            3,
            nullptr,
            0,
            shares,
            nullptr,
            &error);
        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) {
            epp_error_free(&error);
        }
        epp_buffer_free(shares);
    }

    SECTION("Split rejects empty secret") {
        std::vector<uint8_t> secret(16, 0x22);
        EppBuffer* shares = epp_buffer_alloc(0);
        size_t share_length = 0;
        EppError error{};

        const auto result = epp_shamir_split(
            secret.data(),
            0,
            2,
            3,
            nullptr,
            0,
            shares,
            &share_length,
            &error);
        REQUIRE(result == EPP_ERROR_INVALID_INPUT);
        if (error.message) {
            epp_error_free(&error);
        }
        epp_buffer_free(shares);
    }

    SECTION("Split rejects invalid auth key length") {
        std::vector<uint8_t> secret(16, 0x33);
        std::vector<uint8_t> auth_key(31, 0xAB);
        EppBuffer* shares = epp_buffer_alloc(0);
        size_t share_length = 0;
        EppError error{};

        const auto result = epp_shamir_split(
            secret.data(),
            secret.size(),
            2,
            3,
            auth_key.data(),
            auth_key.size(),
            shares,
            &share_length,
            &error);
        REQUIRE(result == EPP_ERROR_INVALID_INPUT);
        if (error.message) {
            epp_error_free(&error);
        }
        epp_buffer_free(shares);
    }

    SECTION("Roundtrip without auth") {
        std::vector<uint8_t> secret(32, 0x44);
        EppBuffer* shares = epp_buffer_alloc(0);
        size_t share_length = 0;
        EppError error{};

        auto result = epp_shamir_split(
            secret.data(),
            secret.size(),
            3,
            5,
            nullptr,
            0,
            shares,
            &share_length,
            &error);
        REQUIRE(result == EPP_SUCCESS);
        REQUIRE(shares->data != nullptr);

        EppBuffer* out_secret = epp_buffer_alloc(0);
        result = epp_shamir_reconstruct(
            shares->data,
            shares->length,
            share_length,
            5,
            nullptr,
            0,
            out_secret,
            &error);
        REQUIRE(result == EPP_SUCCESS);
        REQUIRE(out_secret->length == secret.size());
        REQUIRE(std::memcmp(out_secret->data, secret.data(), secret.size()) == 0);

        epp_buffer_free(out_secret);
        epp_buffer_free(shares);
    }

    SECTION("Reconstruct rejects missing auth key for auth shares") {
        std::vector<uint8_t> secret(16, 0x55);
        std::vector<uint8_t> auth_key(32, 0xDD);
        EppBuffer* shares = epp_buffer_alloc(0);
        size_t share_length = 0;
        EppError error{};

        auto result = epp_shamir_split(
            secret.data(),
            secret.size(),
            2,
            3,
            auth_key.data(),
            auth_key.size(),
            shares,
            &share_length,
            &error);
        REQUIRE(result == EPP_SUCCESS);

        EppBuffer* out_secret = epp_buffer_alloc(0);
        result = epp_shamir_reconstruct(
            shares->data,
            shares->length,
            share_length,
            3,
            nullptr,
            0,
            out_secret,
            &error);
        REQUIRE(result == EPP_ERROR_INVALID_INPUT);
        if (error.message) {
            epp_error_free(&error);
        }

        epp_buffer_free(out_secret);
        epp_buffer_free(shares);
    }

    SECTION("Reconstruct rejects invalid auth key length") {
        std::vector<uint8_t> secret(16, 0x66);
        std::vector<uint8_t> auth_key(31, 0x44);
        EppBuffer* shares = epp_buffer_alloc(0);
        size_t share_length = 0;
        EppError error{};

        auto result = epp_shamir_split(
            secret.data(),
            secret.size(),
            2,
            3,
            nullptr,
            0,
            shares,
            &share_length,
            &error);
        REQUIRE(result == EPP_SUCCESS);

        EppBuffer* out_secret = epp_buffer_alloc(0);
        result = epp_shamir_reconstruct(
            shares->data,
            shares->length,
            share_length,
            3,
            auth_key.data(),
            auth_key.size(),
            out_secret,
            &error);
        REQUIRE(result == EPP_ERROR_INVALID_INPUT);
        if (error.message) {
            epp_error_free(&error);
        }

        epp_buffer_free(out_secret);
        epp_buffer_free(shares);
    }

    SECTION("Reconstruct rejects share length mismatch") {
        std::vector<uint8_t> secret(16, 0x77);
        EppBuffer* shares = epp_buffer_alloc(0);
        size_t share_length = 0;
        EppError error{};

        auto result = epp_shamir_split(
            secret.data(),
            secret.size(),
            2,
            3,
            nullptr,
            0,
            shares,
            &share_length,
            &error);
        REQUIRE(result == EPP_SUCCESS);

        EppBuffer* out_secret = epp_buffer_alloc(0);
        result = epp_shamir_reconstruct(
            shares->data,
            shares->length,
            share_length + 1,
            3,
            nullptr,
            0,
            out_secret,
            &error);
        REQUIRE(result == EPP_ERROR_INVALID_INPUT);
        if (error.message) {
            epp_error_free(&error);
        }

        epp_buffer_free(out_secret);
        epp_buffer_free(shares);
    }

    SECTION("Reconstruct rejects null shares") {
        EppBuffer* out_secret = epp_buffer_alloc(0);
        EppError error{};

        const auto result = epp_shamir_reconstruct(
            nullptr,
            16,
            8,
            2,
            nullptr,
            0,
            out_secret,
            &error);
        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) {
            epp_error_free(&error);
        }

        epp_buffer_free(out_secret);
    }

    epp_shutdown();
}
