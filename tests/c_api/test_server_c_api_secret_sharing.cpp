#include <catch2/catch_test_macros.hpp>
#include "ecliptix/c_api/ecliptix_server_c_api.h"
#include <cstring>
#include <vector>

TEST_CASE("Server C API - Secret sharing", "[c_api][server][secret-sharing]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Split rejects null outputs") {
        std::vector<uint8_t> secret(16, 0x11);
        size_t share_length = 0;
        EcliptixError error{};

        auto result = ecliptix_secret_sharing_split(
            secret.data(),
            secret.size(),
            2,
            3,
            nullptr,
            0,
            nullptr,
            &share_length,
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) {
            ecliptix_error_free(&error);
        }

        EcliptixBuffer* shares = ecliptix_buffer_allocate(0);
        result = ecliptix_secret_sharing_split(
            secret.data(),
            secret.size(),
            2,
            3,
            nullptr,
            0,
            shares,
            nullptr,
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) {
            ecliptix_error_free(&error);
        }
        ecliptix_buffer_free(shares);
    }

    SECTION("Split rejects empty secret") {
        std::vector<uint8_t> secret(16, 0x22);
        EcliptixBuffer* shares = ecliptix_buffer_allocate(0);
        size_t share_length = 0;
        EcliptixError error{};

        const auto result = ecliptix_secret_sharing_split(
            secret.data(),
            0,
            2,
            3,
            nullptr,
            0,
            shares,
            &share_length,
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_INVALID_INPUT);
        if (error.message) {
            ecliptix_error_free(&error);
        }
        ecliptix_buffer_free(shares);
    }

    SECTION("Split rejects invalid auth key length") {
        std::vector<uint8_t> secret(16, 0x33);
        std::vector<uint8_t> auth_key(31, 0xAB);
        EcliptixBuffer* shares = ecliptix_buffer_allocate(0);
        size_t share_length = 0;
        EcliptixError error{};

        const auto result = ecliptix_secret_sharing_split(
            secret.data(),
            secret.size(),
            2,
            3,
            auth_key.data(),
            auth_key.size(),
            shares,
            &share_length,
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_INVALID_INPUT);
        if (error.message) {
            ecliptix_error_free(&error);
        }
        ecliptix_buffer_free(shares);
    }

    SECTION("Roundtrip without auth") {
        std::vector<uint8_t> secret(32, 0x44);
        EcliptixBuffer* shares = ecliptix_buffer_allocate(0);
        size_t share_length = 0;
        EcliptixError error{};

        auto result = ecliptix_secret_sharing_split(
            secret.data(),
            secret.size(),
            3,
            5,
            nullptr,
            0,
            shares,
            &share_length,
            &error);
        REQUIRE(result == ECLIPTIX_SUCCESS);
        REQUIRE(shares->data != nullptr);

        EcliptixBuffer* out_secret = ecliptix_buffer_allocate(0);
        result = ecliptix_secret_sharing_reconstruct(
            shares->data,
            shares->length,
            share_length,
            5,
            nullptr,
            0,
            out_secret,
            &error);
        REQUIRE(result == ECLIPTIX_SUCCESS);
        REQUIRE(out_secret->length == secret.size());
        REQUIRE(std::memcmp(out_secret->data, secret.data(), secret.size()) == 0);

        ecliptix_buffer_free(out_secret);
        ecliptix_buffer_free(shares);
    }

    SECTION("Reconstruct rejects missing auth key for auth shares") {
        std::vector<uint8_t> secret(16, 0x55);
        std::vector<uint8_t> auth_key(32, 0xDD);
        EcliptixBuffer* shares = ecliptix_buffer_allocate(0);
        size_t share_length = 0;
        EcliptixError error{};

        auto result = ecliptix_secret_sharing_split(
            secret.data(),
            secret.size(),
            2,
            3,
            auth_key.data(),
            auth_key.size(),
            shares,
            &share_length,
            &error);
        REQUIRE(result == ECLIPTIX_SUCCESS);

        EcliptixBuffer* out_secret = ecliptix_buffer_allocate(0);
        result = ecliptix_secret_sharing_reconstruct(
            shares->data,
            shares->length,
            share_length,
            3,
            nullptr,
            0,
            out_secret,
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_INVALID_INPUT);
        if (error.message) {
            ecliptix_error_free(&error);
        }

        ecliptix_buffer_free(out_secret);
        ecliptix_buffer_free(shares);
    }

    SECTION("Reconstruct rejects invalid auth key length") {
        std::vector<uint8_t> secret(16, 0x66);
        std::vector<uint8_t> auth_key(31, 0x44);
        EcliptixBuffer* shares = ecliptix_buffer_allocate(0);
        size_t share_length = 0;
        EcliptixError error{};

        auto result = ecliptix_secret_sharing_split(
            secret.data(),
            secret.size(),
            2,
            3,
            nullptr,
            0,
            shares,
            &share_length,
            &error);
        REQUIRE(result == ECLIPTIX_SUCCESS);

        EcliptixBuffer* out_secret = ecliptix_buffer_allocate(0);
        result = ecliptix_secret_sharing_reconstruct(
            shares->data,
            shares->length,
            share_length,
            3,
            auth_key.data(),
            auth_key.size(),
            out_secret,
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_INVALID_INPUT);
        if (error.message) {
            ecliptix_error_free(&error);
        }

        ecliptix_buffer_free(out_secret);
        ecliptix_buffer_free(shares);
    }

    SECTION("Reconstruct rejects share length mismatch") {
        std::vector<uint8_t> secret(16, 0x77);
        EcliptixBuffer* shares = ecliptix_buffer_allocate(0);
        size_t share_length = 0;
        EcliptixError error{};

        auto result = ecliptix_secret_sharing_split(
            secret.data(),
            secret.size(),
            2,
            3,
            nullptr,
            0,
            shares,
            &share_length,
            &error);
        REQUIRE(result == ECLIPTIX_SUCCESS);

        EcliptixBuffer* out_secret = ecliptix_buffer_allocate(0);
        result = ecliptix_secret_sharing_reconstruct(
            shares->data,
            shares->length,
            share_length + 1,
            3,
            nullptr,
            0,
            out_secret,
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_INVALID_INPUT);
        if (error.message) {
            ecliptix_error_free(&error);
        }

        ecliptix_buffer_free(out_secret);
        ecliptix_buffer_free(shares);
    }

    SECTION("Reconstruct rejects null shares") {
        EcliptixBuffer* out_secret = ecliptix_buffer_allocate(0);
        EcliptixError error{};

        const auto result = ecliptix_secret_sharing_reconstruct(
            nullptr,
            16,
            8,
            2,
            nullptr,
            0,
            out_secret,
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) {
            ecliptix_error_free(&error);
        }

        ecliptix_buffer_free(out_secret);
    }

    ecliptix_shutdown();
}
