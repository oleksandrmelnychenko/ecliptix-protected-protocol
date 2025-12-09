#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>
#include "ecliptix/c_api/ecliptix_c_api.h"
#include <cstring>
#include <vector>
#include <thread>
#include <atomic>

TEST_CASE("C API - Initialization", "[c_api][boundary][init]") {
    SECTION("Initialize succeeds") {
        const EcliptixErrorCode result = ecliptix_initialize();
        REQUIRE(result == ECLIPTIX_SUCCESS);
        ecliptix_shutdown();
    }

    SECTION("Version string is valid") {
        const char* version = ecliptix_get_version();
        REQUIRE(version != nullptr);
        REQUIRE(std::strlen(version) > 0);
        REQUIRE(std::strcmp(version, "1.0.0") == 0);
    }

    SECTION("Multiple initialize calls are safe") {
        REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);
        REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);
        ecliptix_shutdown();
    }

    SECTION("Shutdown without initialize is safe") {
        ecliptix_shutdown();
        ecliptix_shutdown();
    }
}

TEST_CASE("C API - NULL Pointer Handling", "[c_api][boundary][null]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Identity keys create - NULL output handle") {
        const EcliptixErrorCode result = ecliptix_identity_keys_create(
            nullptr,
            nullptr
        );
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
    }

    SECTION("Identity keys create - NULL error output is safe") {
        EcliptixIdentityKeysHandle* handle = nullptr;
        const EcliptixErrorCode result = ecliptix_identity_keys_create(
            &handle,
            nullptr
        );
        REQUIRE(result == ECLIPTIX_SUCCESS);
        REQUIRE(handle != nullptr);
        ecliptix_identity_keys_destroy(handle);
    }

    SECTION("Identity keys create from seed - NULL seed") {
        EcliptixIdentityKeysHandle* handle = nullptr;
        EcliptixError error{};
        const EcliptixErrorCode result = ecliptix_identity_keys_create_from_seed(
            nullptr,
            32,
            &handle,
            &error
        );
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) {
            ecliptix_error_free(&error);
        }
    }

    SECTION("Identity keys create from seed - NULL output handle") {
        std::vector<uint8_t> seed(32, 0xAA);
        EcliptixError error{};
        const EcliptixErrorCode result = ecliptix_identity_keys_create_from_seed(
            seed.data(),
            seed.size(),
            nullptr,
            &error
        );
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) {
            ecliptix_error_free(&error);
        }
    }

    SECTION("Get public X25519 - NULL handle") {
        uint8_t key[32] = {};
        EcliptixError error{};
        const EcliptixErrorCode result = ecliptix_identity_keys_get_public_x25519(
            nullptr,
            key,
            32,
            &error
        );
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) {
            ecliptix_error_free(&error);
        }
    }

    SECTION("Get public X25519 - NULL output buffer") {
        EcliptixIdentityKeysHandle* handle = nullptr;
        REQUIRE(ecliptix_identity_keys_create(&handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixError error{};
        const EcliptixErrorCode result = ecliptix_identity_keys_get_public_x25519(
            handle,
            nullptr,
            32,
            &error
        );
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);

        ecliptix_identity_keys_destroy(handle);
        if (error.message) {
            ecliptix_error_free(&error);
        }
    }

    SECTION("Get public Ed25519 - NULL handle") {
        uint8_t key[32] = {};
        EcliptixError error{};
        const EcliptixErrorCode result = ecliptix_identity_keys_get_public_ed25519(
            nullptr,
            key,
            32,
            &error
        );
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) {
            ecliptix_error_free(&error);
        }
    }

    SECTION("Get public Ed25519 - NULL output buffer") {
        EcliptixIdentityKeysHandle* handle = nullptr;
        REQUIRE(ecliptix_identity_keys_create(&handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixError error{};
        const EcliptixErrorCode result = ecliptix_identity_keys_get_public_ed25519(
            handle,
            nullptr,
            32,
            &error
        );
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);

        ecliptix_identity_keys_destroy(handle);
        if (error.message) {
            ecliptix_error_free(&error);
        }
    }

    SECTION("Protocol system create - NULL identity keys") {
        EcliptixProtocolSystemHandle* system = nullptr;
        EcliptixError error{};
        const EcliptixErrorCode result = ecliptix_protocol_system_create(
            nullptr,
            &system,
            &error
        );
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) {
            ecliptix_error_free(&error);
        }
    }

    SECTION("Protocol system create - NULL output handle") {
        EcliptixIdentityKeysHandle* keys = nullptr;
        REQUIRE(ecliptix_identity_keys_create(&keys, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixError error{};
        const EcliptixErrorCode result = ecliptix_protocol_system_create(
            keys,
            nullptr,
            &error
        );
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);

        ecliptix_identity_keys_destroy(keys);
        if (error.message) {
            ecliptix_error_free(&error);
        }
    }

    SECTION("Destroy NULL handles is safe") {
        ecliptix_identity_keys_destroy(nullptr);
        ecliptix_protocol_system_destroy(nullptr);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API - Buffer Size Validation", "[c_api][boundary][buffer]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Identity keys from seed - invalid seed size") {
        std::vector<uint8_t> seed(16, 0xAA);
        EcliptixIdentityKeysHandle* handle = nullptr;
        EcliptixError error{};

        const EcliptixErrorCode result = ecliptix_identity_keys_create_from_seed(
            seed.data(),
            seed.size(),
            &handle,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_INVALID_INPUT);
        REQUIRE(error.message != nullptr);
        REQUIRE(std::strstr(error.message, "32 bytes") != nullptr);
        ecliptix_error_free(&error);
    }

    SECTION("Identity keys from seed - zero size") {
        std::vector<uint8_t> seed(32, 0xAA);
        EcliptixIdentityKeysHandle* handle = nullptr;
        EcliptixError error{};

        const EcliptixErrorCode result = ecliptix_identity_keys_create_from_seed(
            seed.data(),
            0,
            &handle,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_INVALID_INPUT);
        ecliptix_error_free(&error);
    }

    SECTION("Get public X25519 - buffer too small") {
        EcliptixIdentityKeysHandle* handle = nullptr;
        REQUIRE(ecliptix_identity_keys_create(&handle, nullptr) == ECLIPTIX_SUCCESS);

        uint8_t key[16] = {};
        EcliptixError error{};
        const EcliptixErrorCode result = ecliptix_identity_keys_get_public_x25519(
            handle,
            key,
            16,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_BUFFER_TOO_SMALL);
        REQUIRE(error.message != nullptr);

        ecliptix_identity_keys_destroy(handle);
        ecliptix_error_free(&error);
    }

    SECTION("Get public Ed25519 - buffer too small") {
        EcliptixIdentityKeysHandle* handle = nullptr;
        REQUIRE(ecliptix_identity_keys_create(&handle, nullptr) == ECLIPTIX_SUCCESS);

        uint8_t key[16] = {};
        EcliptixError error{};
        const EcliptixErrorCode result = ecliptix_identity_keys_get_public_ed25519(
            handle,
            key,
            16,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_BUFFER_TOO_SMALL);
        REQUIRE(error.message != nullptr);

        ecliptix_identity_keys_destroy(handle);
        ecliptix_error_free(&error);
    }

    SECTION("Get public X25519 - exact size succeeds") {
        EcliptixIdentityKeysHandle* handle = nullptr;
        REQUIRE(ecliptix_identity_keys_create(&handle, nullptr) == ECLIPTIX_SUCCESS);

        uint8_t key[32] = {};
        const EcliptixErrorCode result = ecliptix_identity_keys_get_public_x25519(
            handle,
            key,
            32,
            nullptr
        );

        REQUIRE(result == ECLIPTIX_SUCCESS);

        bool all_zero = true;
        for (int i = 0; i < 32; ++i) {
            if (key[i] != 0) {
                all_zero = false;
                break;
            }
        }
        REQUIRE_FALSE(all_zero);

        ecliptix_identity_keys_destroy(handle);
    }

    SECTION("Get public Ed25519 - exact size succeeds") {
        EcliptixIdentityKeysHandle* handle = nullptr;
        REQUIRE(ecliptix_identity_keys_create(&handle, nullptr) == ECLIPTIX_SUCCESS);

        uint8_t key[32] = {};
        const EcliptixErrorCode result = ecliptix_identity_keys_get_public_ed25519(
            handle,
            key,
            32,
            nullptr
        );

        REQUIRE(result == ECLIPTIX_SUCCESS);

        bool all_zero = true;
        for (int i = 0; i < 32; ++i) {
            if (key[i] != 0) {
                all_zero = false;
                break;
            }
        }
        REQUIRE_FALSE(all_zero);

        ecliptix_identity_keys_destroy(handle);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API - Error Propagation", "[c_api][boundary][error]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Error codes are distinct") {
        REQUIRE(ECLIPTIX_SUCCESS == 0);
        REQUIRE(ECLIPTIX_ERROR_GENERIC != ECLIPTIX_SUCCESS);
        REQUIRE(ECLIPTIX_ERROR_INVALID_INPUT != ECLIPTIX_SUCCESS);
        REQUIRE(ECLIPTIX_ERROR_KEY_GENERATION != ECLIPTIX_ERROR_DERIVE_KEY);
    }

    SECTION("Error code to string") {
        REQUIRE(std::strcmp(ecliptix_error_code_to_string(ECLIPTIX_SUCCESS), "Success") == 0);
        REQUIRE(std::strcmp(ecliptix_error_code_to_string(ECLIPTIX_ERROR_GENERIC), "Generic error") == 0);
        REQUIRE(std::strcmp(ecliptix_error_code_to_string(ECLIPTIX_ERROR_NULL_POINTER), "Null pointer") == 0);
        REQUIRE(std::strcmp(ecliptix_error_code_to_string(ECLIPTIX_ERROR_BUFFER_TOO_SMALL), "Buffer too small") == 0);
        REQUIRE(std::strcmp(ecliptix_error_code_to_string(ECLIPTIX_ERROR_ENCODE), "Encoding failed") == 0);
    }

    SECTION("Error message allocation and cleanup") {
        std::vector<uint8_t> seed(16, 0xAA);
        EcliptixIdentityKeysHandle* handle = nullptr;
        EcliptixError error{};
        error.message = nullptr;

        ecliptix_identity_keys_create_from_seed(
            seed.data(),
            seed.size(),
            &handle,
            &error
        );

        REQUIRE(error.code == ECLIPTIX_ERROR_INVALID_INPUT);
        REQUIRE(error.message != nullptr);
        REQUIRE(std::strlen(error.message) > 0);

        ecliptix_error_free(&error);
        REQUIRE(error.message == nullptr);
    }

    SECTION("Error free on NULL is safe") {
        EcliptixError error{};
        error.message = nullptr;
        ecliptix_error_free(&error);
        ecliptix_error_free(nullptr);
    }

    SECTION("Error free multiple times is safe") {
        std::vector<uint8_t> seed(16, 0xAA);
        EcliptixIdentityKeysHandle* handle = nullptr;
        EcliptixError error{};

        ecliptix_identity_keys_create_from_seed(
            seed.data(),
            seed.size(),
            &handle,
            &error
        );

        ecliptix_error_free(&error);
        ecliptix_error_free(&error);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API - Memory Management", "[c_api][boundary][memory]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Identity keys lifecycle") {
        EcliptixIdentityKeysHandle* handle = nullptr;
        REQUIRE(ecliptix_identity_keys_create(&handle, nullptr) == ECLIPTIX_SUCCESS);
        REQUIRE(handle != nullptr);

        ecliptix_identity_keys_destroy(handle);
    }

    SECTION("Multiple identity keys") {
        constexpr int count = 10;
        EcliptixIdentityKeysHandle* handles[count] = {};

        for (int i = 0; i < count; ++i) {
            REQUIRE(ecliptix_identity_keys_create(&handles[i], nullptr) == ECLIPTIX_SUCCESS);
            REQUIRE(handles[i] != nullptr);
        }

        for (int i = 0; i < count; ++i) {
            ecliptix_identity_keys_destroy(handles[i]);
        }
    }

    SECTION("Buffer allocation and cleanup") {
        EcliptixBuffer* buffer = ecliptix_buffer_allocate(1024);
        REQUIRE(buffer != nullptr);
        REQUIRE(buffer->data != nullptr);
        REQUIRE(buffer->length == 1024);

        ecliptix_buffer_free(buffer);
    }

    SECTION("Buffer allocation - zero size") {
        EcliptixBuffer* buffer = ecliptix_buffer_allocate(0);
        REQUIRE(buffer != nullptr);
        REQUIRE(buffer->data == nullptr);
        REQUIRE(buffer->length == 0);

        ecliptix_buffer_free(buffer);
    }

    SECTION("Buffer free NULL is safe") {
        ecliptix_buffer_free(nullptr);
    }

    SECTION("Secure wipe") {
        std::vector<uint8_t> data(256, 0xAA);

        const EcliptixErrorCode result = ecliptix_secure_wipe(data.data(), data.size());
        REQUIRE(result == ECLIPTIX_SUCCESS);

        bool all_zero = true;
        for (const auto byte : data) {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        REQUIRE(all_zero);
    }

    SECTION("Secure wipe - NULL with zero length is safe") {
        const EcliptixErrorCode result = ecliptix_secure_wipe(nullptr, 0);
        REQUIRE(result == ECLIPTIX_SUCCESS);
    }

    SECTION("Secure wipe - NULL with non-zero length fails") {
        const EcliptixErrorCode result = ecliptix_secure_wipe(nullptr, 100);
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API - Protocol System Lifecycle", "[c_api][boundary][protocol]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Create protocol system") {
        EcliptixIdentityKeysHandle* keys = nullptr;
        REQUIRE(ecliptix_identity_keys_create(&keys, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* system = nullptr;
        const EcliptixErrorCode result = ecliptix_protocol_system_create(
            keys,
            &system,
            nullptr
        );

        REQUIRE(result == ECLIPTIX_SUCCESS);
        REQUIRE(system != nullptr);

        ecliptix_protocol_system_destroy(system);
        ecliptix_identity_keys_destroy(keys);
    }

    SECTION("Set callbacks - NULL callback") {
        EcliptixIdentityKeysHandle* keys = nullptr;
        REQUIRE(ecliptix_identity_keys_create(&keys, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* system = nullptr;
        REQUIRE(ecliptix_protocol_system_create(keys, &system, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixCallbacks callbacks{};
        callbacks.on_protocol_state_changed = nullptr;
        callbacks.user_data = nullptr;

        const EcliptixErrorCode result = ecliptix_protocol_system_set_callbacks(
            system,
            &callbacks,
            nullptr
        );

        REQUIRE(result == ECLIPTIX_SUCCESS);

        ecliptix_protocol_system_destroy(system);
        ecliptix_identity_keys_destroy(keys);
    }

    SECTION("Set callbacks - NULL callbacks struct") {
        EcliptixIdentityKeysHandle* keys = nullptr;
        REQUIRE(ecliptix_identity_keys_create(&keys, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* system = nullptr;
        REQUIRE(ecliptix_protocol_system_create(keys, &system, nullptr) == ECLIPTIX_SUCCESS);

        const EcliptixErrorCode result = ecliptix_protocol_system_set_callbacks(
            system,
            nullptr,
            nullptr
        );

        REQUIRE(result == ECLIPTIX_SUCCESS);

        ecliptix_protocol_system_destroy(system);
        ecliptix_identity_keys_destroy(keys);
    }

    SECTION("Set callbacks - NULL system handle") {
        EcliptixCallbacks callbacks{};
        EcliptixError error{};

        const EcliptixErrorCode result = ecliptix_protocol_system_set_callbacks(
            nullptr,
            &callbacks,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) {
            ecliptix_error_free(&error);
        }
    }

    ecliptix_shutdown();
}

TEST_CASE("C API - Thread Safety", "[c_api][boundary][thread]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Concurrent identity key creation") {
        constexpr int thread_count = 10;
        constexpr int iterations = 5;
        std::atomic<int> success_count{0};

        std::vector<std::thread> threads;
        threads.reserve(thread_count);

        for (int t = 0; t < thread_count; ++t) {
            threads.emplace_back([&success_count]() {
                for (int i = 0; i < iterations; ++i) {
                    EcliptixIdentityKeysHandle* handle = nullptr;
                    if (ecliptix_identity_keys_create(&handle, nullptr) == ECLIPTIX_SUCCESS) {
                        success_count.fetch_add(1, std::memory_order_relaxed);
                        ecliptix_identity_keys_destroy(handle);
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(success_count.load() == thread_count * iterations);
    }

    SECTION("Concurrent buffer allocation") {
        constexpr int thread_count = 10;
        constexpr int iterations = 10;
        std::atomic<int> success_count{0};

        std::vector<std::thread> threads;
        threads.reserve(thread_count);

        for (int t = 0; t < thread_count; ++t) {
            threads.emplace_back([&success_count]() {
                for (int i = 0; i < iterations; ++i) {
                    EcliptixBuffer* buffer = ecliptix_buffer_allocate(1024);
                    if (buffer != nullptr) {
                        success_count.fetch_add(1, std::memory_order_relaxed);
                        ecliptix_buffer_free(buffer);
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(success_count.load() == thread_count * iterations);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API - Deterministic Key Generation from Seed", "[c_api][boundary][deterministic]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Same seed produces same keys") {
        std::vector<uint8_t> seed(32, 0xBB);

        EcliptixIdentityKeysHandle* handle1 = nullptr;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            seed.data(),
            seed.size(),
            &handle1,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        uint8_t x25519_key1[32] = {};
        REQUIRE(ecliptix_identity_keys_get_public_x25519(
            handle1,
            x25519_key1,
            32,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixIdentityKeysHandle* handle2 = nullptr;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            seed.data(),
            seed.size(),
            &handle2,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        uint8_t x25519_key2[32] = {};
        REQUIRE(ecliptix_identity_keys_get_public_x25519(
            handle2,
            x25519_key2,
            32,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(std::memcmp(x25519_key1, x25519_key2, 32) == 0);

        ecliptix_identity_keys_destroy(handle1);
        ecliptix_identity_keys_destroy(handle2);
    }

    SECTION("Different seeds produce different keys") {
        std::vector<uint8_t> seed1(32, 0xAA);
        std::vector<uint8_t> seed2(32, 0xBB);

        EcliptixIdentityKeysHandle* handle1 = nullptr;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            seed1.data(),
            seed1.size(),
            &handle1,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        uint8_t x25519_key1[32] = {};
        REQUIRE(ecliptix_identity_keys_get_public_x25519(
            handle1,
            x25519_key1,
            32,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixIdentityKeysHandle* handle2 = nullptr;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            seed2.data(),
            seed2.size(),
            &handle2,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        uint8_t x25519_key2[32] = {};
        REQUIRE(ecliptix_identity_keys_get_public_x25519(
            handle2,
            x25519_key2,
            32,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(std::memcmp(x25519_key1, x25519_key2, 32) != 0);

        ecliptix_identity_keys_destroy(handle1);
        ecliptix_identity_keys_destroy(handle2);
    }

    ecliptix_shutdown();
}
