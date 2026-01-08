#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>
#include "ecliptix/c_api/ecliptix_c_api.h"
#include "common/secure_envelope.pb.h"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/core/constants.hpp"
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

TEST_CASE("C API - Hybrid ratchet requires Kyber ciphertext with DH", "[c_api][boundary][hybrid][pq]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    EcliptixIdentityKeysHandle* keys = nullptr;
    REQUIRE(ecliptix_identity_keys_create(&keys, nullptr) == ECLIPTIX_SUCCESS);

    EcliptixProtocolSystemHandle* system = nullptr;
    REQUIRE(ecliptix_protocol_system_create(keys, &system, nullptr) == ECLIPTIX_SUCCESS);

    ecliptix::proto::common::SecureEnvelope envelope;
    std::vector<uint8_t> dh(ecliptix::protocol::Constants::X_25519_PUBLIC_KEY_SIZE, 0x01);
    envelope.set_dh_public_key(dh.data(), dh.size());
    envelope.set_ratchet_epoch(0);
    const std::string serialized = envelope.SerializeAsString();

    EcliptixBuffer plaintext{};
    EcliptixError error{};
    const auto result = ecliptix_protocol_system_receive_message(
        system,
        reinterpret_cast<const uint8_t*>(serialized.data()),
        serialized.size(),
        &plaintext,
        &error);

    REQUIRE(result == ECLIPTIX_ERROR_PQ_MISSING);
    REQUIRE(error.message != nullptr);
    ecliptix_error_free(&error);

    ecliptix_protocol_system_destroy(system);
    ecliptix_identity_keys_destroy(keys);
    ecliptix_shutdown();
}

TEST_CASE("C API - Envelope validation prefilter enforces hybrid ciphertext", "[c_api][boundary][hybrid][pq]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    std::vector<uint8_t> dh(ecliptix::protocol::Constants::X_25519_PUBLIC_KEY_SIZE, 0x01);
    std::vector<uint8_t> kyber(ecliptix::protocol::crypto::KyberInterop::KYBER_768_CIPHERTEXT_SIZE, 0x02);

    SECTION("Rejects DH without Kyber") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh.data(), dh.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        EcliptixError error{};
        const auto result = ecliptix_envelope_validate_hybrid_requirements(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            &error);

        REQUIRE(result == ECLIPTIX_ERROR_PQ_MISSING);
        REQUIRE(error.message != nullptr);
        ecliptix_error_free(&error);
    }

    SECTION("Accepts DH with Kyber") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh.data(), dh.size());
        envelope.set_kyber_ciphertext(kyber.data(), kyber.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        const auto result = ecliptix_envelope_validate_hybrid_requirements(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            nullptr);

        REQUIRE(result == ECLIPTIX_SUCCESS);
    }

    SECTION("Rejects bad Kyber size") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh.data(), dh.size());
        std::vector<uint8_t> short_ct(10, 0x03);
        envelope.set_kyber_ciphertext(short_ct.data(), short_ct.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        EcliptixError error{};
        const auto result = ecliptix_envelope_validate_hybrid_requirements(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            &error);

        REQUIRE(result == ECLIPTIX_ERROR_DECODE);
        REQUIRE(error.message != nullptr);
        ecliptix_error_free(&error);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API - Derive root from OPAQUE session key", "[c_api][boundary][opaque]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    uint8_t session_key[32] = {};
    for (size_t i = 0; i < sizeof(session_key); ++i) {
        session_key[i] = static_cast<uint8_t>(i + 1);
    }
    std::vector<uint8_t> context{0xAA, 0xBB, 0xCC};
    uint8_t root_key[32] = {};
    EcliptixError error{};

    SECTION("Succeeds with valid inputs") {
        const auto result = ecliptix_derive_root_from_opaque_session_key(
            session_key,
            sizeof(session_key),
            context.data(),
            context.size(),
            root_key,
            sizeof(root_key),
            &error);

        REQUIRE(result == ECLIPTIX_SUCCESS);
        bool any_non_zero = false;
        for (auto b : root_key) {
            any_non_zero = any_non_zero || (b != 0);
        }
        REQUIRE(any_non_zero);
    }

    SECTION("Rejects wrong session key length") {
        const auto result = ecliptix_derive_root_from_opaque_session_key(
            session_key,
            16,
            context.data(),
            context.size(),
            root_key,
            sizeof(root_key),
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_INVALID_INPUT);
        if (error.message) {
            ecliptix_error_free(&error);
        }
    }

    SECTION("Rejects empty context") {
        const auto result = ecliptix_derive_root_from_opaque_session_key(
            session_key,
            sizeof(session_key),
            nullptr,
            0,
            root_key,
            sizeof(root_key),
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_INVALID_INPUT);
        if (error.message) {
            ecliptix_error_free(&error);
        }
    }

    ecliptix_shutdown();
}

TEST_CASE("C API - Secret sharing", "[c_api][boundary][secret-sharing]") {
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

    SECTION("Split rejects null secret pointer") {
        EcliptixBuffer* shares = ecliptix_buffer_allocate(0);
        size_t share_length = 0;
        EcliptixError error{};

        const auto result = ecliptix_secret_sharing_split(
            nullptr,
            16,
            2,
            3,
            nullptr,
            0,
            shares,
            &share_length,
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) {
            ecliptix_error_free(&error);
        }
        ecliptix_buffer_free(shares);
    }

    SECTION("Split rejects empty secret") {
        std::vector<uint8_t> secret(16, 0x11);
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
        std::vector<uint8_t> secret(16, 0x22);
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
        std::vector<uint8_t> secret(32, 0x42);
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
        REQUIRE(share_length > 0);
        REQUIRE(shares->length == share_length * 5);

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

    SECTION("Roundtrip with auth") {
        std::vector<uint8_t> secret(32, 0x7A);
        std::vector<uint8_t> auth_key(32, 0xCC);
        EcliptixBuffer* shares = ecliptix_buffer_allocate(0);
        size_t share_length = 0;
        EcliptixError error{};

        auto result = ecliptix_secret_sharing_split(
            secret.data(),
            secret.size(),
            3,
            5,
            auth_key.data(),
            auth_key.size(),
            shares,
            &share_length,
            &error);
        REQUIRE(result == ECLIPTIX_SUCCESS);
        REQUIRE(shares->length == share_length * 5);

        EcliptixBuffer* out_secret = ecliptix_buffer_allocate(0);
        result = ecliptix_secret_sharing_reconstruct(
            shares->data,
            shares->length,
            share_length,
            5,
            auth_key.data(),
            auth_key.size(),
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

    SECTION("Reconstruct rejects wrong auth key") {
        std::vector<uint8_t> secret(16, 0x66);
        std::vector<uint8_t> auth_key(32, 0xEE);
        std::vector<uint8_t> other_key(32, 0xFF);
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
            other_key.data(),
            other_key.size(),
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
        std::vector<uint8_t> secret(16, 0x77);
        EcliptixBuffer* shares = ecliptix_buffer_allocate(0);
        size_t share_length = 0;
        std::vector<uint8_t> auth_key(31, 0x44);
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
        std::vector<uint8_t> secret(16, 0x88);
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

    SECTION("Reconstruct rejects zero share length or count") {
        std::vector<uint8_t> secret(16, 0x99);
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
            0,
            3,
            nullptr,
            0,
            out_secret,
            &error);
        REQUIRE(result == ECLIPTIX_ERROR_INVALID_INPUT);
        if (error.message) {
            ecliptix_error_free(&error);
        }

        result = ecliptix_secret_sharing_reconstruct(
            shares->data,
            shares->length,
            share_length,
            0,
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

    ecliptix_shutdown();
}
