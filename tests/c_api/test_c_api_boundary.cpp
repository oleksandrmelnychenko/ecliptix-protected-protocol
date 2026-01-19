#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>
#include "ecliptix/c_api/epp_api.h"
#include "common/secure_envelope.pb.h"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include <cstring>
#include <vector>
#include <thread>
#include <atomic>

TEST_CASE("C API - Initialization", "[c_api][boundary][init]") {
    SECTION("Initialize succeeds") {
        const EppErrorCode result = epp_init();
        REQUIRE(result == EPP_SUCCESS);
        epp_shutdown();
    }

    SECTION("Version string is valid") {
        const char* version = epp_version();
        REQUIRE(version != nullptr);
        REQUIRE(std::strlen(version) > 0);
        REQUIRE(std::strcmp(version, "1.0.0") == 0);
    }

    SECTION("Multiple initialize calls are safe") {
        REQUIRE(epp_init() == EPP_SUCCESS);
        REQUIRE(epp_init() == EPP_SUCCESS);
        epp_shutdown();
    }

    SECTION("Shutdown without initialize is safe") {
        epp_shutdown();
        epp_shutdown();
    }
}

TEST_CASE("C API - NULL Pointer Handling", "[c_api][boundary][null]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Identity keys create - NULL output handle") {
        const EppErrorCode result = epp_identity_create(
            nullptr,
            nullptr
        );
        REQUIRE(result == EPP_ERROR_NULL_POINTER);
    }

    SECTION("Identity keys create - NULL error output is safe") {
        EppIdentityHandle* handle = nullptr;
        const EppErrorCode result = epp_identity_create(
            &handle,
            nullptr
        );
        REQUIRE(result == EPP_SUCCESS);
        REQUIRE(handle != nullptr);
        epp_identity_destroy(handle);
    }

    SECTION("Identity keys create from seed - NULL seed") {
        EppIdentityHandle* handle = nullptr;
        EppError error{};
        const EppErrorCode result = epp_identity_create_from_seed(
            nullptr,
            32,
            &handle,
            &error
        );
        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) {
            epp_error_free(&error);
        }
    }

    SECTION("Identity keys create from seed - NULL output handle") {
        std::vector<uint8_t> seed(32, 0xAA);
        EppError error{};
        const EppErrorCode result = epp_identity_create_from_seed(
            seed.data(),
            seed.size(),
            nullptr,
            &error
        );
        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) {
            epp_error_free(&error);
        }
    }

    SECTION("Get public X25519 - NULL handle") {
        uint8_t key[32] = {};
        EppError error{};
        const EppErrorCode result = epp_identity_get_x25519_public(
            nullptr,
            key,
            32,
            &error
        );
        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) {
            epp_error_free(&error);
        }
    }

    SECTION("Get public X25519 - NULL output buffer") {
        EppIdentityHandle* handle = nullptr;
        REQUIRE(epp_identity_create(&handle, nullptr) == EPP_SUCCESS);

        EppError error{};
        const EppErrorCode result = epp_identity_get_x25519_public(
            handle,
            nullptr,
            32,
            &error
        );
        REQUIRE(result == EPP_ERROR_NULL_POINTER);

        epp_identity_destroy(handle);
        if (error.message) {
            epp_error_free(&error);
        }
    }

    SECTION("Get public Ed25519 - NULL handle") {
        uint8_t key[32] = {};
        EppError error{};
        const EppErrorCode result = epp_identity_get_ed25519_public(
            nullptr,
            key,
            32,
            &error
        );
        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) {
            epp_error_free(&error);
        }
    }

    SECTION("Get public Ed25519 - NULL output buffer") {
        EppIdentityHandle* handle = nullptr;
        REQUIRE(epp_identity_create(&handle, nullptr) == EPP_SUCCESS);

        EppError error{};
        const EppErrorCode result = epp_identity_get_ed25519_public(
            handle,
            nullptr,
            32,
            &error
        );
        REQUIRE(result == EPP_ERROR_NULL_POINTER);

        epp_identity_destroy(handle);
        if (error.message) {
            epp_error_free(&error);
        }
    }

    SECTION("Protocol system create - NULL identity keys") {
        ProtocolSystemHandle* system = nullptr;
        EppError error{};
        const EppErrorCode result = epp_session_create(
            nullptr,
            &system,
            &error
        );
        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) {
            epp_error_free(&error);
        }
    }

    SECTION("Protocol system create - NULL output handle") {
        EppIdentityHandle* keys = nullptr;
        REQUIRE(epp_identity_create(&keys, nullptr) == EPP_SUCCESS);

        EppError error{};
        const EppErrorCode result = epp_session_create(
            keys,
            nullptr,
            &error
        );
        REQUIRE(result == EPP_ERROR_NULL_POINTER);

        epp_identity_destroy(keys);
        if (error.message) {
            epp_error_free(&error);
        }
    }

    SECTION("Destroy NULL handles is safe") {
        epp_identity_destroy(nullptr);
        epp_session_destroy(nullptr);
    }

    epp_shutdown();
}

TEST_CASE("C API - Buffer Size Validation", "[c_api][boundary][buffer]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Identity keys from seed - invalid seed size") {
        std::vector<uint8_t> seed(16, 0xAA);
        EppIdentityHandle* handle = nullptr;
        EppError error{};

        const EppErrorCode result = epp_identity_create_from_seed(
            seed.data(),
            seed.size(),
            &handle,
            &error
        );

        REQUIRE(result == EPP_ERROR_INVALID_INPUT);
        REQUIRE(error.message != nullptr);
        REQUIRE(std::strstr(error.message, "32 bytes") != nullptr);
        epp_error_free(&error);
    }

    SECTION("Identity keys from seed - zero size") {
        std::vector<uint8_t> seed(32, 0xAA);
        EppIdentityHandle* handle = nullptr;
        EppError error{};

        const EppErrorCode result = epp_identity_create_from_seed(
            seed.data(),
            0,
            &handle,
            &error
        );

        REQUIRE(result == EPP_ERROR_INVALID_INPUT);
        epp_error_free(&error);
    }

    SECTION("Get public X25519 - buffer too small") {
        EppIdentityHandle* handle = nullptr;
        REQUIRE(epp_identity_create(&handle, nullptr) == EPP_SUCCESS);

        uint8_t key[16] = {};
        EppError error{};
        const EppErrorCode result = epp_identity_get_x25519_public(
            handle,
            key,
            16,
            &error
        );

        REQUIRE(result == EPP_ERROR_BUFFER_TOO_SMALL);
        REQUIRE(error.message != nullptr);

        epp_identity_destroy(handle);
        epp_error_free(&error);
    }

    SECTION("Get public Ed25519 - buffer too small") {
        EppIdentityHandle* handle = nullptr;
        REQUIRE(epp_identity_create(&handle, nullptr) == EPP_SUCCESS);

        uint8_t key[16] = {};
        EppError error{};
        const EppErrorCode result = epp_identity_get_ed25519_public(
            handle,
            key,
            16,
            &error
        );

        REQUIRE(result == EPP_ERROR_BUFFER_TOO_SMALL);
        REQUIRE(error.message != nullptr);

        epp_identity_destroy(handle);
        epp_error_free(&error);
    }

    SECTION("Get public X25519 - exact size succeeds") {
        EppIdentityHandle* handle = nullptr;
        REQUIRE(epp_identity_create(&handle, nullptr) == EPP_SUCCESS);

        uint8_t key[32] = {};
        const EppErrorCode result = epp_identity_get_x25519_public(
            handle,
            key,
            32,
            nullptr
        );

        REQUIRE(result == EPP_SUCCESS);

        bool all_zero = true;
        for (int i = 0; i < 32; ++i) {
            if (key[i] != 0) {
                all_zero = false;
                break;
            }
        }
        REQUIRE_FALSE(all_zero);

        epp_identity_destroy(handle);
    }

    SECTION("Get public Ed25519 - exact size succeeds") {
        EppIdentityHandle* handle = nullptr;
        REQUIRE(epp_identity_create(&handle, nullptr) == EPP_SUCCESS);

        uint8_t key[32] = {};
        const EppErrorCode result = epp_identity_get_ed25519_public(
            handle,
            key,
            32,
            nullptr
        );

        REQUIRE(result == EPP_SUCCESS);

        bool all_zero = true;
        for (int i = 0; i < 32; ++i) {
            if (key[i] != 0) {
                all_zero = false;
                break;
            }
        }
        REQUIRE_FALSE(all_zero);

        epp_identity_destroy(handle);
    }

    epp_shutdown();
}

TEST_CASE("C API - Error Propagation", "[c_api][boundary][error]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Error codes are distinct") {
        REQUIRE(EPP_SUCCESS == 0);
        REQUIRE(EPP_ERROR_GENERIC != EPP_SUCCESS);
        REQUIRE(EPP_ERROR_INVALID_INPUT != EPP_SUCCESS);
        REQUIRE(EPP_ERROR_KEY_GENERATION != EPP_ERROR_DERIVE_KEY);
    }

    SECTION("Error code to string") {
        REQUIRE(std::strcmp(epp_error_string(EPP_SUCCESS), "Success") == 0);
        REQUIRE(std::strcmp(epp_error_string(EPP_ERROR_GENERIC), "Generic error") == 0);
        REQUIRE(std::strcmp(epp_error_string(EPP_ERROR_NULL_POINTER), "Null pointer") == 0);
        REQUIRE(std::strcmp(epp_error_string(EPP_ERROR_BUFFER_TOO_SMALL), "Buffer too small") == 0);
        REQUIRE(std::strcmp(epp_error_string(EPP_ERROR_ENCODE), "Encoding failed") == 0);
    }

    SECTION("Error message allocation and cleanup") {
        std::vector<uint8_t> seed(16, 0xAA);
        EppIdentityHandle* handle = nullptr;
        EppError error{};
        error.message = nullptr;

        epp_identity_create_from_seed(
            seed.data(),
            seed.size(),
            &handle,
            &error
        );

        REQUIRE(error.code == EPP_ERROR_INVALID_INPUT);
        REQUIRE(error.message != nullptr);
        REQUIRE(std::strlen(error.message) > 0);

        epp_error_free(&error);
        REQUIRE(error.message == nullptr);
    }

    SECTION("Error free on NULL is safe") {
        EppError error{};
        error.message = nullptr;
        epp_error_free(&error);
        epp_error_free(nullptr);
    }

    SECTION("Error free multiple times is safe") {
        std::vector<uint8_t> seed(16, 0xAA);
        EppIdentityHandle* handle = nullptr;
        EppError error{};

        epp_identity_create_from_seed(
            seed.data(),
            seed.size(),
            &handle,
            &error
        );

        epp_error_free(&error);
        epp_error_free(&error);
    }

    epp_shutdown();
}

TEST_CASE("C API - Memory Management", "[c_api][boundary][memory]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Identity keys lifecycle") {
        EppIdentityHandle* handle = nullptr;
        REQUIRE(epp_identity_create(&handle, nullptr) == EPP_SUCCESS);
        REQUIRE(handle != nullptr);

        epp_identity_destroy(handle);
    }

    SECTION("Multiple identity keys") {
        constexpr int count = 10;
        EppIdentityHandle* handles[count] = {};

        for (int i = 0; i < count; ++i) {
            REQUIRE(epp_identity_create(&handles[i], nullptr) == EPP_SUCCESS);
            REQUIRE(handles[i] != nullptr);
        }

        for (int i = 0; i < count; ++i) {
            epp_identity_destroy(handles[i]);
        }
    }

    SECTION("Buffer allocation and cleanup") {
        EppBuffer* buffer = epp_buffer_alloc(1024);
        REQUIRE(buffer != nullptr);
        REQUIRE(buffer->data != nullptr);
        REQUIRE(buffer->length == 1024);

        epp_buffer_free(buffer);
    }

    SECTION("Buffer allocation - zero size") {
        EppBuffer* buffer = epp_buffer_alloc(0);
        REQUIRE(buffer != nullptr);
        REQUIRE(buffer->data == nullptr);
        REQUIRE(buffer->length == 0);

        epp_buffer_free(buffer);
    }

    SECTION("Buffer free NULL is safe") {
        epp_buffer_free(nullptr);
    }

    SECTION("Secure wipe") {
        std::vector<uint8_t> data(256, 0xAA);

        const EppErrorCode result = epp_secure_wipe(data.data(), data.size());
        REQUIRE(result == EPP_SUCCESS);

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
        const EppErrorCode result = epp_secure_wipe(nullptr, 0);
        REQUIRE(result == EPP_SUCCESS);
    }

    SECTION("Secure wipe - NULL with non-zero length fails") {
        const EppErrorCode result = epp_secure_wipe(nullptr, 100);
        REQUIRE(result == EPP_ERROR_NULL_POINTER);
    }

    epp_shutdown();
}

TEST_CASE("C API - Protocol System Lifecycle", "[c_api][boundary][protocol]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Create protocol system") {
        EppIdentityHandle* keys = nullptr;
        REQUIRE(epp_identity_create(&keys, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* system = nullptr;
        const EppErrorCode result = epp_session_create(
            keys,
            &system,
            nullptr
        );

        REQUIRE(result == EPP_SUCCESS);
        REQUIRE(system != nullptr);

        epp_session_destroy(system);
        epp_identity_destroy(keys);
    }

    SECTION("Set callbacks - NULL callback") {
        EppIdentityHandle* keys = nullptr;
        REQUIRE(epp_identity_create(&keys, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* system = nullptr;
        REQUIRE(epp_session_create(keys, &system, nullptr) == EPP_SUCCESS);

        EppCallbacks callbacks{};
        callbacks.on_protocol_state_changed = nullptr;
        callbacks.user_data = nullptr;

        const EppErrorCode result = epp_session_set_callbacks(
            system,
            &callbacks,
            nullptr
        );

        REQUIRE(result == EPP_SUCCESS);

        epp_session_destroy(system);
        epp_identity_destroy(keys);
    }

    SECTION("Set callbacks - NULL callbacks struct") {
        EppIdentityHandle* keys = nullptr;
        REQUIRE(epp_identity_create(&keys, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* system = nullptr;
        REQUIRE(epp_session_create(keys, &system, nullptr) == EPP_SUCCESS);

        const EppErrorCode result = epp_session_set_callbacks(
            system,
            nullptr,
            nullptr
        );

        REQUIRE(result == EPP_SUCCESS);

        epp_session_destroy(system);
        epp_identity_destroy(keys);
    }

    SECTION("Set callbacks - NULL system handle") {
        EppCallbacks callbacks{};
        EppError error{};

        const EppErrorCode result = epp_session_set_callbacks(
            nullptr,
            &callbacks,
            &error
        );

        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) {
            epp_error_free(&error);
        }
    }

    epp_shutdown();
}

TEST_CASE("C API - Thread Safety", "[c_api][boundary][thread]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Concurrent identity key creation") {
        constexpr int thread_count = 10;
        constexpr int iterations = 5;
        std::atomic<int> success_count{0};

        std::vector<std::thread> threads;
        threads.reserve(thread_count);

        for (int t = 0; t < thread_count; ++t) {
            threads.emplace_back([&success_count]() {
                for (int i = 0; i < iterations; ++i) {
                    EppIdentityHandle* handle = nullptr;
                    if (epp_identity_create(&handle, nullptr) == EPP_SUCCESS) {
                        success_count.fetch_add(1, std::memory_order_relaxed);
                        epp_identity_destroy(handle);
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
                    EppBuffer* buffer = epp_buffer_alloc(1024);
                    if (buffer != nullptr) {
                        success_count.fetch_add(1, std::memory_order_relaxed);
                        epp_buffer_free(buffer);
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(success_count.load() == thread_count * iterations);
    }

    epp_shutdown();
}

TEST_CASE("C API - Deterministic Key Generation from Seed", "[c_api][boundary][deterministic]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Same seed produces same keys") {
        std::vector<uint8_t> seed(32, 0xBB);

        EppIdentityHandle* handle1 = nullptr;
        REQUIRE(epp_identity_create_from_seed(
            seed.data(),
            seed.size(),
            &handle1,
            nullptr
        ) == EPP_SUCCESS);

        uint8_t x25519_key1[32] = {};
        REQUIRE(epp_identity_get_x25519_public(
            handle1,
            x25519_key1,
            32,
            nullptr
        ) == EPP_SUCCESS);

        EppIdentityHandle* handle2 = nullptr;
        REQUIRE(epp_identity_create_from_seed(
            seed.data(),
            seed.size(),
            &handle2,
            nullptr
        ) == EPP_SUCCESS);

        uint8_t x25519_key2[32] = {};
        REQUIRE(epp_identity_get_x25519_public(
            handle2,
            x25519_key2,
            32,
            nullptr
        ) == EPP_SUCCESS);

        REQUIRE(std::memcmp(x25519_key1, x25519_key2, 32) == 0);

        epp_identity_destroy(handle1);
        epp_identity_destroy(handle2);
    }

    SECTION("Different seeds produce different keys") {
        std::vector<uint8_t> seed1(32, 0xAA);
        std::vector<uint8_t> seed2(32, 0xBB);

        EppIdentityHandle* handle1 = nullptr;
        REQUIRE(epp_identity_create_from_seed(
            seed1.data(),
            seed1.size(),
            &handle1,
            nullptr
        ) == EPP_SUCCESS);

        uint8_t x25519_key1[32] = {};
        REQUIRE(epp_identity_get_x25519_public(
            handle1,
            x25519_key1,
            32,
            nullptr
        ) == EPP_SUCCESS);

        EppIdentityHandle* handle2 = nullptr;
        REQUIRE(epp_identity_create_from_seed(
            seed2.data(),
            seed2.size(),
            &handle2,
            nullptr
        ) == EPP_SUCCESS);

        uint8_t x25519_key2[32] = {};
        REQUIRE(epp_identity_get_x25519_public(
            handle2,
            x25519_key2,
            32,
            nullptr
        ) == EPP_SUCCESS);

        REQUIRE(std::memcmp(x25519_key1, x25519_key2, 32) != 0);

        epp_identity_destroy(handle1);
        epp_identity_destroy(handle2);
    }

    epp_shutdown();
}

TEST_CASE("C API - Hybrid ratchet requires Kyber ciphertext with DH", "[c_api][boundary][hybrid][pq]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    EppIdentityHandle* keys = nullptr;
    REQUIRE(epp_identity_create(&keys, nullptr) == EPP_SUCCESS);

    ProtocolSystemHandle* system = nullptr;
    REQUIRE(epp_session_create(keys, &system, nullptr) == EPP_SUCCESS);

    ecliptix::proto::common::SecureEnvelope envelope;
    std::vector<uint8_t> dh(ecliptix::protocol::kX25519PublicKeyBytes, 0x01);
    envelope.set_dh_public_key(dh.data(), dh.size());
    envelope.set_ratchet_epoch(0);
    const std::string serialized = envelope.SerializeAsString();

    EppBuffer plaintext{};
    EppError error{};
    const auto result = epp_session_decrypt(
        system,
        reinterpret_cast<const uint8_t*>(serialized.data()),
        serialized.size(),
        &plaintext,
        &error);

    REQUIRE(result == EPP_ERROR_PQ_MISSING);
    REQUIRE(error.message != nullptr);
    epp_error_free(&error);

    epp_session_destroy(system);
    epp_identity_destroy(keys);
    epp_shutdown();
}

TEST_CASE("C API - Envelope validation prefilter enforces hybrid ciphertext", "[c_api][boundary][hybrid][pq]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    std::vector<uint8_t> dh(ecliptix::protocol::kX25519PublicKeyBytes, 0x01);
    std::vector<uint8_t> kyber(ecliptix::protocol::crypto::KyberInterop::KYBER_768_CIPHERTEXT_SIZE, 0x02);

    SECTION("Rejects DH without Kyber") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh.data(), dh.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        EppError error{};
        const auto result = epp_envelope_validate(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            &error);

        REQUIRE(result == EPP_ERROR_PQ_MISSING);
        REQUIRE(error.message != nullptr);
        epp_error_free(&error);
    }

    SECTION("Accepts DH with Kyber") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh.data(), dh.size());
        envelope.set_kyber_ciphertext(kyber.data(), kyber.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        const auto result = epp_envelope_validate(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            nullptr);

        REQUIRE(result == EPP_SUCCESS);
    }

    SECTION("Rejects bad Kyber size") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh.data(), dh.size());
        std::vector<uint8_t> short_ct(10, 0x03);
        envelope.set_kyber_ciphertext(short_ct.data(), short_ct.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        EppError error{};
        const auto result = epp_envelope_validate(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            &error);

        REQUIRE(result == EPP_ERROR_DECODE);
        REQUIRE(error.message != nullptr);
        epp_error_free(&error);
    }

    epp_shutdown();
}

TEST_CASE("C API - Derive root from OPAQUE session key", "[c_api][boundary][opaque]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    uint8_t session_key[32] = {};
    for (size_t i = 0; i < sizeof(session_key); ++i) {
        session_key[i] = static_cast<uint8_t>(i + 1);
    }
    std::vector<uint8_t> context{0xAA, 0xBB, 0xCC};
    uint8_t root_key[32] = {};
    EppError error{};

    SECTION("Succeeds with valid inputs") {
        const auto result = epp_derive_root_key(
            session_key,
            sizeof(session_key),
            context.data(),
            context.size(),
            root_key,
            sizeof(root_key),
            &error);

        REQUIRE(result == EPP_SUCCESS);
        bool any_non_zero = false;
        for (auto b : root_key) {
            any_non_zero = any_non_zero || (b != 0);
        }
        REQUIRE(any_non_zero);
    }

    SECTION("Rejects wrong session key length") {
        const auto result = epp_derive_root_key(
            session_key,
            16,
            context.data(),
            context.size(),
            root_key,
            sizeof(root_key),
            &error);
        REQUIRE(result == EPP_ERROR_INVALID_INPUT);
        if (error.message) {
            epp_error_free(&error);
        }
    }

    SECTION("Rejects empty context") {
        const auto result = epp_derive_root_key(
            session_key,
            sizeof(session_key),
            nullptr,
            0,
            root_key,
            sizeof(root_key),
            &error);
        REQUIRE(result == EPP_ERROR_INVALID_INPUT);
        if (error.message) {
            epp_error_free(&error);
        }
    }

    epp_shutdown();
}

TEST_CASE("C API - Secret sharing", "[c_api][boundary][secret-sharing]") {
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

    SECTION("Split rejects null secret pointer") {
        EppBuffer* shares = epp_buffer_alloc(0);
        size_t share_length = 0;
        EppError error{};

        const auto result = epp_shamir_split(
            nullptr,
            16,
            2,
            3,
            nullptr,
            0,
            shares,
            &share_length,
            &error);
        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) {
            epp_error_free(&error);
        }
        epp_buffer_free(shares);
    }

    SECTION("Split rejects empty secret") {
        std::vector<uint8_t> secret(16, 0x11);
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
        std::vector<uint8_t> secret(16, 0x22);
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
        std::vector<uint8_t> secret(32, 0x42);
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
        REQUIRE(share_length > 0);
        REQUIRE(shares->length == share_length * 5);

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

    SECTION("Roundtrip with auth") {
        std::vector<uint8_t> secret(32, 0x7A);
        std::vector<uint8_t> auth_key(32, 0xCC);
        EppBuffer* shares = epp_buffer_alloc(0);
        size_t share_length = 0;
        EppError error{};

        auto result = epp_shamir_split(
            secret.data(),
            secret.size(),
            3,
            5,
            auth_key.data(),
            auth_key.size(),
            shares,
            &share_length,
            &error);
        REQUIRE(result == EPP_SUCCESS);
        REQUIRE(shares->length == share_length * 5);

        EppBuffer* out_secret = epp_buffer_alloc(0);
        result = epp_shamir_reconstruct(
            shares->data,
            shares->length,
            share_length,
            5,
            auth_key.data(),
            auth_key.size(),
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

    SECTION("Reconstruct rejects wrong auth key") {
        std::vector<uint8_t> secret(16, 0x66);
        std::vector<uint8_t> auth_key(32, 0xEE);
        std::vector<uint8_t> other_key(32, 0xFF);
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
            other_key.data(),
            other_key.size(),
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
        std::vector<uint8_t> secret(16, 0x77);
        EppBuffer* shares = epp_buffer_alloc(0);
        size_t share_length = 0;
        std::vector<uint8_t> auth_key(31, 0x44);
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
        std::vector<uint8_t> secret(16, 0x88);
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

    SECTION("Reconstruct rejects zero share length or count") {
        std::vector<uint8_t> secret(16, 0x99);
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
            0,
            3,
            nullptr,
            0,
            out_secret,
            &error);
        REQUIRE(result == EPP_ERROR_INVALID_INPUT);
        if (error.message) {
            epp_error_free(&error);
        }

        result = epp_shamir_reconstruct(
            shares->data,
            shares->length,
            share_length,
            0,
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

    epp_shutdown();
}
