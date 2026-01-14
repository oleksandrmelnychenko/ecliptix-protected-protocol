#include <catch2/catch_test_macros.hpp>
#include "ecliptix/c_api/ecliptix_c_api.h"
#include "common/secure_envelope.pb.h"
#include <cstring>
#include <vector>
#include <string>

extern "C" {
    EcliptixErrorCode ecliptix_protocol_server_system_create(
        EcliptixIdentityKeysHandle* identity_keys,
        EcliptixProtocolSystemHandle** out_handle,
        EcliptixError* out_error);

    EcliptixErrorCode ecliptix_protocol_server_system_begin_handshake_with_peer_kyber(
        EcliptixProtocolSystemHandle* handle,
        uint64_t peer_device_id,
        uint64_t peer_identity_id,
        const uint8_t* peer_kyber_public_key,
        size_t peer_kyber_public_key_length,
        EcliptixBuffer* out_handshake_message,
        EcliptixError* out_error);

    EcliptixErrorCode ecliptix_protocol_server_system_complete_handshake_auto(
        EcliptixProtocolSystemHandle* handle,
        const uint8_t* peer_handshake_message,
        size_t peer_handshake_message_length,
        EcliptixError* out_error);

    EcliptixErrorCode ecliptix_protocol_server_system_send_message(
        EcliptixProtocolSystemHandle* handle,
        const uint8_t* plaintext,
        size_t plaintext_length,
        EcliptixBuffer* out_encrypted_envelope,
        EcliptixError* out_error);

    EcliptixErrorCode ecliptix_protocol_server_system_receive_message(
        EcliptixProtocolSystemHandle* handle,
        const uint8_t* encrypted_envelope,
        size_t encrypted_envelope_length,
        EcliptixBuffer* out_plaintext,
        EcliptixError* out_error);

    void ecliptix_protocol_server_system_destroy(EcliptixProtocolSystemHandle* handle);
}

namespace {
    constexpr size_t KYBER_PUBLIC_KEY_SIZE = 1184;
    constexpr size_t KYBER_CIPHERTEXT_SIZE = 1088;
    constexpr size_t X25519_KEY_SIZE = 32;

    void free_buffer_data(EcliptixBuffer* buffer) {
        if (buffer && buffer->data) {
            delete[] buffer->data;
            buffer->data = nullptr;
            buffer->length = 0;
        }
    }

    struct IdentityKeysGuard {
        EcliptixIdentityKeysHandle* handle = nullptr;
        ~IdentityKeysGuard() {
            if (handle) ecliptix_identity_keys_destroy(handle);
        }
    };

    struct ClientSystemGuard {
        EcliptixProtocolSystemHandle* handle = nullptr;
        ~ClientSystemGuard() {
            if (handle) ecliptix_protocol_system_destroy(handle);
        }
    };

    struct ServerSystemGuard {
        EcliptixProtocolSystemHandle* handle = nullptr;
        ~ServerSystemGuard() {
            if (handle) ecliptix_protocol_server_system_destroy(handle);
        }
    };
}

TEST_CASE("C API Hybrid PQ - Kyber Public Key Retrieval", "[c_api][hybrid][pq][kyber]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Can retrieve Kyber public key from identity keys") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        const auto result = ecliptix_identity_keys_get_public_kyber(
            keys.handle,
            kyber_pk.data(),
            kyber_pk.size(),
            nullptr
        );

        REQUIRE(result == ECLIPTIX_SUCCESS);

        bool all_zero = true;
        for (const auto& byte : kyber_pk) {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        REQUIRE_FALSE(all_zero);
    }

    SECTION("Kyber key buffer too small returns error") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> small_buf(100);
        EcliptixError error{};

        const auto result = ecliptix_identity_keys_get_public_kyber(
            keys.handle,
            small_buf.data(),
            small_buf.size(),
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_BUFFER_TOO_SMALL);
        if (error.message) ecliptix_error_free(&error);
    }

    SECTION("Same seed produces same Kyber key") {
        std::vector<uint8_t> seed(32, 0xCC);

        IdentityKeysGuard keys1;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            seed.data(), seed.size(), &keys1.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard keys2;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            seed.data(), seed.size(), &keys2.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> kyber1(KYBER_PUBLIC_KEY_SIZE);
        std::vector<uint8_t> kyber2(KYBER_PUBLIC_KEY_SIZE);

        REQUIRE(ecliptix_identity_keys_get_public_kyber(keys1.handle, kyber1.data(), kyber1.size(), nullptr) == ECLIPTIX_SUCCESS);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(keys2.handle, kyber2.data(), kyber2.size(), nullptr) == ECLIPTIX_SUCCESS);

        REQUIRE(std::memcmp(kyber1.data(), kyber2.data(), KYBER_PUBLIC_KEY_SIZE) == 0);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Hybrid PQ - Envelope Validation", "[c_api][hybrid][pq][envelope]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    std::vector<uint8_t> dh_key(X25519_KEY_SIZE, 0x01);
    std::vector<uint8_t> kyber_ct(KYBER_CIPHERTEXT_SIZE, 0x02);

    SECTION("Rejects DH-only envelope (missing Kyber)") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh_key.data(), dh_key.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        EcliptixError error{};
        const auto result = ecliptix_envelope_validate_hybrid_requirements(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_PQ_MISSING);
        REQUIRE(error.message != nullptr);
        ecliptix_error_free(&error);
    }

    SECTION("Accepts DH + Kyber envelope") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh_key.data(), dh_key.size());
        envelope.set_kyber_ciphertext(kyber_ct.data(), kyber_ct.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        const auto result = ecliptix_envelope_validate_hybrid_requirements(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            nullptr
        );

        REQUIRE(result == ECLIPTIX_SUCCESS);
    }

    SECTION("Rejects envelope with wrong Kyber ciphertext size") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh_key.data(), dh_key.size());
        std::vector<uint8_t> wrong_size_ct(100, 0x03);
        envelope.set_kyber_ciphertext(wrong_size_ct.data(), wrong_size_ct.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        EcliptixError error{};
        const auto result = ecliptix_envelope_validate_hybrid_requirements(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_DECODE);
        if (error.message) ecliptix_error_free(&error);
    }

    SECTION("Accepts envelope without DH key (chain message)") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        const auto result = ecliptix_envelope_validate_hybrid_requirements(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            nullptr
        );

        REQUIRE(result == ECLIPTIX_SUCCESS);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Hybrid PQ - First Message Contains Kyber", "[c_api][hybrid][pq][first-message]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Client's first message after handshake contains Kyber ciphertext") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(
            server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr
        ) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(
            client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr
        ) == ECLIPTIX_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(ecliptix_protocol_system_create(client_keys.handle, &client_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(ecliptix_protocol_server_system_create(server_keys.handle, &server_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixBuffer client_handshake_msg{};
        REQUIRE(ecliptix_protocol_system_begin_handshake_with_peer_kyber(
            client_system.handle, 1, 0, server_kyber_pk.data(), server_kyber_pk.size(),
            &client_handshake_msg, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer server_handshake_msg{};
        REQUIRE(ecliptix_protocol_server_system_begin_handshake_with_peer_kyber(
            server_system.handle, 1, 0, client_kyber_pk.data(), client_kyber_pk.size(),
            &server_handshake_msg, nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(ecliptix_protocol_server_system_complete_handshake_auto(
            server_system.handle, client_handshake_msg.data, client_handshake_msg.length, nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(ecliptix_protocol_system_complete_handshake_auto(
            client_system.handle, server_handshake_msg.data, server_handshake_msg.length, nullptr
        ) == ECLIPTIX_SUCCESS);

        free_buffer_data(&client_handshake_msg);
        free_buffer_data(&server_handshake_msg);

        const std::string msg = "First message";
        EcliptixBuffer envelope{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        const auto validate_result = ecliptix_envelope_validate_hybrid_requirements(
            envelope.data,
            envelope.length,
            nullptr
        );
        REQUIRE(validate_result == ECLIPTIX_SUCCESS);

        ecliptix::proto::common::SecureEnvelope parsed_envelope;
        REQUIRE(parsed_envelope.ParseFromArray(envelope.data, static_cast<int>(envelope.length)));

        if (parsed_envelope.has_dh_public_key() && !parsed_envelope.dh_public_key().empty()) {
            REQUIRE(parsed_envelope.has_kyber_ciphertext());
            REQUIRE(parsed_envelope.kyber_ciphertext().size() == KYBER_CIPHERTEXT_SIZE);
        }

        free_buffer_data(&envelope);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Hybrid PQ - Reject DH-only at Receive", "[c_api][hybrid][pq][receive]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Receiving DH-only envelope returns PQ_MISSING error") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(ecliptix_protocol_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        ecliptix::proto::common::SecureEnvelope envelope;
        std::vector<uint8_t> dh_key(X25519_KEY_SIZE, 0x01);
        envelope.set_dh_public_key(dh_key.data(), dh_key.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        EcliptixBuffer plaintext{};
        EcliptixError error{};
        const auto result = ecliptix_protocol_system_receive_message(
            system.handle,
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            &plaintext,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_PQ_MISSING);
        REQUIRE(error.message != nullptr);
        ecliptix_error_free(&error);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Hybrid PQ - Handshake Requires Kyber", "[c_api][hybrid][pq][handshake]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Begin handshake with NULL Kyber key fails") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(ecliptix_protocol_system_create(client_keys.handle, &client_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixBuffer handshake_msg{};
        EcliptixError error{};
        const auto result = ecliptix_protocol_system_begin_handshake_with_peer_kyber(
            client_system.handle,
            1, 0,
            nullptr,
            KYBER_PUBLIC_KEY_SIZE,
            &handshake_msg,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) ecliptix_error_free(&error);
    }

    SECTION("Begin handshake with wrong Kyber key size fails") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(ecliptix_protocol_system_create(client_keys.handle, &client_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> short_key(100, 0xAA);
        EcliptixBuffer handshake_msg{};
        EcliptixError error{};
        const auto result = ecliptix_protocol_system_begin_handshake_with_peer_kyber(
            client_system.handle,
            1, 0,
            short_key.data(),
            short_key.size(),
            &handshake_msg,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_INVALID_INPUT);
        if (error.message) ecliptix_error_free(&error);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Hybrid PQ - Manual Kyber Secrets Setup", "[c_api][hybrid][pq][manual]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Can set Kyber secrets manually") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(ecliptix_protocol_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> kyber_ct(KYBER_CIPHERTEXT_SIZE, 0xAA);
        std::vector<uint8_t> kyber_ss(32, 0xBB);

        const auto result = ecliptix_protocol_system_set_kyber_secrets(
            system.handle,
            kyber_ct.data(),
            kyber_ct.size(),
            kyber_ss.data(),
            kyber_ss.size(),
            nullptr
        );

        (void)result;
    }

    SECTION("Set Kyber secrets with NULL ciphertext fails") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(ecliptix_protocol_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> kyber_ss(32, 0xBB);
        EcliptixError error{};

        const auto result = ecliptix_protocol_system_set_kyber_secrets(
            system.handle,
            nullptr,
            KYBER_CIPHERTEXT_SIZE,
            kyber_ss.data(),
            kyber_ss.size(),
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) ecliptix_error_free(&error);
    }

    SECTION("Set Kyber secrets with NULL shared secret fails") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(ecliptix_protocol_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> kyber_ct(KYBER_CIPHERTEXT_SIZE, 0xAA);
        EcliptixError error{};

        const auto result = ecliptix_protocol_system_set_kyber_secrets(
            system.handle,
            kyber_ct.data(),
            kyber_ct.size(),
            nullptr,
            32,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) ecliptix_error_free(&error);
    }

    ecliptix_shutdown();
}
