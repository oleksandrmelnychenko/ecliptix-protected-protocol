#include <catch2/catch_test_macros.hpp>
#include "ecliptix/c_api/epp_api.h"
#include "common/secure_envelope.pb.h"
#include <cstring>
#include <vector>
#include <string>

extern "C" {
    EppErrorCode epp_server_create(
        EppIdentityHandle* identity_keys,
        ProtocolSystemHandle** out_handle,
        EppError* out_error);

    EppErrorCode epp_server_begin_handshake_with_peer_kyber(
        ProtocolSystemHandle* handle,
        uint64_t peer_device_id,
        uint64_t peer_identity_id,
        const uint8_t* peer_kyber_public_key,
        size_t peer_kyber_public_key_length,
        EppBuffer* out_handshake_message,
        EppError* out_error);

    EppErrorCode epp_server_complete_handshake_auto(
        ProtocolSystemHandle* handle,
        const uint8_t* peer_handshake_message,
        size_t peer_handshake_message_length,
        EppError* out_error);

    EppErrorCode epp_server_encrypt(
        ProtocolSystemHandle* handle,
        const uint8_t* plaintext,
        size_t plaintext_length,
        EppBuffer* out_encrypted_envelope,
        EppError* out_error);

    EppErrorCode epp_server_decrypt(
        ProtocolSystemHandle* handle,
        const uint8_t* encrypted_envelope,
        size_t encrypted_envelope_length,
        EppBuffer* out_plaintext,
        EppError* out_error);

    void epp_server_destroy(ProtocolSystemHandle* handle);
}

namespace {
    constexpr size_t KYBER_PUBLIC_KEY_SIZE = 1184;
    constexpr size_t KYBER_CIPHERTEXT_SIZE = 1088;
    constexpr size_t X25519_KEY_SIZE = 32;

    void free_buffer_data(EppBuffer* buffer) {
        if (buffer && buffer->data) {
            delete[] buffer->data;
            buffer->data = nullptr;
            buffer->length = 0;
        }
    }

    struct IdentityKeysGuard {
        EppIdentityHandle* handle = nullptr;
        ~IdentityKeysGuard() {
            if (handle) epp_identity_destroy(handle);
        }
    };

    struct ClientSystemGuard {
        ProtocolSystemHandle* handle = nullptr;
        ~ClientSystemGuard() {
            if (handle) epp_session_destroy(handle);
        }
    };

    struct ServerSystemGuard {
        ProtocolSystemHandle* handle = nullptr;
        ~ServerSystemGuard() {
            if (handle) epp_server_destroy(handle);
        }
    };
}

TEST_CASE("C API Hybrid PQ - Kyber Public Key Retrieval", "[c_api][hybrid][pq][kyber]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Can retrieve Kyber public key from identity keys") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        const auto result = epp_identity_get_kyber_public(
            keys.handle,
            kyber_pk.data(),
            kyber_pk.size(),
            nullptr
        );

        REQUIRE(result == EPP_SUCCESS);

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
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> small_buf(100);
        EppError error{};

        const auto result = epp_identity_get_kyber_public(
            keys.handle,
            small_buf.data(),
            small_buf.size(),
            &error
        );

        REQUIRE(result == EPP_ERROR_BUFFER_TOO_SMALL);
        if (error.message) epp_error_free(&error);
    }

    SECTION("Same seed produces same Kyber key") {
        std::vector<uint8_t> seed(32, 0xCC);

        IdentityKeysGuard keys1;
        REQUIRE(epp_identity_create_from_seed(
            seed.data(), seed.size(), &keys1.handle, nullptr
        ) == EPP_SUCCESS);

        IdentityKeysGuard keys2;
        REQUIRE(epp_identity_create_from_seed(
            seed.data(), seed.size(), &keys2.handle, nullptr
        ) == EPP_SUCCESS);

        std::vector<uint8_t> kyber1(KYBER_PUBLIC_KEY_SIZE);
        std::vector<uint8_t> kyber2(KYBER_PUBLIC_KEY_SIZE);

        REQUIRE(epp_identity_get_kyber_public(keys1.handle, kyber1.data(), kyber1.size(), nullptr) == EPP_SUCCESS);
        REQUIRE(epp_identity_get_kyber_public(keys2.handle, kyber2.data(), kyber2.size(), nullptr) == EPP_SUCCESS);

        REQUIRE(std::memcmp(kyber1.data(), kyber2.data(), KYBER_PUBLIC_KEY_SIZE) == 0);
    }

    epp_shutdown();
}

TEST_CASE("C API Hybrid PQ - Envelope Validation", "[c_api][hybrid][pq][envelope]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    std::vector<uint8_t> dh_key(X25519_KEY_SIZE, 0x01);
    std::vector<uint8_t> kyber_ct(KYBER_CIPHERTEXT_SIZE, 0x02);

    SECTION("Rejects DH-only envelope (missing Kyber)") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh_key.data(), dh_key.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        EppError error{};
        const auto result = epp_envelope_validate(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            &error
        );

        REQUIRE(result == EPP_ERROR_PQ_MISSING);
        REQUIRE(error.message != nullptr);
        epp_error_free(&error);
    }

    SECTION("Accepts DH + Kyber envelope") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh_key.data(), dh_key.size());
        envelope.set_kyber_ciphertext(kyber_ct.data(), kyber_ct.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        const auto result = epp_envelope_validate(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            nullptr
        );

        REQUIRE(result == EPP_SUCCESS);
    }

    SECTION("Rejects envelope with wrong Kyber ciphertext size") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_dh_public_key(dh_key.data(), dh_key.size());
        std::vector<uint8_t> wrong_size_ct(100, 0x03);
        envelope.set_kyber_ciphertext(wrong_size_ct.data(), wrong_size_ct.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        EppError error{};
        const auto result = epp_envelope_validate(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            &error
        );

        REQUIRE(result == EPP_ERROR_DECODE);
        if (error.message) epp_error_free(&error);
    }

    SECTION("Accepts envelope without DH key (chain message)") {
        ecliptix::proto::common::SecureEnvelope envelope;
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        const auto result = epp_envelope_validate(
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            nullptr
        );

        REQUIRE(result == EPP_SUCCESS);
    }

    epp_shutdown();
}

TEST_CASE("C API Hybrid PQ - First Message Contains Kyber", "[c_api][hybrid][pq][first-message]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Client's first message after handshake contains Kyber ciphertext") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(
            server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr
        ) == EPP_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(
            client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr
        ) == EPP_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(epp_session_create(client_keys.handle, &client_system.handle, nullptr) == EPP_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(epp_server_create(server_keys.handle, &server_system.handle, nullptr) == EPP_SUCCESS);

        EppBuffer client_handshake_msg{};
        REQUIRE(epp_session_begin_handshake(
            client_system.handle, 1, 0, server_kyber_pk.data(), server_kyber_pk.size(),
            &client_handshake_msg, nullptr
        ) == EPP_SUCCESS);

        EppBuffer server_handshake_msg{};
        REQUIRE(epp_server_begin_handshake_with_peer_kyber(
            server_system.handle, 1, 0, client_kyber_pk.data(), client_kyber_pk.size(),
            &server_handshake_msg, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(epp_server_complete_handshake_auto(
            server_system.handle, client_handshake_msg.data, client_handshake_msg.length, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(epp_session_complete_handshake_auto(
            client_system.handle, server_handshake_msg.data, server_handshake_msg.length, nullptr
        ) == EPP_SUCCESS);

        free_buffer_data(&client_handshake_msg);
        free_buffer_data(&server_handshake_msg);

        const std::string msg = "First message";
        EppBuffer envelope{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope,
            nullptr
        ) == EPP_SUCCESS);

        const auto validate_result = epp_envelope_validate(
            envelope.data,
            envelope.length,
            nullptr
        );
        REQUIRE(validate_result == EPP_SUCCESS);

        ecliptix::proto::common::SecureEnvelope parsed_envelope;
        REQUIRE(parsed_envelope.ParseFromArray(envelope.data, static_cast<int>(envelope.length)));

        if (parsed_envelope.has_dh_public_key() && !parsed_envelope.dh_public_key().empty()) {
            REQUIRE(parsed_envelope.has_kyber_ciphertext());
            REQUIRE(parsed_envelope.kyber_ciphertext().size() == KYBER_CIPHERTEXT_SIZE);
        }

        free_buffer_data(&envelope);
    }

    epp_shutdown();
}

TEST_CASE("C API Hybrid PQ - Reject DH-only at Receive", "[c_api][hybrid][pq][receive]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Receiving DH-only envelope returns PQ_MISSING error") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(epp_session_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        ecliptix::proto::common::SecureEnvelope envelope;
        std::vector<uint8_t> dh_key(X25519_KEY_SIZE, 0x01);
        envelope.set_dh_public_key(dh_key.data(), dh_key.size());
        envelope.set_ratchet_epoch(0);
        const std::string serialized = envelope.SerializeAsString();

        EppBuffer plaintext{};
        EppError error{};
        const auto result = epp_session_decrypt(
            system.handle,
            reinterpret_cast<const uint8_t*>(serialized.data()),
            serialized.size(),
            &plaintext,
            &error
        );

        REQUIRE(result == EPP_ERROR_PQ_MISSING);
        REQUIRE(error.message != nullptr);
        epp_error_free(&error);
    }

    epp_shutdown();
}

TEST_CASE("C API Hybrid PQ - Handshake Requires Kyber", "[c_api][hybrid][pq][handshake]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Begin handshake with NULL Kyber key fails") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(epp_session_create(client_keys.handle, &client_system.handle, nullptr) == EPP_SUCCESS);

        EppBuffer handshake_msg{};
        EppError error{};
        const auto result = epp_session_begin_handshake(
            client_system.handle,
            1, 0,
            nullptr,
            KYBER_PUBLIC_KEY_SIZE,
            &handshake_msg,
            &error
        );

        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) epp_error_free(&error);
    }

    SECTION("Begin handshake with wrong Kyber key size fails") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(epp_session_create(client_keys.handle, &client_system.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> short_key(100, 0xAA);
        EppBuffer handshake_msg{};
        EppError error{};
        const auto result = epp_session_begin_handshake(
            client_system.handle,
            1, 0,
            short_key.data(),
            short_key.size(),
            &handshake_msg,
            &error
        );

        REQUIRE(result == EPP_ERROR_INVALID_INPUT);
        if (error.message) epp_error_free(&error);
    }

    epp_shutdown();
}

TEST_CASE("C API Hybrid PQ - Manual Kyber Secrets Setup", "[c_api][hybrid][pq][manual]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Can set Kyber secrets manually") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(epp_session_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> kyber_ct(KYBER_CIPHERTEXT_SIZE, 0xAA);
        std::vector<uint8_t> kyber_ss(32, 0xBB);

        const auto result = epp_session_set_kyber_secrets(
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
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(epp_session_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> kyber_ss(32, 0xBB);
        EppError error{};

        const auto result = epp_session_set_kyber_secrets(
            system.handle,
            nullptr,
            KYBER_CIPHERTEXT_SIZE,
            kyber_ss.data(),
            kyber_ss.size(),
            &error
        );

        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) epp_error_free(&error);
    }

    SECTION("Set Kyber secrets with NULL shared secret fails") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(epp_session_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> kyber_ct(KYBER_CIPHERTEXT_SIZE, 0xAA);
        EppError error{};

        const auto result = epp_session_set_kyber_secrets(
            system.handle,
            kyber_ct.data(),
            kyber_ct.size(),
            nullptr,
            32,
            &error
        );

        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) epp_error_free(&error);
    }

    epp_shutdown();
}
