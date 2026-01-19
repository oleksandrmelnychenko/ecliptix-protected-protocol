#include <catch2/catch_test_macros.hpp>
#include "ecliptix/c_api/epp_api.h"
#include <cstring>
#include <vector>
#include <string>

extern "C" {
    EppErrorCode epp_server_create(
        EppIdentityHandle* identity_keys,
        ProtocolSystemHandle** out_handle,
        EppError* out_error);

    EppErrorCode epp_server_begin_handshake(
        ProtocolSystemHandle* handle,
        uint32_t connection_id,
        uint8_t exchange_type,
        const uint8_t* kyber_remote_public,
        size_t kyber_remote_public_length,
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

    EppErrorCode epp_server_is_established(
        const ProtocolSystemHandle* handle,
        bool* out_has_connection,
        EppError* out_error);

    EppErrorCode epp_server_get_id(
        const ProtocolSystemHandle* handle,
        uint32_t* out_connection_id,
        EppError* out_error);

    EppErrorCode epp_server_get_chain_indices(
        const ProtocolSystemHandle* handle,
        uint32_t* out_sending_index,
        uint32_t* out_receiving_index,
        EppError* out_error);

    void epp_server_destroy(ProtocolSystemHandle* handle);
}

namespace {
    constexpr size_t KYBER_PUBLIC_KEY_SIZE = 1184;
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
            if (handle) {
                epp_identity_destroy(handle);
            }
        }
    };

    struct ClientSystemGuard {
        ProtocolSystemHandle* handle = nullptr;

        ~ClientSystemGuard() {
            if (handle) {
                epp_session_destroy(handle);
            }
        }
    };

    struct ServerSystemGuard {
        ProtocolSystemHandle* handle = nullptr;

        ~ServerSystemGuard() {
            if (handle) {
                epp_server_destroy(handle);
            }
        }
    };

    struct BufferGuard {
        EppBuffer* buffer = nullptr;

        explicit BufferGuard(EppBuffer* buf = nullptr) : buffer(buf) {}
        ~BufferGuard() {
            if (buffer) {
                epp_buffer_free(buffer);
            }
        }
    };

    bool PerformTwoWayHandshake(
        const std::vector<uint8_t>& client_kyber_pk,
        const std::vector<uint8_t>& server_kyber_pk,
        ProtocolSystemHandle* client_system,
        ProtocolSystemHandle* server_system,
        uint64_t connection_id = 1
    ) {
        EppError error{};

        EppBuffer client_handshake_msg{};
        auto result = epp_session_begin_handshake(
            client_system, connection_id, 0, server_kyber_pk.data(), server_kyber_pk.size(),
            &client_handshake_msg, &error
        );
        if (result != EPP_SUCCESS) {
            if (error.message) epp_error_free(&error);
            return false;
        }

        EppBuffer server_handshake_msg{};
        result = epp_server_begin_handshake(
            server_system, connection_id, 0, client_kyber_pk.data(), client_kyber_pk.size(),
            &server_handshake_msg, &error
        );
        if (result != EPP_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            if (error.message) epp_error_free(&error);
            return false;
        }

        result = epp_server_complete_handshake_auto(
            server_system, client_handshake_msg.data, client_handshake_msg.length, &error
        );
        if (result != EPP_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            free_buffer_data(&server_handshake_msg);
            if (error.message) epp_error_free(&error);
            return false;
        }

        result = epp_session_complete_handshake_auto(
            client_system, server_handshake_msg.data, server_handshake_msg.length, &error
        );
        if (result != EPP_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            free_buffer_data(&server_handshake_msg);
            if (error.message) epp_error_free(&error);
            return false;
        }

        free_buffer_data(&client_handshake_msg);
        free_buffer_data(&server_handshake_msg);
        return true;
    }
}

TEST_CASE("C API E2E - Full Handshake Flow", "[c_api][e2e][handshake]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Client initiates handshake with server, bidirectional messaging works") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(
            server_keys.handle,
            server_kyber_pk.data(),
            server_kyber_pk.size(),
            nullptr
        ) == EPP_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(
            client_keys.handle,
            client_kyber_pk.data(),
            client_kyber_pk.size(),
            nullptr
        ) == EPP_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(epp_session_create(
            client_keys.handle,
            &client_system.handle,
            nullptr
        ) == EPP_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(epp_server_create(
            server_keys.handle,
            &server_system.handle,
            nullptr
        ) == EPP_SUCCESS);

        EppError error{};

        EppBuffer client_handshake_msg{};
        auto result = epp_session_begin_handshake(
            client_system.handle,
            1,
            0,
            server_kyber_pk.data(),
            server_kyber_pk.size(),
            &client_handshake_msg,
            &error
        );
        if (result != EPP_SUCCESS) {
            INFO("Client begin handshake failed: " << (error.message ? error.message : "unknown"));
            if (error.message) epp_error_free(&error);
        }
        REQUIRE(result == EPP_SUCCESS);
        REQUIRE(client_handshake_msg.data != nullptr);
        REQUIRE(client_handshake_msg.length > 0);

        EppBuffer server_handshake_msg{};
        result = epp_server_begin_handshake(
            server_system.handle,
            1,
            0,
            client_kyber_pk.data(),
            client_kyber_pk.size(),
            &server_handshake_msg,
            &error
        );
        if (result != EPP_SUCCESS) {
            INFO("Server begin handshake failed: " << (error.message ? error.message : "unknown"));
            if (error.message) epp_error_free(&error);
        }
        REQUIRE(result == EPP_SUCCESS);
        REQUIRE(server_handshake_msg.data != nullptr);
        REQUIRE(server_handshake_msg.length > 0);

        result = epp_server_complete_handshake_auto(
            server_system.handle,
            client_handshake_msg.data,
            client_handshake_msg.length,
            &error
        );
        if (result != EPP_SUCCESS) {
            INFO("Server complete handshake failed: " << (error.message ? error.message : "unknown"));
            if (error.message) epp_error_free(&error);
        }
        REQUIRE(result == EPP_SUCCESS);

        result = epp_session_complete_handshake_auto(
            client_system.handle,
            server_handshake_msg.data,
            server_handshake_msg.length,
            &error
        );
        if (result != EPP_SUCCESS) {
            INFO("Client complete handshake failed: " << (error.message ? error.message : "unknown"));
            if (error.message) epp_error_free(&error);
        }
        REQUIRE(result == EPP_SUCCESS);

        free_buffer_data(&client_handshake_msg);
        free_buffer_data(&server_handshake_msg);

        bool client_has_conn = false;
        bool server_has_conn = false;
        REQUIRE(epp_session_is_established(
            client_system.handle, &client_has_conn, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(epp_server_is_established(
            server_system.handle, &server_has_conn, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(client_has_conn);
        REQUIRE(server_has_conn);

        const std::string client_msg = "Hello from client via C API!";
        EppBuffer client_envelope{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(client_msg.data()),
            client_msg.size(),
            &client_envelope,
            nullptr
        ) == EPP_SUCCESS);
        REQUIRE(client_envelope.data != nullptr);
        REQUIRE(client_envelope.length > client_msg.size());

        EppBuffer server_plaintext{};
        REQUIRE(epp_server_decrypt(
            server_system.handle,
            client_envelope.data,
            client_envelope.length,
            &server_plaintext,
            nullptr
        ) == EPP_SUCCESS);
        REQUIRE(server_plaintext.data != nullptr);
        REQUIRE(server_plaintext.length == client_msg.size());
        REQUIRE(std::memcmp(server_plaintext.data, client_msg.data(), client_msg.size()) == 0);

        free_buffer_data(&client_envelope);
        free_buffer_data(&server_plaintext);

        const std::string server_msg = "Hello from server via C API!";
        EppBuffer server_envelope{};
        REQUIRE(epp_server_encrypt(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(server_msg.data()),
            server_msg.size(),
            &server_envelope,
            nullptr
        ) == EPP_SUCCESS);

        EppBuffer client_plaintext{};
        REQUIRE(epp_session_decrypt(
            client_system.handle,
            server_envelope.data,
            server_envelope.length,
            &client_plaintext,
            nullptr
        ) == EPP_SUCCESS);
        REQUIRE(client_plaintext.length == server_msg.size());
        REQUIRE(std::memcmp(client_plaintext.data, server_msg.data(), server_msg.size()) == 0);

        free_buffer_data(&server_envelope);
        free_buffer_data(&client_plaintext);
    }

    epp_shutdown();
}

TEST_CASE("C API E2E - Sequential Messages", "[c_api][e2e][messaging]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Multiple sequential messages in same direction") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) == EPP_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(epp_session_create(client_keys.handle, &client_system.handle, nullptr) == EPP_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(epp_server_create(server_keys.handle, &server_system.handle, nullptr) == EPP_SUCCESS);

        REQUIRE(PerformTwoWayHandshake(client_kyber_pk, server_kyber_pk, client_system.handle, server_system.handle));

        constexpr int message_count = 50;
        for (int i = 0; i < message_count; ++i) {
            std::string msg = "Message " + std::to_string(i) + " from client";

            EppBuffer envelope{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope,
                nullptr
            ) == EPP_SUCCESS);

            EppBuffer plaintext{};
            const auto recv_result = epp_server_decrypt(
                server_system.handle,
                envelope.data,
                envelope.length,
                &plaintext,
                nullptr
            );
            REQUIRE(recv_result == EPP_SUCCESS);
            REQUIRE(plaintext.length == msg.size());
            REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        uint32_t client_send_idx = 0, client_recv_idx = 0;
        uint32_t server_send_idx = 0, server_recv_idx = 0;

        REQUIRE(epp_session_get_chain_indices(
            client_system.handle, &client_send_idx, &client_recv_idx, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(epp_server_get_chain_indices(
            server_system.handle, &server_send_idx, &server_recv_idx, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(client_send_idx == message_count);
        REQUIRE(server_recv_idx == message_count);
    }

    epp_shutdown();
}

TEST_CASE("C API E2E - Deterministic Handshake from Seed", "[c_api][e2e][deterministic]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Same seeds produce reproducible sessions") {
        std::vector<uint8_t> client_seed(32, 0xAA);
        std::vector<uint8_t> server_seed(32, 0xBB);

        IdentityKeysGuard client_keys1;
        REQUIRE(epp_identity_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys1.handle, nullptr
        ) == EPP_SUCCESS);

        IdentityKeysGuard server_keys1;
        REQUIRE(epp_identity_create_from_seed(
            server_seed.data(), server_seed.size(), &server_keys1.handle, nullptr
        ) == EPP_SUCCESS);

        std::vector<uint8_t> client_x25519_1(X25519_KEY_SIZE);
        std::vector<uint8_t> server_x25519_1(X25519_KEY_SIZE);
        std::vector<uint8_t> server_kyber_1(KYBER_PUBLIC_KEY_SIZE);

        REQUIRE(epp_identity_get_x25519_public(
            client_keys1.handle, client_x25519_1.data(), client_x25519_1.size(), nullptr
        ) == EPP_SUCCESS);
        REQUIRE(epp_identity_get_x25519_public(
            server_keys1.handle, server_x25519_1.data(), server_x25519_1.size(), nullptr
        ) == EPP_SUCCESS);
        REQUIRE(epp_identity_get_kyber_public(
            server_keys1.handle, server_kyber_1.data(), server_kyber_1.size(), nullptr
        ) == EPP_SUCCESS);

        IdentityKeysGuard client_keys2;
        REQUIRE(epp_identity_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys2.handle, nullptr
        ) == EPP_SUCCESS);

        IdentityKeysGuard server_keys2;
        REQUIRE(epp_identity_create_from_seed(
            server_seed.data(), server_seed.size(), &server_keys2.handle, nullptr
        ) == EPP_SUCCESS);

        std::vector<uint8_t> client_x25519_2(X25519_KEY_SIZE);
        std::vector<uint8_t> server_x25519_2(X25519_KEY_SIZE);
        std::vector<uint8_t> server_kyber_2(KYBER_PUBLIC_KEY_SIZE);

        REQUIRE(epp_identity_get_x25519_public(
            client_keys2.handle, client_x25519_2.data(), client_x25519_2.size(), nullptr
        ) == EPP_SUCCESS);
        REQUIRE(epp_identity_get_x25519_public(
            server_keys2.handle, server_x25519_2.data(), server_x25519_2.size(), nullptr
        ) == EPP_SUCCESS);
        REQUIRE(epp_identity_get_kyber_public(
            server_keys2.handle, server_kyber_2.data(), server_kyber_2.size(), nullptr
        ) == EPP_SUCCESS);

        REQUIRE(std::memcmp(client_x25519_1.data(), client_x25519_2.data(), X25519_KEY_SIZE) == 0);
        REQUIRE(std::memcmp(server_x25519_1.data(), server_x25519_2.data(), X25519_KEY_SIZE) == 0);
        REQUIRE(std::memcmp(server_kyber_1.data(), server_kyber_2.data(), KYBER_PUBLIC_KEY_SIZE) == 0);
    }

    epp_shutdown();
}

TEST_CASE("C API E2E - Connection ID Consistency", "[c_api][e2e][connection]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Connection ID is set correctly after handshake") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) == EPP_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(epp_session_create(client_keys.handle, &client_system.handle, nullptr) == EPP_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(epp_server_create(server_keys.handle, &server_system.handle, nullptr) == EPP_SUCCESS);

        constexpr uint32_t expected_connection_id = 42;

        REQUIRE(PerformTwoWayHandshake(client_kyber_pk, server_kyber_pk, client_system.handle, server_system.handle, expected_connection_id));

        uint32_t client_conn_id = 0;
        REQUIRE(epp_session_get_id(
            client_system.handle, &client_conn_id, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(client_conn_id == expected_connection_id);

        uint32_t server_conn_id = 0;
        REQUIRE(epp_server_get_id(
            server_system.handle, &server_conn_id, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(server_conn_id > 0);
    }

    epp_shutdown();
}

TEST_CASE("C API E2E - Large Payload Handling", "[c_api][e2e][payload]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Can send and receive large payloads") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) == EPP_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(epp_session_create(client_keys.handle, &client_system.handle, nullptr) == EPP_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(epp_server_create(server_keys.handle, &server_system.handle, nullptr) == EPP_SUCCESS);

        REQUIRE(PerformTwoWayHandshake(client_kyber_pk, server_kyber_pk, client_system.handle, server_system.handle));

        constexpr size_t payload_size = 64 * 1024;
        std::vector<uint8_t> large_payload(payload_size);
        for (size_t i = 0; i < payload_size; ++i) {
            large_payload[i] = static_cast<uint8_t>(i & 0xFF);
        }

        EppBuffer envelope{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            large_payload.data(),
            large_payload.size(),
            &envelope,
            nullptr
        ) == EPP_SUCCESS);

        EppBuffer plaintext{};
        REQUIRE(epp_server_decrypt(
            server_system.handle,
            envelope.data,
            envelope.length,
            &plaintext,
            nullptr
        ) == EPP_SUCCESS);

        REQUIRE(plaintext.length == payload_size);
        REQUIRE(std::memcmp(plaintext.data, large_payload.data(), payload_size) == 0);

        free_buffer_data(&envelope);
        free_buffer_data(&plaintext);
    }

    epp_shutdown();
}

TEST_CASE("C API E2E - Alternating Bidirectional Messages", "[c_api][e2e][bidirectional]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Messages alternate between client and server") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) == EPP_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(epp_session_create(client_keys.handle, &client_system.handle, nullptr) == EPP_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(epp_server_create(server_keys.handle, &server_system.handle, nullptr) == EPP_SUCCESS);

        REQUIRE(PerformTwoWayHandshake(client_kyber_pk, server_kyber_pk, client_system.handle, server_system.handle));

        for (int i = 0; i < 20; ++i) {
            std::string client_msg = "C->S msg " + std::to_string(i);
            EppBuffer c_envelope{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(client_msg.data()),
                client_msg.size(),
                &c_envelope,
                nullptr
            ) == EPP_SUCCESS);

            EppBuffer s_plaintext{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, c_envelope.data, c_envelope.length,
                &s_plaintext, nullptr
            ) == EPP_SUCCESS);
            REQUIRE(s_plaintext.length == client_msg.size());
            REQUIRE(std::memcmp(s_plaintext.data, client_msg.data(), client_msg.size()) == 0);
            free_buffer_data(&c_envelope);
            free_buffer_data(&s_plaintext);

            std::string server_msg = "S->C msg " + std::to_string(i);
            EppBuffer s_envelope{};
            REQUIRE(epp_server_encrypt(
                server_system.handle,
                reinterpret_cast<const uint8_t*>(server_msg.data()),
                server_msg.size(),
                &s_envelope,
                nullptr
            ) == EPP_SUCCESS);

            EppBuffer c_plaintext{};
            REQUIRE(epp_session_decrypt(
                client_system.handle, s_envelope.data, s_envelope.length,
                &c_plaintext, nullptr
            ) == EPP_SUCCESS);
            REQUIRE(c_plaintext.length == server_msg.size());
            REQUIRE(std::memcmp(c_plaintext.data, server_msg.data(), server_msg.size()) == 0);
            free_buffer_data(&s_envelope);
            free_buffer_data(&c_plaintext);
        }
    }

    epp_shutdown();
}

TEST_CASE("C API E2E - Session Age Tracking", "[c_api][e2e][session]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Session age increases over time") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(epp_identity_get_kyber_public(server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) == EPP_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(epp_session_create(client_keys.handle, &client_system.handle, nullptr) == EPP_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(epp_server_create(server_keys.handle, &server_system.handle, nullptr) == EPP_SUCCESS);

        REQUIRE(PerformTwoWayHandshake(client_kyber_pk, server_kyber_pk, client_system.handle, server_system.handle));

        uint64_t initial_age = 0;
        REQUIRE(epp_session_age_seconds(
            client_system.handle, &initial_age, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(initial_age < 5);
    }

    epp_shutdown();
}
