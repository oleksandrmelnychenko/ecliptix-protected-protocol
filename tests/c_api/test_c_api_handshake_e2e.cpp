#include <catch2/catch_test_macros.hpp>
#include "ecliptix/c_api/ecliptix_c_api.h"
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
        uint32_t connection_id,
        uint8_t exchange_type,
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

    EcliptixErrorCode ecliptix_protocol_server_system_has_connection(
        const EcliptixProtocolSystemHandle* handle,
        bool* out_has_connection,
        EcliptixError* out_error);

    EcliptixErrorCode ecliptix_protocol_server_system_get_connection_id(
        const EcliptixProtocolSystemHandle* handle,
        uint32_t* out_connection_id,
        EcliptixError* out_error);

    EcliptixErrorCode ecliptix_protocol_server_system_get_chain_indices(
        const EcliptixProtocolSystemHandle* handle,
        uint32_t* out_sending_index,
        uint32_t* out_receiving_index,
        EcliptixError* out_error);

    void ecliptix_protocol_server_system_destroy(EcliptixProtocolSystemHandle* handle);
}

namespace {
    constexpr size_t KYBER_PUBLIC_KEY_SIZE = 1184;
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
            if (handle) {
                ecliptix_identity_keys_destroy(handle);
            }
        }
    };

    struct ClientSystemGuard {
        EcliptixProtocolSystemHandle* handle = nullptr;

        ~ClientSystemGuard() {
            if (handle) {
                ecliptix_protocol_system_destroy(handle);
            }
        }
    };

    struct ServerSystemGuard {
        EcliptixProtocolSystemHandle* handle = nullptr;

        ~ServerSystemGuard() {
            if (handle) {
                ecliptix_protocol_server_system_destroy(handle);
            }
        }
    };

    struct BufferGuard {
        EcliptixBuffer* buffer = nullptr;

        explicit BufferGuard(EcliptixBuffer* buf = nullptr) : buffer(buf) {}
        ~BufferGuard() {
            if (buffer) {
                ecliptix_buffer_free(buffer);
            }
        }
    };

    bool PerformTwoWayHandshake(
        const std::vector<uint8_t>& client_kyber_pk,
        const std::vector<uint8_t>& server_kyber_pk,
        EcliptixProtocolSystemHandle* client_system,
        EcliptixProtocolSystemHandle* server_system,
        uint64_t connection_id = 1
    ) {
        EcliptixError error{};

        EcliptixBuffer client_handshake_msg{};
        auto result = ecliptix_protocol_system_begin_handshake_with_peer_kyber(
            client_system, connection_id, 0, server_kyber_pk.data(), server_kyber_pk.size(),
            &client_handshake_msg, &error
        );
        if (result != ECLIPTIX_SUCCESS) {
            if (error.message) ecliptix_error_free(&error);
            return false;
        }

        EcliptixBuffer server_handshake_msg{};
        result = ecliptix_protocol_server_system_begin_handshake_with_peer_kyber(
            server_system, connection_id, 0, client_kyber_pk.data(), client_kyber_pk.size(),
            &server_handshake_msg, &error
        );
        if (result != ECLIPTIX_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            if (error.message) ecliptix_error_free(&error);
            return false;
        }

        result = ecliptix_protocol_server_system_complete_handshake_auto(
            server_system, client_handshake_msg.data, client_handshake_msg.length, &error
        );
        if (result != ECLIPTIX_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            free_buffer_data(&server_handshake_msg);
            if (error.message) ecliptix_error_free(&error);
            return false;
        }

        result = ecliptix_protocol_system_complete_handshake_auto(
            client_system, server_handshake_msg.data, server_handshake_msg.length, &error
        );
        if (result != ECLIPTIX_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            free_buffer_data(&server_handshake_msg);
            if (error.message) ecliptix_error_free(&error);
            return false;
        }

        free_buffer_data(&client_handshake_msg);
        free_buffer_data(&server_handshake_msg);
        return true;
    }
}

TEST_CASE("C API E2E - Full Handshake Flow", "[c_api][e2e][handshake]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Client initiates handshake with server, bidirectional messaging works") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(
            server_keys.handle,
            server_kyber_pk.data(),
            server_kyber_pk.size(),
            nullptr
        ) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(
            client_keys.handle,
            client_kyber_pk.data(),
            client_kyber_pk.size(),
            nullptr
        ) == ECLIPTIX_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(ecliptix_protocol_system_create(
            client_keys.handle,
            &client_system.handle,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(ecliptix_protocol_server_system_create(
            server_keys.handle,
            &server_system.handle,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixError error{};

        EcliptixBuffer client_handshake_msg{};
        auto result = ecliptix_protocol_system_begin_handshake_with_peer_kyber(
            client_system.handle,
            1,
            0,
            server_kyber_pk.data(),
            server_kyber_pk.size(),
            &client_handshake_msg,
            &error
        );
        if (result != ECLIPTIX_SUCCESS) {
            INFO("Client begin handshake failed: " << (error.message ? error.message : "unknown"));
            if (error.message) ecliptix_error_free(&error);
        }
        REQUIRE(result == ECLIPTIX_SUCCESS);
        REQUIRE(client_handshake_msg.data != nullptr);
        REQUIRE(client_handshake_msg.length > 0);

        EcliptixBuffer server_handshake_msg{};
        result = ecliptix_protocol_server_system_begin_handshake_with_peer_kyber(
            server_system.handle,
            1,
            0,
            client_kyber_pk.data(),
            client_kyber_pk.size(),
            &server_handshake_msg,
            &error
        );
        if (result != ECLIPTIX_SUCCESS) {
            INFO("Server begin handshake failed: " << (error.message ? error.message : "unknown"));
            if (error.message) ecliptix_error_free(&error);
        }
        REQUIRE(result == ECLIPTIX_SUCCESS);
        REQUIRE(server_handshake_msg.data != nullptr);
        REQUIRE(server_handshake_msg.length > 0);

        result = ecliptix_protocol_server_system_complete_handshake_auto(
            server_system.handle,
            client_handshake_msg.data,
            client_handshake_msg.length,
            &error
        );
        if (result != ECLIPTIX_SUCCESS) {
            INFO("Server complete handshake failed: " << (error.message ? error.message : "unknown"));
            if (error.message) ecliptix_error_free(&error);
        }
        REQUIRE(result == ECLIPTIX_SUCCESS);

        result = ecliptix_protocol_system_complete_handshake_auto(
            client_system.handle,
            server_handshake_msg.data,
            server_handshake_msg.length,
            &error
        );
        if (result != ECLIPTIX_SUCCESS) {
            INFO("Client complete handshake failed: " << (error.message ? error.message : "unknown"));
            if (error.message) ecliptix_error_free(&error);
        }
        REQUIRE(result == ECLIPTIX_SUCCESS);

        free_buffer_data(&client_handshake_msg);
        free_buffer_data(&server_handshake_msg);

        bool client_has_conn = false;
        bool server_has_conn = false;
        REQUIRE(ecliptix_protocol_system_has_connection(
            client_system.handle, &client_has_conn, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(ecliptix_protocol_server_system_has_connection(
            server_system.handle, &server_has_conn, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(client_has_conn);
        REQUIRE(server_has_conn);

        const std::string client_msg = "Hello from client via C API!";
        EcliptixBuffer client_envelope{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(client_msg.data()),
            client_msg.size(),
            &client_envelope,
            nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(client_envelope.data != nullptr);
        REQUIRE(client_envelope.length > client_msg.size());

        EcliptixBuffer server_plaintext{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            server_system.handle,
            client_envelope.data,
            client_envelope.length,
            &server_plaintext,
            nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(server_plaintext.data != nullptr);
        REQUIRE(server_plaintext.length == client_msg.size());
        REQUIRE(std::memcmp(server_plaintext.data, client_msg.data(), client_msg.size()) == 0);

        free_buffer_data(&client_envelope);
        free_buffer_data(&server_plaintext);

        const std::string server_msg = "Hello from server via C API!";
        EcliptixBuffer server_envelope{};
        REQUIRE(ecliptix_protocol_server_system_send_message(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(server_msg.data()),
            server_msg.size(),
            &server_envelope,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer client_plaintext{};
        REQUIRE(ecliptix_protocol_system_receive_message(
            client_system.handle,
            server_envelope.data,
            server_envelope.length,
            &client_plaintext,
            nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(client_plaintext.length == server_msg.size());
        REQUIRE(std::memcmp(client_plaintext.data, server_msg.data(), server_msg.size()) == 0);

        free_buffer_data(&server_envelope);
        free_buffer_data(&client_plaintext);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API E2E - Sequential Messages", "[c_api][e2e][messaging]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Multiple sequential messages in same direction") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(ecliptix_protocol_system_create(client_keys.handle, &client_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(ecliptix_protocol_server_system_create(server_keys.handle, &server_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        REQUIRE(PerformTwoWayHandshake(client_kyber_pk, server_kyber_pk, client_system.handle, server_system.handle));

        constexpr int message_count = 50;
        for (int i = 0; i < message_count; ++i) {
            std::string msg = "Message " + std::to_string(i) + " from client";

            EcliptixBuffer envelope{};
            REQUIRE(ecliptix_protocol_system_send_message(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope,
                nullptr
            ) == ECLIPTIX_SUCCESS);

            EcliptixBuffer plaintext{};
            const auto recv_result = ecliptix_protocol_server_system_receive_message(
                server_system.handle,
                envelope.data,
                envelope.length,
                &plaintext,
                nullptr
            );
            REQUIRE(recv_result == ECLIPTIX_SUCCESS);
            REQUIRE(plaintext.length == msg.size());
            REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        uint32_t client_send_idx = 0, client_recv_idx = 0;
        uint32_t server_send_idx = 0, server_recv_idx = 0;

        REQUIRE(ecliptix_protocol_system_get_chain_indices(
            client_system.handle, &client_send_idx, &client_recv_idx, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(ecliptix_protocol_server_system_get_chain_indices(
            server_system.handle, &server_send_idx, &server_recv_idx, nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(client_send_idx == message_count);
        REQUIRE(server_recv_idx == message_count);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API E2E - Deterministic Handshake from Seed", "[c_api][e2e][deterministic]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Same seeds produce reproducible sessions") {
        std::vector<uint8_t> client_seed(32, 0xAA);
        std::vector<uint8_t> server_seed(32, 0xBB);

        IdentityKeysGuard client_keys1;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys1.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys1;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            server_seed.data(), server_seed.size(), &server_keys1.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> client_x25519_1(X25519_KEY_SIZE);
        std::vector<uint8_t> server_x25519_1(X25519_KEY_SIZE);
        std::vector<uint8_t> server_kyber_1(KYBER_PUBLIC_KEY_SIZE);

        REQUIRE(ecliptix_identity_keys_get_public_x25519(
            client_keys1.handle, client_x25519_1.data(), client_x25519_1.size(), nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(ecliptix_identity_keys_get_public_x25519(
            server_keys1.handle, server_x25519_1.data(), server_x25519_1.size(), nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(
            server_keys1.handle, server_kyber_1.data(), server_kyber_1.size(), nullptr
        ) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard client_keys2;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys2.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys2;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            server_seed.data(), server_seed.size(), &server_keys2.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> client_x25519_2(X25519_KEY_SIZE);
        std::vector<uint8_t> server_x25519_2(X25519_KEY_SIZE);
        std::vector<uint8_t> server_kyber_2(KYBER_PUBLIC_KEY_SIZE);

        REQUIRE(ecliptix_identity_keys_get_public_x25519(
            client_keys2.handle, client_x25519_2.data(), client_x25519_2.size(), nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(ecliptix_identity_keys_get_public_x25519(
            server_keys2.handle, server_x25519_2.data(), server_x25519_2.size(), nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(
            server_keys2.handle, server_kyber_2.data(), server_kyber_2.size(), nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(std::memcmp(client_x25519_1.data(), client_x25519_2.data(), X25519_KEY_SIZE) == 0);
        REQUIRE(std::memcmp(server_x25519_1.data(), server_x25519_2.data(), X25519_KEY_SIZE) == 0);
        REQUIRE(std::memcmp(server_kyber_1.data(), server_kyber_2.data(), KYBER_PUBLIC_KEY_SIZE) == 0);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API E2E - Connection ID Consistency", "[c_api][e2e][connection]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Connection ID is set correctly after handshake") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(ecliptix_protocol_system_create(client_keys.handle, &client_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(ecliptix_protocol_server_system_create(server_keys.handle, &server_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        constexpr uint32_t expected_connection_id = 42;

        REQUIRE(PerformTwoWayHandshake(client_kyber_pk, server_kyber_pk, client_system.handle, server_system.handle, expected_connection_id));

        uint32_t client_conn_id = 0;
        REQUIRE(ecliptix_protocol_system_get_connection_id(
            client_system.handle, &client_conn_id, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(client_conn_id == expected_connection_id);

        uint32_t server_conn_id = 0;
        REQUIRE(ecliptix_protocol_server_system_get_connection_id(
            server_system.handle, &server_conn_id, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(server_conn_id > 0);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API E2E - Large Payload Handling", "[c_api][e2e][payload]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Can send and receive large payloads") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(ecliptix_protocol_system_create(client_keys.handle, &client_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(ecliptix_protocol_server_system_create(server_keys.handle, &server_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        REQUIRE(PerformTwoWayHandshake(client_kyber_pk, server_kyber_pk, client_system.handle, server_system.handle));

        constexpr size_t payload_size = 64 * 1024;
        std::vector<uint8_t> large_payload(payload_size);
        for (size_t i = 0; i < payload_size; ++i) {
            large_payload[i] = static_cast<uint8_t>(i & 0xFF);
        }

        EcliptixBuffer envelope{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client_system.handle,
            large_payload.data(),
            large_payload.size(),
            &envelope,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer plaintext{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            server_system.handle,
            envelope.data,
            envelope.length,
            &plaintext,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(plaintext.length == payload_size);
        REQUIRE(std::memcmp(plaintext.data, large_payload.data(), payload_size) == 0);

        free_buffer_data(&envelope);
        free_buffer_data(&plaintext);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API E2E - Alternating Bidirectional Messages", "[c_api][e2e][bidirectional]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Messages alternate between client and server") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(ecliptix_protocol_system_create(client_keys.handle, &client_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(ecliptix_protocol_server_system_create(server_keys.handle, &server_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        REQUIRE(PerformTwoWayHandshake(client_kyber_pk, server_kyber_pk, client_system.handle, server_system.handle));

        for (int i = 0; i < 20; ++i) {
            std::string client_msg = "C->S msg " + std::to_string(i);
            EcliptixBuffer c_envelope{};
            REQUIRE(ecliptix_protocol_system_send_message(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(client_msg.data()),
                client_msg.size(),
                &c_envelope,
                nullptr
            ) == ECLIPTIX_SUCCESS);

            EcliptixBuffer s_plaintext{};
            REQUIRE(ecliptix_protocol_server_system_receive_message(
                server_system.handle, c_envelope.data, c_envelope.length,
                &s_plaintext, nullptr
            ) == ECLIPTIX_SUCCESS);
            REQUIRE(s_plaintext.length == client_msg.size());
            REQUIRE(std::memcmp(s_plaintext.data, client_msg.data(), client_msg.size()) == 0);
            free_buffer_data(&c_envelope);
            free_buffer_data(&s_plaintext);

            std::string server_msg = "S->C msg " + std::to_string(i);
            EcliptixBuffer s_envelope{};
            REQUIRE(ecliptix_protocol_server_system_send_message(
                server_system.handle,
                reinterpret_cast<const uint8_t*>(server_msg.data()),
                server_msg.size(),
                &s_envelope,
                nullptr
            ) == ECLIPTIX_SUCCESS);

            EcliptixBuffer c_plaintext{};
            REQUIRE(ecliptix_protocol_system_receive_message(
                client_system.handle, s_envelope.data, s_envelope.length,
                &c_plaintext, nullptr
            ) == ECLIPTIX_SUCCESS);
            REQUIRE(c_plaintext.length == server_msg.size());
            REQUIRE(std::memcmp(c_plaintext.data, server_msg.data(), server_msg.size()) == 0);
            free_buffer_data(&s_envelope);
            free_buffer_data(&c_plaintext);
        }
    }

    ecliptix_shutdown();
}

TEST_CASE("C API E2E - Session Age Tracking", "[c_api][e2e][session]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Session age increases over time") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard client_system;
        REQUIRE(ecliptix_protocol_system_create(client_keys.handle, &client_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        ServerSystemGuard server_system;
        REQUIRE(ecliptix_protocol_server_system_create(server_keys.handle, &server_system.handle, nullptr) == ECLIPTIX_SUCCESS);

        REQUIRE(PerformTwoWayHandshake(client_kyber_pk, server_kyber_pk, client_system.handle, server_system.handle));

        uint64_t initial_age = 0;
        REQUIRE(ecliptix_connection_get_session_age_seconds(
            client_system.handle, &initial_age, nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(initial_age < 5);
    }

    ecliptix_shutdown();
}
