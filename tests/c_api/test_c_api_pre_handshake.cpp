#include <catch2/catch_test_macros.hpp>
#include "ecliptix/c_api/ecliptix_c_api.h"
#include <cstring>
#include <vector>

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

    EcliptixErrorCode ecliptix_protocol_server_system_has_connection(
        const EcliptixProtocolSystemHandle* handle,
        bool* out_has_connection,
        EcliptixError* out_error);

    void ecliptix_protocol_server_system_destroy(EcliptixProtocolSystemHandle* handle);
}

namespace {
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

TEST_CASE("C API Pre-Handshake - Send Before Handshake", "[c_api][pre-handshake][send]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Client send before handshake returns INVALID_STATE") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(ecliptix_protocol_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        const std::string msg = "Test message";
        EcliptixBuffer envelope{};
        EcliptixError error{};

        const auto result = ecliptix_protocol_system_send_message(
            system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_INVALID_STATE);
        REQUIRE(error.message != nullptr);
        ecliptix_error_free(&error);
    }

    SECTION("Server send before handshake returns INVALID_STATE") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ServerSystemGuard system;
        REQUIRE(ecliptix_protocol_server_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        const std::string msg = "Test message";
        EcliptixBuffer envelope{};
        EcliptixError error{};

        const auto result = ecliptix_protocol_server_system_send_message(
            system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_INVALID_STATE);
        REQUIRE(error.message != nullptr);
        ecliptix_error_free(&error);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Pre-Handshake - Receive Before Handshake", "[c_api][pre-handshake][receive]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Client receive before handshake returns error") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(ecliptix_protocol_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> fake_envelope(100, 0xAA);
        EcliptixBuffer plaintext{};
        EcliptixError error{};

        const auto result = ecliptix_protocol_system_receive_message(
            system.handle,
            fake_envelope.data(),
            fake_envelope.size(),
            &plaintext,
            &error
        );

        REQUIRE(result != ECLIPTIX_SUCCESS);
        if (error.message) ecliptix_error_free(&error);
        if (plaintext.data) free_buffer_data(&plaintext);
    }

    SECTION("Server receive before handshake returns error") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ServerSystemGuard system;
        REQUIRE(ecliptix_protocol_server_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> fake_envelope(100, 0xBB);
        EcliptixBuffer plaintext{};
        EcliptixError error{};

        const auto result = ecliptix_protocol_server_system_receive_message(
            system.handle,
            fake_envelope.data(),
            fake_envelope.size(),
            &plaintext,
            &error
        );

        REQUIRE(result != ECLIPTIX_SUCCESS);
        if (error.message) ecliptix_error_free(&error);
        if (plaintext.data) free_buffer_data(&plaintext);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Pre-Handshake - Has Connection States", "[c_api][pre-handshake][connection]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Client has_connection is false before handshake") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(ecliptix_protocol_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        bool has_conn = true;
        REQUIRE(ecliptix_protocol_system_has_connection(
            system.handle, &has_conn, nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE_FALSE(has_conn);
    }

    SECTION("Server has_connection is false before handshake") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ServerSystemGuard system;
        REQUIRE(ecliptix_protocol_server_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        bool has_conn = true;
        REQUIRE(ecliptix_protocol_server_system_has_connection(
            system.handle, &has_conn, nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE_FALSE(has_conn);
    }

    SECTION("Client has_connection transitions to true after handshake completes") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(1184);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(
            server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr
        ) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(1184);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(
            client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr
        ) == ECLIPTIX_SUCCESS);

        ClientSystemGuard client;
        REQUIRE(ecliptix_protocol_system_create(client_keys.handle, &client.handle, nullptr) == ECLIPTIX_SUCCESS);

        ServerSystemGuard server;
        REQUIRE(ecliptix_protocol_server_system_create(server_keys.handle, &server.handle, nullptr) == ECLIPTIX_SUCCESS);

        bool has_conn_before = true;
        REQUIRE(ecliptix_protocol_system_has_connection(client.handle, &has_conn_before, nullptr) == ECLIPTIX_SUCCESS);
        REQUIRE_FALSE(has_conn_before);

        EcliptixBuffer client_handshake_msg{};
        REQUIRE(ecliptix_protocol_system_begin_handshake_with_peer_kyber(
            client.handle, 1, 0, server_kyber_pk.data(), server_kyber_pk.size(),
            &client_handshake_msg, nullptr
        ) == ECLIPTIX_SUCCESS);

        bool has_conn_mid = true;
        REQUIRE(ecliptix_protocol_system_has_connection(client.handle, &has_conn_mid, nullptr) == ECLIPTIX_SUCCESS);
        REQUIRE_FALSE(has_conn_mid);

        EcliptixBuffer server_handshake_msg{};
        REQUIRE(ecliptix_protocol_server_system_begin_handshake_with_peer_kyber(
            server.handle, 1, 0, client_kyber_pk.data(), client_kyber_pk.size(),
            &server_handshake_msg, nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(ecliptix_protocol_server_system_complete_handshake_auto(
            server.handle, client_handshake_msg.data, client_handshake_msg.length, nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(ecliptix_protocol_system_complete_handshake_auto(
            client.handle, server_handshake_msg.data, server_handshake_msg.length, nullptr
        ) == ECLIPTIX_SUCCESS);

        bool has_conn_after = false;
        REQUIRE(ecliptix_protocol_system_has_connection(client.handle, &has_conn_after, nullptr) == ECLIPTIX_SUCCESS);
        REQUIRE(has_conn_after);

        free_buffer_data(&client_handshake_msg);
        free_buffer_data(&server_handshake_msg);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Pre-Handshake - Partial Cleanup", "[c_api][pre-handshake][cleanup]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Destroy client mid-handshake is safe") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(1184);
        REQUIRE(ecliptix_identity_keys_get_public_kyber(
            server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* client = nullptr;
        REQUIRE(ecliptix_protocol_system_create(client_keys.handle, &client, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixBuffer handshake_msg{};
        REQUIRE(ecliptix_protocol_system_begin_handshake_with_peer_kyber(
            client, 1, 0, server_kyber_pk.data(), server_kyber_pk.size(),
            &handshake_msg, nullptr
        ) == ECLIPTIX_SUCCESS);

        free_buffer_data(&handshake_msg);

        ecliptix_protocol_system_destroy(client);
    }

    SECTION("Destroy server before complete_handshake is safe") {
        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* server = nullptr;
        REQUIRE(ecliptix_protocol_server_system_create(server_keys.handle, &server, nullptr) == ECLIPTIX_SUCCESS);

        ecliptix_protocol_server_system_destroy(server);
    }

    SECTION("Multiple destroy calls are safe") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* system = nullptr;
        REQUIRE(ecliptix_protocol_system_create(keys.handle, &system, nullptr) == ECLIPTIX_SUCCESS);

        ecliptix_protocol_system_destroy(system);
        ecliptix_protocol_system_destroy(nullptr);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Pre-Handshake - Get Chain Indices Before Handshake", "[c_api][pre-handshake][indices]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Get chain indices before handshake returns error or zero") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(ecliptix_protocol_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        uint32_t send_idx = 999, recv_idx = 999;
        EcliptixError error{};

        const auto result = ecliptix_protocol_system_get_chain_indices(
            system.handle, &send_idx, &recv_idx, &error
        );

        if (result == ECLIPTIX_SUCCESS) {
            REQUIRE(send_idx == 0);
            REQUIRE(recv_idx == 0);
        } else {
            REQUIRE(result == ECLIPTIX_ERROR_INVALID_STATE);
        }
        if (error.message) ecliptix_error_free(&error);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Pre-Handshake - Get Connection ID Before Handshake", "[c_api][pre-handshake][conn-id]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Get connection ID before handshake returns error") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(ecliptix_protocol_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        uint32_t conn_id = 0;
        EcliptixError error{};

        const auto result = ecliptix_protocol_system_get_connection_id(
            system.handle, &conn_id, &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_INVALID_STATE);
        if (error.message) ecliptix_error_free(&error);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Pre-Handshake - Export State Before Handshake", "[c_api][pre-handshake][export]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Export state before handshake returns error") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(ecliptix_protocol_system_create(keys.handle, &system.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixBuffer state{};
        EcliptixError error{};

        const auto result = ecliptix_protocol_system_export_state(
            system.handle, &state, &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_INVALID_STATE);
        if (error.message) ecliptix_error_free(&error);
        if (state.data) free_buffer_data(&state);
    }

    ecliptix_shutdown();
}
