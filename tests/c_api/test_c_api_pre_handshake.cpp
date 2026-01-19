#include <catch2/catch_test_macros.hpp>
#include "ecliptix/c_api/epp_api.h"
#include <cstring>
#include <vector>

extern "C" {
    EppErrorCode epp_server_create(
        EppIdentityHandle* identity_keys,
        ProtocolSystemHandle** out_handle,
        EppError* out_error);

    EppErrorCode epp_server_begin_handshake(
        ProtocolSystemHandle* handle,
        uint64_t peer_device_id,
        uint64_t peer_identity_id,
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

    void epp_server_destroy(ProtocolSystemHandle* handle);
}

namespace {
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

TEST_CASE("C API Pre-Handshake - Send Before Handshake", "[c_api][pre-handshake][send]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Client send before handshake returns INVALID_STATE") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(epp_session_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        const std::string msg = "Test message";
        EppBuffer envelope{};
        EppError error{};

        const auto result = epp_session_encrypt(
            system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope,
            &error
        );

        REQUIRE(result == EPP_ERROR_INVALID_STATE);
        REQUIRE(error.message != nullptr);
        epp_error_free(&error);
    }

    SECTION("Server send before handshake returns INVALID_STATE") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ServerSystemGuard system;
        REQUIRE(epp_server_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        const std::string msg = "Test message";
        EppBuffer envelope{};
        EppError error{};

        const auto result = epp_server_encrypt(
            system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope,
            &error
        );

        REQUIRE(result == EPP_ERROR_INVALID_STATE);
        REQUIRE(error.message != nullptr);
        epp_error_free(&error);
    }

    epp_shutdown();
}

TEST_CASE("C API Pre-Handshake - Receive Before Handshake", "[c_api][pre-handshake][receive]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Client receive before handshake returns error") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(epp_session_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> fake_envelope(100, 0xAA);
        EppBuffer plaintext{};
        EppError error{};

        const auto result = epp_session_decrypt(
            system.handle,
            fake_envelope.data(),
            fake_envelope.size(),
            &plaintext,
            &error
        );

        REQUIRE(result != EPP_SUCCESS);
        if (error.message) epp_error_free(&error);
        if (plaintext.data) free_buffer_data(&plaintext);
    }

    SECTION("Server receive before handshake returns error") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ServerSystemGuard system;
        REQUIRE(epp_server_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> fake_envelope(100, 0xBB);
        EppBuffer plaintext{};
        EppError error{};

        const auto result = epp_server_decrypt(
            system.handle,
            fake_envelope.data(),
            fake_envelope.size(),
            &plaintext,
            &error
        );

        REQUIRE(result != EPP_SUCCESS);
        if (error.message) epp_error_free(&error);
        if (plaintext.data) free_buffer_data(&plaintext);
    }

    epp_shutdown();
}

TEST_CASE("C API Pre-Handshake - Has Connection States", "[c_api][pre-handshake][connection]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Client has_connection is false before handshake") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(epp_session_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        bool has_conn = true;
        REQUIRE(epp_session_is_established(
            system.handle, &has_conn, nullptr
        ) == EPP_SUCCESS);

        REQUIRE_FALSE(has_conn);
    }

    SECTION("Server has_connection is false before handshake") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ServerSystemGuard system;
        REQUIRE(epp_server_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        bool has_conn = true;
        REQUIRE(epp_server_is_established(
            system.handle, &has_conn, nullptr
        ) == EPP_SUCCESS);

        REQUIRE_FALSE(has_conn);
    }

    SECTION("Client has_connection transitions to true after handshake completes") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(1184);
        REQUIRE(epp_identity_get_kyber_public(
            server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr
        ) == EPP_SUCCESS);

        std::vector<uint8_t> client_kyber_pk(1184);
        REQUIRE(epp_identity_get_kyber_public(
            client_keys.handle, client_kyber_pk.data(), client_kyber_pk.size(), nullptr
        ) == EPP_SUCCESS);

        ClientSystemGuard client;
        REQUIRE(epp_session_create(client_keys.handle, &client.handle, nullptr) == EPP_SUCCESS);

        ServerSystemGuard server;
        REQUIRE(epp_server_create(server_keys.handle, &server.handle, nullptr) == EPP_SUCCESS);

        bool has_conn_before = true;
        REQUIRE(epp_session_is_established(client.handle, &has_conn_before, nullptr) == EPP_SUCCESS);
        REQUIRE_FALSE(has_conn_before);

        EppBuffer client_handshake_msg{};
        REQUIRE(epp_session_begin_handshake(
            client.handle, 1, 0, server_kyber_pk.data(), server_kyber_pk.size(),
            &client_handshake_msg, nullptr
        ) == EPP_SUCCESS);

        bool has_conn_mid = true;
        REQUIRE(epp_session_is_established(client.handle, &has_conn_mid, nullptr) == EPP_SUCCESS);
        REQUIRE_FALSE(has_conn_mid);

        EppBuffer server_handshake_msg{};
        REQUIRE(epp_server_begin_handshake(
            server.handle, 1, 0, client_kyber_pk.data(), client_kyber_pk.size(),
            &server_handshake_msg, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(epp_server_complete_handshake_auto(
            server.handle, client_handshake_msg.data, client_handshake_msg.length, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(epp_session_complete_handshake_auto(
            client.handle, server_handshake_msg.data, server_handshake_msg.length, nullptr
        ) == EPP_SUCCESS);

        bool has_conn_after = false;
        REQUIRE(epp_session_is_established(client.handle, &has_conn_after, nullptr) == EPP_SUCCESS);
        REQUIRE(has_conn_after);

        free_buffer_data(&client_handshake_msg);
        free_buffer_data(&server_handshake_msg);
    }

    epp_shutdown();
}

TEST_CASE("C API Pre-Handshake - Partial Cleanup", "[c_api][pre-handshake][cleanup]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Destroy client mid-handshake is safe") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> server_kyber_pk(1184);
        REQUIRE(epp_identity_get_kyber_public(
            server_keys.handle, server_kyber_pk.data(), server_kyber_pk.size(), nullptr
        ) == EPP_SUCCESS);

        ProtocolSystemHandle* client = nullptr;
        REQUIRE(epp_session_create(client_keys.handle, &client, nullptr) == EPP_SUCCESS);

        EppBuffer handshake_msg{};
        REQUIRE(epp_session_begin_handshake(
            client, 1, 0, server_kyber_pk.data(), server_kyber_pk.size(),
            &handshake_msg, nullptr
        ) == EPP_SUCCESS);

        free_buffer_data(&handshake_msg);

        epp_session_destroy(client);
    }

    SECTION("Destroy server before complete_handshake is safe") {
        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* server = nullptr;
        REQUIRE(epp_server_create(server_keys.handle, &server, nullptr) == EPP_SUCCESS);

        epp_server_destroy(server);
    }

    SECTION("Multiple destroy calls are safe") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* system = nullptr;
        REQUIRE(epp_session_create(keys.handle, &system, nullptr) == EPP_SUCCESS);

        epp_session_destroy(system);
        epp_session_destroy(nullptr);
    }

    epp_shutdown();
}

TEST_CASE("C API Pre-Handshake - Get Chain Indices Before Handshake", "[c_api][pre-handshake][indices]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Get chain indices before handshake returns error or zero") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(epp_session_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        uint32_t send_idx = 999, recv_idx = 999;
        EppError error{};

        const auto result = epp_session_get_chain_indices(
            system.handle, &send_idx, &recv_idx, &error
        );

        if (result == EPP_SUCCESS) {
            REQUIRE(send_idx == 0);
            REQUIRE(recv_idx == 0);
        } else {
            REQUIRE(result == EPP_ERROR_INVALID_STATE);
        }
        if (error.message) epp_error_free(&error);
    }

    epp_shutdown();
}

TEST_CASE("C API Pre-Handshake - Get Connection ID Before Handshake", "[c_api][pre-handshake][conn-id]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Get connection ID before handshake returns error") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(epp_session_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        uint32_t conn_id = 0;
        EppError error{};

        const auto result = epp_session_get_id(
            system.handle, &conn_id, &error
        );

        REQUIRE(result == EPP_ERROR_INVALID_STATE);
        if (error.message) epp_error_free(&error);
    }

    epp_shutdown();
}

TEST_CASE("C API Pre-Handshake - Export State Before Handshake", "[c_api][pre-handshake][export]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Export state before handshake returns error") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ClientSystemGuard system;
        REQUIRE(epp_session_create(keys.handle, &system.handle, nullptr) == EPP_SUCCESS);

        EppBuffer state{};
        EppError error{};

        const auto result = epp_session_serialize(
            system.handle, &state, &error
        );

        REQUIRE(result == EPP_ERROR_INVALID_STATE);
        if (error.message) epp_error_free(&error);
        if (state.data) free_buffer_data(&state);
    }

    epp_shutdown();
}
