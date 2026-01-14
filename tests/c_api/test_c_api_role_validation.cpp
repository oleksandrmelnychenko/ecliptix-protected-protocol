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

    EcliptixErrorCode ecliptix_protocol_server_system_get_chain_indices(
        const EcliptixProtocolSystemHandle* handle,
        uint32_t* out_sending_index,
        uint32_t* out_receiving_index,
        EcliptixError* out_error);

    void ecliptix_protocol_server_system_destroy(EcliptixProtocolSystemHandle* handle);
}

namespace {
    constexpr size_t KYBER_PUBLIC_KEY_SIZE = 1184;

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

    bool SetupHandshakedPair(
        EcliptixIdentityKeysHandle* client_keys,
        EcliptixIdentityKeysHandle* server_keys,
        EcliptixProtocolSystemHandle** out_client,
        EcliptixProtocolSystemHandle** out_server
    ) {
        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        if (ecliptix_identity_keys_get_public_kyber(server_keys, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) != ECLIPTIX_SUCCESS) {
            return false;
        }

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        if (ecliptix_identity_keys_get_public_kyber(client_keys, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) != ECLIPTIX_SUCCESS) {
            return false;
        }

        if (ecliptix_protocol_system_create(client_keys, out_client, nullptr) != ECLIPTIX_SUCCESS) {
            return false;
        }

        if (ecliptix_protocol_server_system_create(server_keys, out_server, nullptr) != ECLIPTIX_SUCCESS) {
            ecliptix_protocol_system_destroy(*out_client);
            *out_client = nullptr;
            return false;
        }

        EcliptixBuffer client_handshake_msg{};
        if (ecliptix_protocol_system_begin_handshake_with_peer_kyber(
            *out_client, 1, 0, server_kyber_pk.data(), server_kyber_pk.size(),
            &client_handshake_msg, nullptr
        ) != ECLIPTIX_SUCCESS) {
            ecliptix_protocol_system_destroy(*out_client);
            ecliptix_protocol_server_system_destroy(*out_server);
            *out_client = nullptr;
            *out_server = nullptr;
            return false;
        }

        EcliptixBuffer server_handshake_msg{};
        if (ecliptix_protocol_server_system_begin_handshake_with_peer_kyber(
            *out_server, 1, 0, client_kyber_pk.data(), client_kyber_pk.size(),
            &server_handshake_msg, nullptr
        ) != ECLIPTIX_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            ecliptix_protocol_system_destroy(*out_client);
            ecliptix_protocol_server_system_destroy(*out_server);
            *out_client = nullptr;
            *out_server = nullptr;
            return false;
        }

        if (ecliptix_protocol_server_system_complete_handshake_auto(
            *out_server, client_handshake_msg.data, client_handshake_msg.length, nullptr
        ) != ECLIPTIX_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            free_buffer_data(&server_handshake_msg);
            ecliptix_protocol_system_destroy(*out_client);
            ecliptix_protocol_server_system_destroy(*out_server);
            *out_client = nullptr;
            *out_server = nullptr;
            return false;
        }

        if (ecliptix_protocol_system_complete_handshake_auto(
            *out_client, server_handshake_msg.data, server_handshake_msg.length, nullptr
        ) != ECLIPTIX_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            free_buffer_data(&server_handshake_msg);
            ecliptix_protocol_system_destroy(*out_client);
            ecliptix_protocol_server_system_destroy(*out_server);
            *out_client = nullptr;
            *out_server = nullptr;
            return false;
        }

        free_buffer_data(&client_handshake_msg);
        free_buffer_data(&server_handshake_msg);
        return true;
    }
}

TEST_CASE("C API Role Validation - Client Cannot Decrypt Own Messages", "[c_api][role][client]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Client sending message cannot decrypt it with same client") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* client_raw = nullptr;
        EcliptixProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        const std::string msg = "Test message";
        EcliptixBuffer envelope{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer plaintext{};
        EcliptixError error{};
        const auto result = ecliptix_protocol_system_receive_message(
            client_system.handle,
            envelope.data,
            envelope.length,
            &plaintext,
            &error
        );

        REQUIRE(result != ECLIPTIX_SUCCESS);
        if (error.message) ecliptix_error_free(&error);
        if (plaintext.data) free_buffer_data(&plaintext);

        free_buffer_data(&envelope);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Role Validation - Server Cannot Decrypt Own Messages", "[c_api][role][server]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Server sending message cannot decrypt it with same server") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* client_raw = nullptr;
        EcliptixProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        const std::string init_msg = "Init message";
        EcliptixBuffer init_env{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(init_msg.data()),
            init_msg.size(),
            &init_env, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer init_pt{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            server_system.handle, init_env.data, init_env.length, &init_pt, nullptr
        ) == ECLIPTIX_SUCCESS);
        free_buffer_data(&init_env);
        free_buffer_data(&init_pt);

        const std::string msg = "Server message";
        EcliptixBuffer envelope{};
        REQUIRE(ecliptix_protocol_server_system_send_message(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer plaintext{};
        EcliptixError error{};
        const auto result = ecliptix_protocol_server_system_receive_message(
            server_system.handle,
            envelope.data,
            envelope.length,
            &plaintext,
            &error
        );

        REQUIRE(result != ECLIPTIX_SUCCESS);
        if (error.message) ecliptix_error_free(&error);
        if (plaintext.data) free_buffer_data(&plaintext);

        free_buffer_data(&envelope);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Role Validation - Correct Direction Works", "[c_api][role][direction]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Client->Server and Server->Client both work correctly") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* client_raw = nullptr;
        EcliptixProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        const std::string client_msg = "From client";
        EcliptixBuffer client_env{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(client_msg.data()),
            client_msg.size(),
            &client_env, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer server_pt{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            server_system.handle, client_env.data, client_env.length,
            &server_pt, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(server_pt.length == client_msg.size());
        REQUIRE(std::memcmp(server_pt.data, client_msg.data(), client_msg.size()) == 0);
        free_buffer_data(&client_env);
        free_buffer_data(&server_pt);

        const std::string server_msg = "From server";
        EcliptixBuffer server_env{};
        REQUIRE(ecliptix_protocol_server_system_send_message(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(server_msg.data()),
            server_msg.size(),
            &server_env, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer client_pt{};
        REQUIRE(ecliptix_protocol_system_receive_message(
            client_system.handle, server_env.data, server_env.length,
            &client_pt, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(client_pt.length == server_msg.size());
        REQUIRE(std::memcmp(client_pt.data, server_msg.data(), server_msg.size()) == 0);
        free_buffer_data(&server_env);
        free_buffer_data(&client_pt);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Role Validation - Chain Asymmetry", "[c_api][role][chain]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Client and server have swapped send/receive chains") {
        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create(&client_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* client_raw = nullptr;
        EcliptixProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        for (int i = 0; i < 5; ++i) {
            std::string msg = "Msg " + std::to_string(i);
            EcliptixBuffer env{};
            REQUIRE(ecliptix_protocol_system_send_message(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &env, nullptr
            ) == ECLIPTIX_SUCCESS);

            EcliptixBuffer pt{};
            REQUIRE(ecliptix_protocol_server_system_receive_message(
                server_system.handle, env.data, env.length, &pt, nullptr
            ) == ECLIPTIX_SUCCESS);
            free_buffer_data(&env);
            free_buffer_data(&pt);
        }

        uint32_t client_send = 0, client_recv = 0;
        uint32_t server_send = 0, server_recv = 0;

        REQUIRE(ecliptix_protocol_system_get_chain_indices(
            client_system.handle, &client_send, &client_recv, nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(ecliptix_protocol_server_system_get_chain_indices(
            server_system.handle, &server_send, &server_recv, nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(client_send == 5);
        REQUIRE(client_recv == 0);

        REQUIRE(server_recv == 5);
        REQUIRE(server_send == 0);

        REQUIRE(client_send == server_recv);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Role Validation - Cross-Session Messages Fail", "[c_api][role][cross-session]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Messages from one session cannot be decrypted by different session") {
        IdentityKeysGuard client1_keys;
        REQUIRE(ecliptix_identity_keys_create(&client1_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server1_keys;
        REQUIRE(ecliptix_identity_keys_create(&server1_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* client1_raw = nullptr;
        EcliptixProtocolSystemHandle* server1_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client1_keys.handle, server1_keys.handle, &client1_raw, &server1_raw));

        ClientSystemGuard client1;
        client1.handle = client1_raw;

        ServerSystemGuard server1;
        server1.handle = server1_raw;

        IdentityKeysGuard client2_keys;
        REQUIRE(ecliptix_identity_keys_create(&client2_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server2_keys;
        REQUIRE(ecliptix_identity_keys_create(&server2_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* client2_raw = nullptr;
        EcliptixProtocolSystemHandle* server2_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client2_keys.handle, server2_keys.handle, &client2_raw, &server2_raw));

        ClientSystemGuard client2;
        client2.handle = client2_raw;

        ServerSystemGuard server2;
        server2.handle = server2_raw;

        const std::string msg = "Session 1 message";
        EcliptixBuffer envelope{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client1.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer plaintext{};
        EcliptixError error{};
        const auto result = ecliptix_protocol_server_system_receive_message(
            server2.handle,
            envelope.data,
            envelope.length,
            &plaintext,
            &error
        );

        REQUIRE(result != ECLIPTIX_SUCCESS);
        if (error.message) ecliptix_error_free(&error);
        if (plaintext.data) free_buffer_data(&plaintext);

        EcliptixBuffer correct_pt{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            server1.handle, envelope.data, envelope.length, &correct_pt, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(correct_pt.length == msg.size());
        free_buffer_data(&correct_pt);

        free_buffer_data(&envelope);
    }

    ecliptix_shutdown();
}
