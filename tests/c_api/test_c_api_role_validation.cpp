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

    EppErrorCode epp_server_begin_handshake_with_peer_kyber(
        ProtocolSystemHandle* handle,
        uint32_t connection_id,
        uint8_t exchange_type,
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

    EppErrorCode epp_server_get_chain_indices(
        const ProtocolSystemHandle* handle,
        uint32_t* out_sending_index,
        uint32_t* out_receiving_index,
        EppError* out_error);

    void epp_server_destroy(ProtocolSystemHandle* handle);
}

namespace {
    constexpr size_t KYBER_PUBLIC_KEY_SIZE = 1184;

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

    bool SetupHandshakedPair(
        EppIdentityHandle* client_keys,
        EppIdentityHandle* server_keys,
        ProtocolSystemHandle** out_client,
        ProtocolSystemHandle** out_server
    ) {
        std::vector<uint8_t> server_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        if (epp_identity_get_kyber_public(server_keys, server_kyber_pk.data(), server_kyber_pk.size(), nullptr) != EPP_SUCCESS) {
            return false;
        }

        std::vector<uint8_t> client_kyber_pk(KYBER_PUBLIC_KEY_SIZE);
        if (epp_identity_get_kyber_public(client_keys, client_kyber_pk.data(), client_kyber_pk.size(), nullptr) != EPP_SUCCESS) {
            return false;
        }

        if (epp_session_create(client_keys, out_client, nullptr) != EPP_SUCCESS) {
            return false;
        }

        if (epp_server_create(server_keys, out_server, nullptr) != EPP_SUCCESS) {
            epp_session_destroy(*out_client);
            *out_client = nullptr;
            return false;
        }

        EppBuffer client_handshake_msg{};
        if (epp_session_begin_handshake(
            *out_client, 1, 0, server_kyber_pk.data(), server_kyber_pk.size(),
            &client_handshake_msg, nullptr
        ) != EPP_SUCCESS) {
            epp_session_destroy(*out_client);
            epp_server_destroy(*out_server);
            *out_client = nullptr;
            *out_server = nullptr;
            return false;
        }

        EppBuffer server_handshake_msg{};
        if (epp_server_begin_handshake_with_peer_kyber(
            *out_server, 1, 0, client_kyber_pk.data(), client_kyber_pk.size(),
            &server_handshake_msg, nullptr
        ) != EPP_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            epp_session_destroy(*out_client);
            epp_server_destroy(*out_server);
            *out_client = nullptr;
            *out_server = nullptr;
            return false;
        }

        if (epp_server_complete_handshake_auto(
            *out_server, client_handshake_msg.data, client_handshake_msg.length, nullptr
        ) != EPP_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            free_buffer_data(&server_handshake_msg);
            epp_session_destroy(*out_client);
            epp_server_destroy(*out_server);
            *out_client = nullptr;
            *out_server = nullptr;
            return false;
        }

        if (epp_session_complete_handshake_auto(
            *out_client, server_handshake_msg.data, server_handshake_msg.length, nullptr
        ) != EPP_SUCCESS) {
            free_buffer_data(&client_handshake_msg);
            free_buffer_data(&server_handshake_msg);
            epp_session_destroy(*out_client);
            epp_server_destroy(*out_server);
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
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Client sending message cannot decrypt it with same client") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* client_raw = nullptr;
        ProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        const std::string msg = "Test message";
        EppBuffer envelope{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == EPP_SUCCESS);

        EppBuffer plaintext{};
        EppError error{};
        const auto result = epp_session_decrypt(
            client_system.handle,
            envelope.data,
            envelope.length,
            &plaintext,
            &error
        );

        REQUIRE(result != EPP_SUCCESS);
        if (error.message) epp_error_free(&error);
        if (plaintext.data) free_buffer_data(&plaintext);

        free_buffer_data(&envelope);
    }

    epp_shutdown();
}

TEST_CASE("C API Role Validation - Server Cannot Decrypt Own Messages", "[c_api][role][server]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Server sending message cannot decrypt it with same server") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* client_raw = nullptr;
        ProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        const std::string init_msg = "Init message";
        EppBuffer init_env{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(init_msg.data()),
            init_msg.size(),
            &init_env, nullptr
        ) == EPP_SUCCESS);

        EppBuffer init_pt{};
        REQUIRE(epp_server_decrypt(
            server_system.handle, init_env.data, init_env.length, &init_pt, nullptr
        ) == EPP_SUCCESS);
        free_buffer_data(&init_env);
        free_buffer_data(&init_pt);

        const std::string msg = "Server message";
        EppBuffer envelope{};
        REQUIRE(epp_server_encrypt(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == EPP_SUCCESS);

        EppBuffer plaintext{};
        EppError error{};
        const auto result = epp_server_decrypt(
            server_system.handle,
            envelope.data,
            envelope.length,
            &plaintext,
            &error
        );

        REQUIRE(result != EPP_SUCCESS);
        if (error.message) epp_error_free(&error);
        if (plaintext.data) free_buffer_data(&plaintext);

        free_buffer_data(&envelope);
    }

    epp_shutdown();
}

TEST_CASE("C API Role Validation - Correct Direction Works", "[c_api][role][direction]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Client->Server and Server->Client both work correctly") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* client_raw = nullptr;
        ProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        const std::string client_msg = "From client";
        EppBuffer client_env{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(client_msg.data()),
            client_msg.size(),
            &client_env, nullptr
        ) == EPP_SUCCESS);

        EppBuffer server_pt{};
        REQUIRE(epp_server_decrypt(
            server_system.handle, client_env.data, client_env.length,
            &server_pt, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(server_pt.length == client_msg.size());
        REQUIRE(std::memcmp(server_pt.data, client_msg.data(), client_msg.size()) == 0);
        free_buffer_data(&client_env);
        free_buffer_data(&server_pt);

        const std::string server_msg = "From server";
        EppBuffer server_env{};
        REQUIRE(epp_server_encrypt(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(server_msg.data()),
            server_msg.size(),
            &server_env, nullptr
        ) == EPP_SUCCESS);

        EppBuffer client_pt{};
        REQUIRE(epp_session_decrypt(
            client_system.handle, server_env.data, server_env.length,
            &client_pt, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(client_pt.length == server_msg.size());
        REQUIRE(std::memcmp(client_pt.data, server_msg.data(), server_msg.size()) == 0);
        free_buffer_data(&server_env);
        free_buffer_data(&client_pt);
    }

    epp_shutdown();
}

TEST_CASE("C API Role Validation - Chain Asymmetry", "[c_api][role][chain]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Client and server have swapped send/receive chains") {
        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create(&client_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* client_raw = nullptr;
        ProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        for (int i = 0; i < 5; ++i) {
            std::string msg = "Msg " + std::to_string(i);
            EppBuffer env{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &env, nullptr
            ) == EPP_SUCCESS);

            EppBuffer pt{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, env.data, env.length, &pt, nullptr
            ) == EPP_SUCCESS);
            free_buffer_data(&env);
            free_buffer_data(&pt);
        }

        uint32_t client_send = 0, client_recv = 0;
        uint32_t server_send = 0, server_recv = 0;

        REQUIRE(epp_session_get_chain_indices(
            client_system.handle, &client_send, &client_recv, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(epp_server_get_chain_indices(
            server_system.handle, &server_send, &server_recv, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(client_send == 5);
        REQUIRE(client_recv == 0);

        REQUIRE(server_recv == 5);
        REQUIRE(server_send == 0);

        REQUIRE(client_send == server_recv);
    }

    epp_shutdown();
}

TEST_CASE("C API Role Validation - Cross-Session Messages Fail", "[c_api][role][cross-session]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Messages from one session cannot be decrypted by different session") {
        IdentityKeysGuard client1_keys;
        REQUIRE(epp_identity_create(&client1_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server1_keys;
        REQUIRE(epp_identity_create(&server1_keys.handle, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* client1_raw = nullptr;
        ProtocolSystemHandle* server1_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client1_keys.handle, server1_keys.handle, &client1_raw, &server1_raw));

        ClientSystemGuard client1;
        client1.handle = client1_raw;

        ServerSystemGuard server1;
        server1.handle = server1_raw;

        IdentityKeysGuard client2_keys;
        REQUIRE(epp_identity_create(&client2_keys.handle, nullptr) == EPP_SUCCESS);

        IdentityKeysGuard server2_keys;
        REQUIRE(epp_identity_create(&server2_keys.handle, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* client2_raw = nullptr;
        ProtocolSystemHandle* server2_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client2_keys.handle, server2_keys.handle, &client2_raw, &server2_raw));

        ClientSystemGuard client2;
        client2.handle = client2_raw;

        ServerSystemGuard server2;
        server2.handle = server2_raw;

        const std::string msg = "Session 1 message";
        EppBuffer envelope{};
        REQUIRE(epp_session_encrypt(
            client1.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == EPP_SUCCESS);

        EppBuffer plaintext{};
        EppError error{};
        const auto result = epp_server_decrypt(
            server2.handle,
            envelope.data,
            envelope.length,
            &plaintext,
            &error
        );

        REQUIRE(result != EPP_SUCCESS);
        if (error.message) epp_error_free(&error);
        if (plaintext.data) free_buffer_data(&plaintext);

        EppBuffer correct_pt{};
        REQUIRE(epp_server_decrypt(
            server1.handle, envelope.data, envelope.length, &correct_pt, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(correct_pt.length == msg.size());
        free_buffer_data(&correct_pt);

        free_buffer_data(&envelope);
    }

    epp_shutdown();
}
