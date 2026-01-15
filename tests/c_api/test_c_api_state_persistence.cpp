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

    EppErrorCode epp_server_serialize(
        ProtocolSystemHandle* handle,
        EppBuffer* out_state,
        EppError* out_error);

    EppErrorCode epp_server_deserialize(
        EppIdentityHandle* identity_keys,
        const uint8_t* state_bytes,
        size_t state_bytes_length,
        ProtocolSystemHandle** out_handle,
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
        if (epp_server_begin_handshake(
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

TEST_CASE("C API State Persistence - Client Export/Import", "[c_api][persistence][client]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Client can export and import state, continue messaging") {
        std::vector<uint8_t> client_seed(32, 0xAA);
        std::vector<uint8_t> server_seed(32, 0xBB);

        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys.handle, nullptr
        ) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create_from_seed(
            server_seed.data(), server_seed.size(), &server_keys.handle, nullptr
        ) == EPP_SUCCESS);

        ProtocolSystemHandle* client_raw = nullptr;
        ProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        for (int i = 0; i < 5; ++i) {
            std::string msg = "Msg " + std::to_string(i);
            EppBuffer envelope{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == EPP_SUCCESS);

            EppBuffer plaintext{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == EPP_SUCCESS);
            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        EppBuffer client_state{};
        REQUIRE(epp_session_serialize(
            client_system.handle, &client_state, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(client_state.data != nullptr);
        REQUIRE(client_state.length > 0);

        std::vector<uint8_t> saved_state(client_state.data, client_state.data + client_state.length);
        uint32_t original_send_idx = 0, original_recv_idx = 0;
        REQUIRE(epp_session_get_chain_indices(
            client_system.handle, &original_send_idx, &original_recv_idx, nullptr
        ) == EPP_SUCCESS);
        free_buffer_data(&client_state);

        client_system.handle = nullptr;
        epp_session_destroy(client_raw);

        IdentityKeysGuard fresh_client_keys;
        REQUIRE(epp_identity_create_from_seed(
            client_seed.data(), client_seed.size(), &fresh_client_keys.handle, nullptr
        ) == EPP_SUCCESS);

        ProtocolSystemHandle* restored_client = nullptr;
        REQUIRE(epp_session_deserialize(
            fresh_client_keys.handle,
            saved_state.data(),
            saved_state.size(),
            &restored_client,
            nullptr
        ) == EPP_SUCCESS);

        ClientSystemGuard restored_client_guard;
        restored_client_guard.handle = restored_client;

        uint32_t restored_send_idx = 0, restored_recv_idx = 0;
        REQUIRE(epp_session_get_chain_indices(
            restored_client_guard.handle, &restored_send_idx, &restored_recv_idx, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(restored_send_idx == original_send_idx);
        REQUIRE(restored_recv_idx == original_recv_idx);

        const std::string msg = "Message from restored client";
        EppBuffer envelope{};
        REQUIRE(epp_session_encrypt(
            restored_client_guard.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == EPP_SUCCESS);

        EppBuffer plaintext{};
        REQUIRE(epp_server_decrypt(
            server_system.handle, envelope.data, envelope.length,
            &plaintext, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(plaintext.length == msg.size());
        REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

        free_buffer_data(&envelope);
        free_buffer_data(&plaintext);
    }

    epp_shutdown();
}

TEST_CASE("C API State Persistence - Server Export/Import", "[c_api][persistence][server]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Server can export and import state, continue messaging") {
        std::vector<uint8_t> client_seed(32, 0xCC);
        std::vector<uint8_t> server_seed(32, 0xDD);

        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys.handle, nullptr
        ) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create_from_seed(
            server_seed.data(), server_seed.size(), &server_keys.handle, nullptr
        ) == EPP_SUCCESS);

        ProtocolSystemHandle* client_raw = nullptr;
        ProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        for (int i = 0; i < 5; ++i) {
            std::string msg = "Msg " + std::to_string(i);
            EppBuffer envelope{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == EPP_SUCCESS);

            EppBuffer plaintext{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == EPP_SUCCESS);
            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        EppBuffer server_state{};
        REQUIRE(epp_server_serialize(
            server_system.handle, &server_state, nullptr
        ) == EPP_SUCCESS);

        std::vector<uint8_t> saved_state(server_state.data, server_state.data + server_state.length);
        uint32_t original_send_idx = 0, original_recv_idx = 0;
        REQUIRE(epp_server_get_chain_indices(
            server_system.handle, &original_send_idx, &original_recv_idx, nullptr
        ) == EPP_SUCCESS);
        free_buffer_data(&server_state);

        server_system.handle = nullptr;
        epp_server_destroy(server_raw);

        IdentityKeysGuard fresh_server_keys;
        REQUIRE(epp_identity_create_from_seed(
            server_seed.data(), server_seed.size(), &fresh_server_keys.handle, nullptr
        ) == EPP_SUCCESS);

        ProtocolSystemHandle* restored_server = nullptr;
        REQUIRE(epp_server_deserialize(
            fresh_server_keys.handle,
            saved_state.data(),
            saved_state.size(),
            &restored_server,
            nullptr
        ) == EPP_SUCCESS);

        ServerSystemGuard restored_server_guard;
        restored_server_guard.handle = restored_server;

        uint32_t restored_send_idx = 0, restored_recv_idx = 0;
        REQUIRE(epp_server_get_chain_indices(
            restored_server_guard.handle, &restored_send_idx, &restored_recv_idx, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(restored_send_idx == original_send_idx);
        REQUIRE(restored_recv_idx == original_recv_idx);

        const std::string msg = "Message to restored server";
        EppBuffer envelope{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == EPP_SUCCESS);

        EppBuffer plaintext{};
        REQUIRE(epp_server_decrypt(
            restored_server_guard.handle, envelope.data, envelope.length,
            &plaintext, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(plaintext.length == msg.size());
        REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

        free_buffer_data(&envelope);
        free_buffer_data(&plaintext);
    }

    epp_shutdown();
}

TEST_CASE("C API State Persistence - Corrupted State Rejection", "[c_api][persistence][corruption]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Import rejects corrupted state data") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> garbage(100, 0xFF);
        ProtocolSystemHandle* system = nullptr;
        EppError error{};

        const auto result = epp_session_deserialize(
            keys.handle,
            garbage.data(),
            garbage.size(),
            &system,
            &error
        );

        REQUIRE(result != EPP_SUCCESS);
        REQUIRE(system == nullptr);
        if (error.message) epp_error_free(&error);
    }

    SECTION("Import rejects empty state data") {
        IdentityKeysGuard keys;
        REQUIRE(epp_identity_create(&keys.handle, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* system = nullptr;
        EppError error{};

        const auto result = epp_session_deserialize(
            keys.handle,
            nullptr,
            0,
            &system,
            &error
        );

        REQUIRE(result == EPP_ERROR_NULL_POINTER);
        if (error.message) epp_error_free(&error);
    }

    SECTION("Import rejects truncated state data") {
        std::vector<uint8_t> client_seed(32, 0xEE);

        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys.handle, nullptr
        ) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create(&server_keys.handle, nullptr) == EPP_SUCCESS);

        ProtocolSystemHandle* client_raw = nullptr;
        ProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        EppBuffer client_state{};
        REQUIRE(epp_session_serialize(
            client_system.handle, &client_state, nullptr
        ) == EPP_SUCCESS);

        size_t truncated_len = client_state.length / 2;
        std::vector<uint8_t> truncated_state(client_state.data, client_state.data + truncated_len);
        free_buffer_data(&client_state);

        IdentityKeysGuard fresh_keys;
        REQUIRE(epp_identity_create_from_seed(
            client_seed.data(), client_seed.size(), &fresh_keys.handle, nullptr
        ) == EPP_SUCCESS);

        ProtocolSystemHandle* system = nullptr;
        EppError error{};

        const auto result = epp_session_deserialize(
            fresh_keys.handle,
            truncated_state.data(),
            truncated_state.size(),
            &system,
            &error
        );

        REQUIRE(result != EPP_SUCCESS);
        if (error.message) epp_error_free(&error);
        if (system) epp_session_destroy(system);
    }

    epp_shutdown();
}

TEST_CASE("C API State Persistence - Mid-Conversation Resume", "[c_api][persistence][resume]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Both sides can export, restart, import, and continue") {
        std::vector<uint8_t> client_seed(32, 0x11);
        std::vector<uint8_t> server_seed(32, 0x22);

        IdentityKeysGuard client_keys;
        REQUIRE(epp_identity_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys.handle, nullptr
        ) == EPP_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(epp_identity_create_from_seed(
            server_seed.data(), server_seed.size(), &server_keys.handle, nullptr
        ) == EPP_SUCCESS);

        ProtocolSystemHandle* client_raw = nullptr;
        ProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        for (int round = 0; round < 3; ++round) {
            std::string c_msg = "C->S round " + std::to_string(round);
            EppBuffer c_env{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(c_msg.data()),
                c_msg.size(),
                &c_env, nullptr
            ) == EPP_SUCCESS);

            EppBuffer s_pt{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, c_env.data, c_env.length, &s_pt, nullptr
            ) == EPP_SUCCESS);
            free_buffer_data(&c_env);
            free_buffer_data(&s_pt);

            std::string s_msg = "S->C round " + std::to_string(round);
            EppBuffer s_env{};
            REQUIRE(epp_server_encrypt(
                server_system.handle,
                reinterpret_cast<const uint8_t*>(s_msg.data()),
                s_msg.size(),
                &s_env, nullptr
            ) == EPP_SUCCESS);

            EppBuffer c_pt{};
            REQUIRE(epp_session_decrypt(
                client_system.handle, s_env.data, s_env.length, &c_pt, nullptr
            ) == EPP_SUCCESS);
            free_buffer_data(&s_env);
            free_buffer_data(&c_pt);
        }

        EppBuffer client_state{};
        EppBuffer server_state{};
        REQUIRE(epp_session_serialize(client_system.handle, &client_state, nullptr) == EPP_SUCCESS);
        REQUIRE(epp_server_serialize(server_system.handle, &server_state, nullptr) == EPP_SUCCESS);

        std::vector<uint8_t> saved_client(client_state.data, client_state.data + client_state.length);
        std::vector<uint8_t> saved_server(server_state.data, server_state.data + server_state.length);
        free_buffer_data(&client_state);
        free_buffer_data(&server_state);

        client_system.handle = nullptr;
        server_system.handle = nullptr;
        epp_session_destroy(client_raw);
        epp_server_destroy(server_raw);

        IdentityKeysGuard fresh_client_keys;
        REQUIRE(epp_identity_create_from_seed(
            client_seed.data(), client_seed.size(), &fresh_client_keys.handle, nullptr
        ) == EPP_SUCCESS);

        IdentityKeysGuard fresh_server_keys;
        REQUIRE(epp_identity_create_from_seed(
            server_seed.data(), server_seed.size(), &fresh_server_keys.handle, nullptr
        ) == EPP_SUCCESS);

        ProtocolSystemHandle* restored_client = nullptr;
        ProtocolSystemHandle* restored_server = nullptr;

        REQUIRE(epp_session_deserialize(
            fresh_client_keys.handle, saved_client.data(), saved_client.size(),
            &restored_client, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(epp_server_deserialize(
            fresh_server_keys.handle, saved_server.data(), saved_server.size(),
            &restored_server, nullptr
        ) == EPP_SUCCESS);

        ClientSystemGuard restored_client_guard;
        restored_client_guard.handle = restored_client;

        ServerSystemGuard restored_server_guard;
        restored_server_guard.handle = restored_server;

        const std::string msg = "Message after restore";
        EppBuffer envelope{};
        REQUIRE(epp_session_encrypt(
            restored_client_guard.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == EPP_SUCCESS);

        EppBuffer plaintext{};
        REQUIRE(epp_server_decrypt(
            restored_server_guard.handle, envelope.data, envelope.length,
            &plaintext, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(plaintext.length == msg.size());
        REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

        free_buffer_data(&envelope);
        free_buffer_data(&plaintext);
    }

    epp_shutdown();
}
