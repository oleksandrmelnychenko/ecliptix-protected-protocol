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

    EcliptixErrorCode ecliptix_protocol_server_system_export_state(
        EcliptixProtocolSystemHandle* handle,
        EcliptixBuffer* out_state,
        EcliptixError* out_error);

    EcliptixErrorCode ecliptix_protocol_server_system_import_state(
        EcliptixIdentityKeysHandle* identity_keys,
        const uint8_t* state_bytes,
        size_t state_bytes_length,
        EcliptixProtocolSystemHandle** out_handle,
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

TEST_CASE("C API State Persistence - Client Export/Import", "[c_api][persistence][client]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Client can export and import state, continue messaging") {
        std::vector<uint8_t> client_seed(32, 0xAA);
        std::vector<uint8_t> server_seed(32, 0xBB);

        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            server_seed.data(), server_seed.size(), &server_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* client_raw = nullptr;
        EcliptixProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        for (int i = 0; i < 5; ++i) {
            std::string msg = "Msg " + std::to_string(i);
            EcliptixBuffer envelope{};
            REQUIRE(ecliptix_protocol_system_send_message(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == ECLIPTIX_SUCCESS);

            EcliptixBuffer plaintext{};
            REQUIRE(ecliptix_protocol_server_system_receive_message(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == ECLIPTIX_SUCCESS);
            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        EcliptixBuffer client_state{};
        REQUIRE(ecliptix_protocol_system_export_state(
            client_system.handle, &client_state, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(client_state.data != nullptr);
        REQUIRE(client_state.length > 0);

        std::vector<uint8_t> saved_state(client_state.data, client_state.data + client_state.length);
        uint32_t original_send_idx = 0, original_recv_idx = 0;
        REQUIRE(ecliptix_protocol_system_get_chain_indices(
            client_system.handle, &original_send_idx, &original_recv_idx, nullptr
        ) == ECLIPTIX_SUCCESS);
        free_buffer_data(&client_state);

        client_system.handle = nullptr;
        ecliptix_protocol_system_destroy(client_raw);

        IdentityKeysGuard fresh_client_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            client_seed.data(), client_seed.size(), &fresh_client_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* restored_client = nullptr;
        REQUIRE(ecliptix_protocol_system_import_state(
            fresh_client_keys.handle,
            saved_state.data(),
            saved_state.size(),
            &restored_client,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        ClientSystemGuard restored_client_guard;
        restored_client_guard.handle = restored_client;

        uint32_t restored_send_idx = 0, restored_recv_idx = 0;
        REQUIRE(ecliptix_protocol_system_get_chain_indices(
            restored_client_guard.handle, &restored_send_idx, &restored_recv_idx, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(restored_send_idx == original_send_idx);
        REQUIRE(restored_recv_idx == original_recv_idx);

        const std::string msg = "Message from restored client";
        EcliptixBuffer envelope{};
        REQUIRE(ecliptix_protocol_system_send_message(
            restored_client_guard.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer plaintext{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            server_system.handle, envelope.data, envelope.length,
            &plaintext, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(plaintext.length == msg.size());
        REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

        free_buffer_data(&envelope);
        free_buffer_data(&plaintext);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API State Persistence - Server Export/Import", "[c_api][persistence][server]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Server can export and import state, continue messaging") {
        std::vector<uint8_t> client_seed(32, 0xCC);
        std::vector<uint8_t> server_seed(32, 0xDD);

        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            server_seed.data(), server_seed.size(), &server_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* client_raw = nullptr;
        EcliptixProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        for (int i = 0; i < 5; ++i) {
            std::string msg = "Msg " + std::to_string(i);
            EcliptixBuffer envelope{};
            REQUIRE(ecliptix_protocol_system_send_message(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == ECLIPTIX_SUCCESS);

            EcliptixBuffer plaintext{};
            REQUIRE(ecliptix_protocol_server_system_receive_message(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == ECLIPTIX_SUCCESS);
            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        EcliptixBuffer server_state{};
        REQUIRE(ecliptix_protocol_server_system_export_state(
            server_system.handle, &server_state, nullptr
        ) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> saved_state(server_state.data, server_state.data + server_state.length);
        uint32_t original_send_idx = 0, original_recv_idx = 0;
        REQUIRE(ecliptix_protocol_server_system_get_chain_indices(
            server_system.handle, &original_send_idx, &original_recv_idx, nullptr
        ) == ECLIPTIX_SUCCESS);
        free_buffer_data(&server_state);

        server_system.handle = nullptr;
        ecliptix_protocol_server_system_destroy(server_raw);

        IdentityKeysGuard fresh_server_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            server_seed.data(), server_seed.size(), &fresh_server_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* restored_server = nullptr;
        REQUIRE(ecliptix_protocol_server_system_import_state(
            fresh_server_keys.handle,
            saved_state.data(),
            saved_state.size(),
            &restored_server,
            nullptr
        ) == ECLIPTIX_SUCCESS);

        ServerSystemGuard restored_server_guard;
        restored_server_guard.handle = restored_server;

        uint32_t restored_send_idx = 0, restored_recv_idx = 0;
        REQUIRE(ecliptix_protocol_server_system_get_chain_indices(
            restored_server_guard.handle, &restored_send_idx, &restored_recv_idx, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(restored_send_idx == original_send_idx);
        REQUIRE(restored_recv_idx == original_recv_idx);

        const std::string msg = "Message to restored server";
        EcliptixBuffer envelope{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer plaintext{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            restored_server_guard.handle, envelope.data, envelope.length,
            &plaintext, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(plaintext.length == msg.size());
        REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

        free_buffer_data(&envelope);
        free_buffer_data(&plaintext);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API State Persistence - Corrupted State Rejection", "[c_api][persistence][corruption]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Import rejects corrupted state data") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> garbage(100, 0xFF);
        EcliptixProtocolSystemHandle* system = nullptr;
        EcliptixError error{};

        const auto result = ecliptix_protocol_system_import_state(
            keys.handle,
            garbage.data(),
            garbage.size(),
            &system,
            &error
        );

        REQUIRE(result != ECLIPTIX_SUCCESS);
        REQUIRE(system == nullptr);
        if (error.message) ecliptix_error_free(&error);
    }

    SECTION("Import rejects empty state data") {
        IdentityKeysGuard keys;
        REQUIRE(ecliptix_identity_keys_create(&keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* system = nullptr;
        EcliptixError error{};

        const auto result = ecliptix_protocol_system_import_state(
            keys.handle,
            nullptr,
            0,
            &system,
            &error
        );

        REQUIRE(result == ECLIPTIX_ERROR_NULL_POINTER);
        if (error.message) ecliptix_error_free(&error);
    }

    SECTION("Import rejects truncated state data") {
        std::vector<uint8_t> client_seed(32, 0xEE);

        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create(&server_keys.handle, nullptr) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* client_raw = nullptr;
        EcliptixProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        EcliptixBuffer client_state{};
        REQUIRE(ecliptix_protocol_system_export_state(
            client_system.handle, &client_state, nullptr
        ) == ECLIPTIX_SUCCESS);

        size_t truncated_len = client_state.length / 2;
        std::vector<uint8_t> truncated_state(client_state.data, client_state.data + truncated_len);
        free_buffer_data(&client_state);

        IdentityKeysGuard fresh_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            client_seed.data(), client_seed.size(), &fresh_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* system = nullptr;
        EcliptixError error{};

        const auto result = ecliptix_protocol_system_import_state(
            fresh_keys.handle,
            truncated_state.data(),
            truncated_state.size(),
            &system,
            &error
        );

        REQUIRE(result != ECLIPTIX_SUCCESS);
        if (error.message) ecliptix_error_free(&error);
        if (system) ecliptix_protocol_system_destroy(system);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API State Persistence - Mid-Conversation Resume", "[c_api][persistence][resume]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Both sides can export, restart, import, and continue") {
        std::vector<uint8_t> client_seed(32, 0x11);
        std::vector<uint8_t> server_seed(32, 0x22);

        IdentityKeysGuard client_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            client_seed.data(), client_seed.size(), &client_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard server_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            server_seed.data(), server_seed.size(), &server_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* client_raw = nullptr;
        EcliptixProtocolSystemHandle* server_raw = nullptr;
        REQUIRE(SetupHandshakedPair(client_keys.handle, server_keys.handle, &client_raw, &server_raw));

        ClientSystemGuard client_system;
        client_system.handle = client_raw;

        ServerSystemGuard server_system;
        server_system.handle = server_raw;

        for (int round = 0; round < 3; ++round) {
            std::string c_msg = "C->S round " + std::to_string(round);
            EcliptixBuffer c_env{};
            REQUIRE(ecliptix_protocol_system_send_message(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(c_msg.data()),
                c_msg.size(),
                &c_env, nullptr
            ) == ECLIPTIX_SUCCESS);

            EcliptixBuffer s_pt{};
            REQUIRE(ecliptix_protocol_server_system_receive_message(
                server_system.handle, c_env.data, c_env.length, &s_pt, nullptr
            ) == ECLIPTIX_SUCCESS);
            free_buffer_data(&c_env);
            free_buffer_data(&s_pt);

            std::string s_msg = "S->C round " + std::to_string(round);
            EcliptixBuffer s_env{};
            REQUIRE(ecliptix_protocol_server_system_send_message(
                server_system.handle,
                reinterpret_cast<const uint8_t*>(s_msg.data()),
                s_msg.size(),
                &s_env, nullptr
            ) == ECLIPTIX_SUCCESS);

            EcliptixBuffer c_pt{};
            REQUIRE(ecliptix_protocol_system_receive_message(
                client_system.handle, s_env.data, s_env.length, &c_pt, nullptr
            ) == ECLIPTIX_SUCCESS);
            free_buffer_data(&s_env);
            free_buffer_data(&c_pt);
        }

        EcliptixBuffer client_state{};
        EcliptixBuffer server_state{};
        REQUIRE(ecliptix_protocol_system_export_state(client_system.handle, &client_state, nullptr) == ECLIPTIX_SUCCESS);
        REQUIRE(ecliptix_protocol_server_system_export_state(server_system.handle, &server_state, nullptr) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> saved_client(client_state.data, client_state.data + client_state.length);
        std::vector<uint8_t> saved_server(server_state.data, server_state.data + server_state.length);
        free_buffer_data(&client_state);
        free_buffer_data(&server_state);

        client_system.handle = nullptr;
        server_system.handle = nullptr;
        ecliptix_protocol_system_destroy(client_raw);
        ecliptix_protocol_server_system_destroy(server_raw);

        IdentityKeysGuard fresh_client_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            client_seed.data(), client_seed.size(), &fresh_client_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        IdentityKeysGuard fresh_server_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            server_seed.data(), server_seed.size(), &fresh_server_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* restored_client = nullptr;
        EcliptixProtocolSystemHandle* restored_server = nullptr;

        REQUIRE(ecliptix_protocol_system_import_state(
            fresh_client_keys.handle, saved_client.data(), saved_client.size(),
            &restored_client, nullptr
        ) == ECLIPTIX_SUCCESS);

        REQUIRE(ecliptix_protocol_server_system_import_state(
            fresh_server_keys.handle, saved_server.data(), saved_server.size(),
            &restored_server, nullptr
        ) == ECLIPTIX_SUCCESS);

        ClientSystemGuard restored_client_guard;
        restored_client_guard.handle = restored_client;

        ServerSystemGuard restored_server_guard;
        restored_server_guard.handle = restored_server;

        const std::string msg = "Message after restore";
        EcliptixBuffer envelope{};
        REQUIRE(ecliptix_protocol_system_send_message(
            restored_client_guard.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer plaintext{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            restored_server_guard.handle, envelope.data, envelope.length,
            &plaintext, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(plaintext.length == msg.size());
        REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

        free_buffer_data(&envelope);
        free_buffer_data(&plaintext);
    }

    ecliptix_shutdown();
}
