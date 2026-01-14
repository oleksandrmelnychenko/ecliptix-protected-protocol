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

TEST_CASE("C API Forward Secrecy - Old State Cannot Decrypt New Messages", "[c_api][forward-secrecy][critical]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Server state snapshot before DH ratchet cannot decrypt messages after ratchet") {
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

        for (int i = 0; i < 95; ++i) {
            std::string msg = "Message " + std::to_string(i);
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

        EcliptixBuffer old_server_state{};
        REQUIRE(ecliptix_protocol_server_system_export_state(
            server_system.handle, &old_server_state, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(old_server_state.data != nullptr);
        REQUIRE(old_server_state.length > 0);

        std::vector<uint8_t> old_state_vec(old_server_state.data, old_server_state.data + old_server_state.length);
        free_buffer_data(&old_server_state);

        std::vector<std::vector<uint8_t>> future_envelopes;
        for (int i = 95; i < 105; ++i) {
            std::string msg = "Message " + std::to_string(i);
            EcliptixBuffer envelope{};
            REQUIRE(ecliptix_protocol_system_send_message(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == ECLIPTIX_SUCCESS);

            future_envelopes.emplace_back(envelope.data, envelope.data + envelope.length);

            EcliptixBuffer plaintext{};
            REQUIRE(ecliptix_protocol_server_system_receive_message(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == ECLIPTIX_SUCCESS);
            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        IdentityKeysGuard fresh_server_keys;
        REQUIRE(ecliptix_identity_keys_create_from_seed(
            server_seed.data(), server_seed.size(), &fresh_server_keys.handle, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixProtocolSystemHandle* old_server_raw = nullptr;
        const auto import_result = ecliptix_protocol_server_system_import_state(
            fresh_server_keys.handle,
            old_state_vec.data(),
            old_state_vec.size(),
            &old_server_raw,
            nullptr
        );
        REQUIRE(import_result == ECLIPTIX_SUCCESS);

        ServerSystemGuard old_server_system;
        old_server_system.handle = old_server_raw;

        const auto& last_envelope = future_envelopes.back();
        EcliptixBuffer old_plaintext{};
        EcliptixError error{};
        const auto decrypt_result = ecliptix_protocol_server_system_receive_message(
            old_server_system.handle,
            last_envelope.data(),
            last_envelope.size(),
            &old_plaintext,
            &error
        );

        REQUIRE(decrypt_result != ECLIPTIX_SUCCESS);
        if (error.message) ecliptix_error_free(&error);
        if (old_plaintext.data) free_buffer_data(&old_plaintext);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Forward Secrecy - Replay Prevention", "[c_api][forward-secrecy][replay]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Same message cannot be received twice") {
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

        const std::string msg = "Test message for replay";
        EcliptixBuffer envelope{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == ECLIPTIX_SUCCESS);

        std::vector<uint8_t> envelope_copy(envelope.data, envelope.data + envelope.length);

        EcliptixBuffer plaintext1{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            server_system.handle, envelope.data, envelope.length,
            &plaintext1, nullptr
        ) == ECLIPTIX_SUCCESS);
        free_buffer_data(&plaintext1);
        free_buffer_data(&envelope);

        EcliptixBuffer plaintext2{};
        EcliptixError error{};
        const auto replay_result = ecliptix_protocol_server_system_receive_message(
            server_system.handle,
            envelope_copy.data(),
            envelope_copy.size(),
            &plaintext2,
            &error
        );

        REQUIRE(replay_result != ECLIPTIX_SUCCESS);
        if (error.message) ecliptix_error_free(&error);
        if (plaintext2.data) free_buffer_data(&plaintext2);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Forward Secrecy - Chain Key Evolution", "[c_api][forward-secrecy][chain]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Each message uses a unique key (chain evolves)") {
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

        const std::string msg = "Identical message";
        std::vector<std::vector<uint8_t>> ciphertexts;

        for (int i = 0; i < 5; ++i) {
            EcliptixBuffer envelope{};
            REQUIRE(ecliptix_protocol_system_send_message(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == ECLIPTIX_SUCCESS);

            ciphertexts.emplace_back(envelope.data, envelope.data + envelope.length);

            EcliptixBuffer plaintext{};
            REQUIRE(ecliptix_protocol_server_system_receive_message(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == ECLIPTIX_SUCCESS);
            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        for (size_t i = 0; i < ciphertexts.size(); ++i) {
            for (size_t j = i + 1; j < ciphertexts.size(); ++j) {
                if (ciphertexts[i].size() == ciphertexts[j].size()) {
                    REQUIRE(std::memcmp(
                        ciphertexts[i].data(),
                        ciphertexts[j].data(),
                        ciphertexts[i].size()
                    ) != 0);
                }
            }
        }
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Forward Secrecy - Chain Index Increments", "[c_api][forward-secrecy][index]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Sending chain index increases with each message") {
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

        uint32_t prev_send_idx = 0;

        for (int i = 0; i < 10; ++i) {
            std::string msg = "Msg " + std::to_string(i);
            EcliptixBuffer envelope{};
            REQUIRE(ecliptix_protocol_system_send_message(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == ECLIPTIX_SUCCESS);

            uint32_t send_idx = 0, recv_idx = 0;
            REQUIRE(ecliptix_protocol_system_get_chain_indices(
                client_system.handle, &send_idx, &recv_idx, nullptr
            ) == ECLIPTIX_SUCCESS);

            REQUIRE(send_idx == static_cast<uint32_t>(i + 1));
            REQUIRE(send_idx > prev_send_idx);
            prev_send_idx = send_idx;

            EcliptixBuffer plaintext{};
            REQUIRE(ecliptix_protocol_server_system_receive_message(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == ECLIPTIX_SUCCESS);
            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }
    }

    ecliptix_shutdown();
}
