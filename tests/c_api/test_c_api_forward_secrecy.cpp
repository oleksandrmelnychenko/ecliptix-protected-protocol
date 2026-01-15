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

TEST_CASE("C API Forward Secrecy - Old State Cannot Decrypt New Messages", "[c_api][forward-secrecy][critical]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Server state snapshot before DH ratchet cannot decrypt messages after ratchet") {
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

        for (int i = 0; i < 95; ++i) {
            std::string msg = "Message " + std::to_string(i);
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

        EppBuffer old_server_state{};
        REQUIRE(epp_server_serialize(
            server_system.handle, &old_server_state, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(old_server_state.data != nullptr);
        REQUIRE(old_server_state.length > 0);

        std::vector<uint8_t> old_state_vec(old_server_state.data, old_server_state.data + old_server_state.length);
        free_buffer_data(&old_server_state);

        std::vector<std::vector<uint8_t>> future_envelopes;
        for (int i = 95; i < 105; ++i) {
            std::string msg = "Message " + std::to_string(i);
            EppBuffer envelope{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == EPP_SUCCESS);

            future_envelopes.emplace_back(envelope.data, envelope.data + envelope.length);

            EppBuffer plaintext{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == EPP_SUCCESS);
            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        IdentityKeysGuard fresh_server_keys;
        REQUIRE(epp_identity_create_from_seed(
            server_seed.data(), server_seed.size(), &fresh_server_keys.handle, nullptr
        ) == EPP_SUCCESS);

        ProtocolSystemHandle* old_server_raw = nullptr;
        const auto import_result = epp_server_deserialize(
            fresh_server_keys.handle,
            old_state_vec.data(),
            old_state_vec.size(),
            &old_server_raw,
            nullptr
        );
        REQUIRE(import_result == EPP_SUCCESS);

        ServerSystemGuard old_server_system;
        old_server_system.handle = old_server_raw;

        const auto& last_envelope = future_envelopes.back();
        EppBuffer old_plaintext{};
        EppError error{};
        const auto decrypt_result = epp_server_decrypt(
            old_server_system.handle,
            last_envelope.data(),
            last_envelope.size(),
            &old_plaintext,
            &error
        );

        REQUIRE(decrypt_result != EPP_SUCCESS);
        if (error.message) epp_error_free(&error);
        if (old_plaintext.data) free_buffer_data(&old_plaintext);
    }

    epp_shutdown();
}

TEST_CASE("C API Forward Secrecy - Replay Prevention", "[c_api][forward-secrecy][replay]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Same message cannot be received twice") {
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

        const std::string msg = "Test message for replay";
        EppBuffer envelope{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            &envelope, nullptr
        ) == EPP_SUCCESS);

        std::vector<uint8_t> envelope_copy(envelope.data, envelope.data + envelope.length);

        EppBuffer plaintext1{};
        REQUIRE(epp_server_decrypt(
            server_system.handle, envelope.data, envelope.length,
            &plaintext1, nullptr
        ) == EPP_SUCCESS);
        free_buffer_data(&plaintext1);
        free_buffer_data(&envelope);

        EppBuffer plaintext2{};
        EppError error{};
        const auto replay_result = epp_server_decrypt(
            server_system.handle,
            envelope_copy.data(),
            envelope_copy.size(),
            &plaintext2,
            &error
        );

        REQUIRE(replay_result != EPP_SUCCESS);
        if (error.message) epp_error_free(&error);
        if (plaintext2.data) free_buffer_data(&plaintext2);
    }

    epp_shutdown();
}

TEST_CASE("C API Forward Secrecy - Chain Key Evolution", "[c_api][forward-secrecy][chain]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Each message uses a unique key (chain evolves)") {
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

        const std::string msg = "Identical message";
        std::vector<std::vector<uint8_t>> ciphertexts;

        for (int i = 0; i < 5; ++i) {
            EppBuffer envelope{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == EPP_SUCCESS);

            ciphertexts.emplace_back(envelope.data, envelope.data + envelope.length);

            EppBuffer plaintext{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == EPP_SUCCESS);
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

    epp_shutdown();
}

TEST_CASE("C API Forward Secrecy - Chain Index Increments", "[c_api][forward-secrecy][index]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Sending chain index increases with each message") {
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

        uint32_t prev_send_idx = 0;

        for (int i = 0; i < 10; ++i) {
            std::string msg = "Msg " + std::to_string(i);
            EppBuffer envelope{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == EPP_SUCCESS);

            uint32_t send_idx = 0, recv_idx = 0;
            REQUIRE(epp_session_get_chain_indices(
                client_system.handle, &send_idx, &recv_idx, nullptr
            ) == EPP_SUCCESS);

            REQUIRE(send_idx == static_cast<uint32_t>(i + 1));
            REQUIRE(send_idx > prev_send_idx);
            prev_send_idx = send_idx;

            EppBuffer plaintext{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == EPP_SUCCESS);
            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }
    }

    epp_shutdown();
}
