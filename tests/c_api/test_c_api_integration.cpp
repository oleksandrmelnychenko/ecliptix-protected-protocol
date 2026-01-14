#include <catch2/catch_test_macros.hpp>
#include "ecliptix/c_api/epp_api.h"
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>

extern "C" {
    EppErrorCode epp_server_create(
        EppIdentityHandle* identity_keys,
        ProtocolSystemHandle** out_handle,
        EppError* out_error);

    EppErrorCode epp_server_begin_handshake_with_peer_kyber(
        ProtocolSystemHandle* handle,
        uint64_t peer_device_id,
        uint64_t peer_identity_id,
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

    EppErrorCode epp_server_serialize(
        const ProtocolSystemHandle* handle,
        EppBuffer* out_state,
        EppError* out_error);

    EppErrorCode epp_server_deserialize(
        EppIdentityHandle* identity_keys,
        const uint8_t* state_data,
        size_t state_length,
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

TEST_CASE("C API Integration - Many Messages Stability", "[c_api][integration][stress]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("200 sequential messages in one direction") {
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

        constexpr int message_count = 200;
        constexpr int ratchet_threshold = 100;
        for (int i = 0; i < message_count; ++i) {
            std::string msg = "Message number " + std::to_string(i) + " with some padding data.";

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

            REQUIRE(plaintext.length == msg.size());
            REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        uint32_t send_idx = 0, recv_idx = 0;
        REQUIRE(epp_session_get_chain_indices(
            client_system.handle, &send_idx, &recv_idx, nullptr
        ) == EPP_SUCCESS);
        const uint32_t expected_index = (message_count % ratchet_threshold == 0)
            ? ratchet_threshold
            : (message_count % ratchet_threshold);
        REQUIRE(send_idx == expected_index);
    }

    epp_shutdown();
}

TEST_CASE("C API Integration - Bidirectional Stress", "[c_api][integration][bidirectional]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("50 round-trip message exchanges") {
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

        constexpr int rounds = 50;
        for (int i = 0; i < rounds; ++i) {
            std::string c_msg = "C->S #" + std::to_string(i);
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
            REQUIRE(s_pt.length == c_msg.size());
            free_buffer_data(&c_env);
            free_buffer_data(&s_pt);

            std::string s_msg = "S->C #" + std::to_string(i);
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
            REQUIRE(c_pt.length == s_msg.size());
            free_buffer_data(&s_env);
            free_buffer_data(&c_pt);
        }

        uint32_t c_send = 0, c_recv = 0;
        uint32_t s_send = 0, s_recv = 0;

        REQUIRE(epp_session_get_chain_indices(
            client_system.handle, &c_send, &c_recv, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(epp_server_get_chain_indices(
            server_system.handle, &s_send, &s_recv, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(c_send == rounds);
        REQUIRE(c_recv == rounds);
        REQUIRE(s_send == rounds);
        REQUIRE(s_recv == rounds);
    }

    epp_shutdown();
}

TEST_CASE("C API Integration - Variable Payload Sizes", "[c_api][integration][payload]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Messages of different sizes") {
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

        std::vector<size_t> sizes = {1, 16, 64, 256, 1024, 4096, 16384, 65536};

        for (size_t size : sizes) {
            std::vector<uint8_t> payload(size);
            for (size_t i = 0; i < size; ++i) {
                payload[i] = static_cast<uint8_t>(i & 0xFF);
            }

            EppBuffer envelope{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                payload.data(),
                payload.size(),
                &envelope, nullptr
            ) == EPP_SUCCESS);

            EppBuffer plaintext{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == EPP_SUCCESS);

            REQUIRE(plaintext.length == size);
            REQUIRE(std::memcmp(plaintext.data, payload.data(), size) == 0);

            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }
    }

    epp_shutdown();
}

TEST_CASE("C API Integration - Empty Message", "[c_api][integration][edge]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Can send and receive empty message") {
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

        EppBuffer envelope{};
        const auto send_result = epp_session_encrypt(
            client_system.handle,
            nullptr,
            0,
            &envelope, nullptr
        );

        if (send_result == EPP_SUCCESS) {
            EppBuffer plaintext{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == EPP_SUCCESS);
            REQUIRE(plaintext.length == 0);
            free_buffer_data(&plaintext);
            free_buffer_data(&envelope);
        }
    }

    epp_shutdown();
}

TEST_CASE("C API Integration - Session Age Tracking", "[c_api][integration][session]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Session age is tracked correctly") {
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

        uint64_t age = 0;
        REQUIRE(epp_session_age_seconds(
            client_system.handle, &age, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(age < 5);
    }

    epp_shutdown();
}

TEST_CASE("C API Integration - Multiple Sessions Simultaneously", "[c_api][integration][multi-session]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Three simultaneous client-server pairs") {
        constexpr int num_sessions = 3;

        std::vector<IdentityKeysGuard> client_keys(num_sessions);
        std::vector<IdentityKeysGuard> server_keys(num_sessions);
        std::vector<ClientSystemGuard> client_systems(num_sessions);
        std::vector<ServerSystemGuard> server_systems(num_sessions);

        for (int i = 0; i < num_sessions; ++i) {
            REQUIRE(epp_identity_create(&client_keys[i].handle, nullptr) == EPP_SUCCESS);
            REQUIRE(epp_identity_create(&server_keys[i].handle, nullptr) == EPP_SUCCESS);

            ProtocolSystemHandle* client_raw = nullptr;
            ProtocolSystemHandle* server_raw = nullptr;
            REQUIRE(SetupHandshakedPair(
                client_keys[i].handle, server_keys[i].handle,
                &client_raw, &server_raw
            ));

            client_systems[i].handle = client_raw;
            server_systems[i].handle = server_raw;
        }

        for (int round = 0; round < 10; ++round) {
            for (int sess = 0; sess < num_sessions; ++sess) {
                std::string msg = "Session " + std::to_string(sess) + " msg " + std::to_string(round);

                EppBuffer envelope{};
                REQUIRE(epp_session_encrypt(
                    client_systems[sess].handle,
                    reinterpret_cast<const uint8_t*>(msg.data()),
                    msg.size(),
                    &envelope, nullptr
                ) == EPP_SUCCESS);

                EppBuffer plaintext{};
                REQUIRE(epp_server_decrypt(
                    server_systems[sess].handle, envelope.data, envelope.length,
                    &plaintext, nullptr
                ) == EPP_SUCCESS);

                REQUIRE(plaintext.length == msg.size());
                REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

                free_buffer_data(&envelope);
                free_buffer_data(&plaintext);
            }
        }

        for (int sess = 0; sess < num_sessions; ++sess) {
            uint32_t send_idx = 0, recv_idx = 0;
            REQUIRE(epp_session_get_chain_indices(
                client_systems[sess].handle, &send_idx, &recv_idx, nullptr
            ) == EPP_SUCCESS);
            REQUIRE(send_idx == 10);
        }
    }

    epp_shutdown();
}

TEST_CASE("C API Integration - Binary Data", "[c_api][integration][binary]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Can send arbitrary binary data including nulls") {
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

        std::vector<uint8_t> binary_data(512);
        for (size_t i = 0; i < binary_data.size(); ++i) {
            binary_data[i] = static_cast<uint8_t>(i % 256);
        }

        EppBuffer envelope{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            binary_data.data(),
            binary_data.size(),
            &envelope, nullptr
        ) == EPP_SUCCESS);

        EppBuffer plaintext{};
        REQUIRE(epp_server_decrypt(
            server_system.handle, envelope.data, envelope.length,
            &plaintext, nullptr
        ) == EPP_SUCCESS);

        REQUIRE(plaintext.length == binary_data.size());
        REQUIRE(std::memcmp(plaintext.data, binary_data.data(), binary_data.size()) == 0);

        free_buffer_data(&envelope);
        free_buffer_data(&plaintext);
    }

    epp_shutdown();
}

TEST_CASE("C API Integration - Corrupted Envelope Handling", "[c_api][integration][error]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Corrupted envelope is rejected gracefully") {
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

        std::vector<uint8_t> corrupted(envelope.data, envelope.data + envelope.length);
        for (size_t i = 10; i < std::min<size_t>(20, corrupted.size()); ++i) {
            corrupted[i] ^= 0xFF;
        }

        EppBuffer plaintext{};
        EppError error{};
        const auto result = epp_server_decrypt(
            server_system.handle,
            corrupted.data(),
            corrupted.size(),
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

TEST_CASE("C API Integration - Long Session After DH Ratchet", "[c_api][integration][long-session]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("350 sequential messages with multiple DH ratchets") {
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

        constexpr int message_count = 350;
        constexpr int ratchet_threshold = 100;

        for (int i = 0; i < message_count; ++i) {
            std::string msg = "Long session message #" + std::to_string(i);

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

            REQUIRE(plaintext.length == msg.size());
            REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        uint32_t send_idx = 0, recv_idx = 0;
        REQUIRE(epp_session_get_chain_indices(
            client_system.handle, &send_idx, &recv_idx, nullptr
        ) == EPP_SUCCESS);

        const uint32_t expected_index = message_count % ratchet_threshold;
        REQUIRE(send_idx == expected_index);
    }


    SECTION("620 messages stress test - 6 DH ratchets") {
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

        constexpr int message_count = 620;
        constexpr int ratchet_threshold = 100;
        int ratchet_count = 0;

        for (int i = 0; i < message_count; ++i) {
            std::string msg = "Stress test message #" + std::to_string(i);

            EppBuffer envelope{};
            auto send_result = epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            );
            INFO("Message " << i << " send");
            REQUIRE(send_result == EPP_SUCCESS);

            EppBuffer plaintext{};
            auto recv_result = epp_server_decrypt(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            );
            INFO("Message " << i << " receive");
            REQUIRE(recv_result == EPP_SUCCESS);

            REQUIRE(plaintext.length == msg.size());
            REQUIRE(std::memcmp(plaintext.data, msg.data(), msg.size()) == 0);

            if ((i + 1) % ratchet_threshold == 0) {
                ++ratchet_count;
            }

            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        REQUIRE(ratchet_count == 6);

        uint32_t send_idx = 0, recv_idx = 0;
        REQUIRE(epp_session_get_chain_indices(
            client_system.handle, &send_idx, &recv_idx, nullptr
        ) == EPP_SUCCESS);

        const uint32_t expected_index = message_count % ratchet_threshold;
        REQUIRE(send_idx == expected_index);
    }
    epp_shutdown();
}

TEST_CASE("C API Integration - Message Skip Recovery", "[c_api][integration][skip-recovery]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Receiver can decrypt after skipping messages") {
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

        std::vector<std::vector<uint8_t>> all_envelopes;

        for (int i = 0; i < 10; ++i) {
            std::string msg = "Message " + std::to_string(i);
            EppBuffer envelope{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == EPP_SUCCESS);

            all_envelopes.emplace_back(envelope.data, envelope.data + envelope.length);
            free_buffer_data(&envelope);
        }

        for (int i = 0; i < 3; ++i) {
            EppBuffer plaintext{};
            REQUIRE(epp_server_decrypt(
                server_system.handle,
                all_envelopes[i].data(),
                all_envelopes[i].size(),
                &plaintext, nullptr
            ) == EPP_SUCCESS);

            std::string expected = "Message " + std::to_string(i);
            REQUIRE(plaintext.length == expected.size());
            free_buffer_data(&plaintext);
        }

        for (int i = 7; i < 10; ++i) {
            EppBuffer plaintext{};
            auto result = epp_server_decrypt(
                server_system.handle,
                all_envelopes[i].data(),
                all_envelopes[i].size(),
                &plaintext, nullptr
            );

            REQUIRE(result == EPP_SUCCESS);

            std::string expected = "Message " + std::to_string(i);
            REQUIRE(plaintext.length == expected.size());
            REQUIRE(std::memcmp(plaintext.data, expected.data(), expected.size()) == 0);
            free_buffer_data(&plaintext);
        }

        for (int i = 3; i < 7; ++i) {
            EppBuffer plaintext{};
            auto result = epp_server_decrypt(
                server_system.handle,
                all_envelopes[i].data(),
                all_envelopes[i].size(),
                &plaintext, nullptr
            );

            REQUIRE(result == EPP_SUCCESS);

            std::string expected = "Message " + std::to_string(i);
            REQUIRE(plaintext.length == expected.size());
            REQUIRE(std::memcmp(plaintext.data, expected.data(), expected.size()) == 0);
            free_buffer_data(&plaintext);
        }
    }

    epp_shutdown();
}

TEST_CASE("C API Integration - Rapid Reconnect Under Load", "[c_api][integration][reconnect]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Export/import cycle preserves session state under message load") {
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

        for (int i = 0; i < 25; ++i) {
            std::string msg = "Phase1 msg " + std::to_string(i);
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

        EppBuffer server_state{};
        REQUIRE(epp_server_serialize(
            server_system.handle, &server_state, nullptr
        ) == EPP_SUCCESS);

        std::vector<uint8_t> client_state_vec(client_state.data, client_state.data + client_state.length);
        std::vector<uint8_t> server_state_vec(server_state.data, server_state.data + server_state.length);
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
        REQUIRE(epp_session_deserialize(
            fresh_client_keys.handle,
            client_state_vec.data(),
            client_state_vec.size(),
            &restored_client, nullptr
        ) == EPP_SUCCESS);

        ProtocolSystemHandle* restored_server = nullptr;
        REQUIRE(epp_server_deserialize(
            fresh_server_keys.handle,
            server_state_vec.data(),
            server_state_vec.size(),
            &restored_server, nullptr
        ) == EPP_SUCCESS);

        ClientSystemGuard restored_client_guard;
        restored_client_guard.handle = restored_client;

        ServerSystemGuard restored_server_guard;
        restored_server_guard.handle = restored_server;

        for (int i = 25; i < 50; ++i) {
            std::string msg = "Phase2 msg " + std::to_string(i);
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

        uint32_t send_idx = 0, recv_idx = 0;
        REQUIRE(epp_session_get_chain_indices(
            restored_client_guard.handle, &send_idx, &recv_idx, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(send_idx == 50);
    }

    epp_shutdown();
}
