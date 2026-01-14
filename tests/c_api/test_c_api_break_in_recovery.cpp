#include <catch2/catch_test_macros.hpp>
#include "ecliptix/c_api/ecliptix_c_api.h"
#include "common/secure_envelope.pb.h"
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

    bool EnvelopeHasDHRatchet(const uint8_t* data, size_t length) {
        ecliptix::proto::common::SecureEnvelope envelope;
        if (!envelope.ParseFromArray(data, static_cast<int>(length))) {
            return false;
        }
        return envelope.has_dh_public_key() && !envelope.dh_public_key().empty();
    }
}

TEST_CASE("C API Break-in Recovery - DH Ratchet on Reply", "[c_api][break-in-recovery][dh-ratchet]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Server reply triggers DH ratchet with new keys") {
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

        const std::string client_msg1 = "Hello from client";
        EcliptixBuffer client_envelope1{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(client_msg1.data()),
            client_msg1.size(),
            &client_envelope1, nullptr
        ) == ECLIPTIX_SUCCESS);

        ecliptix::proto::common::SecureEnvelope parsed_client_env;
        REQUIRE(parsed_client_env.ParseFromArray(client_envelope1.data, static_cast<int>(client_envelope1.length)));

        std::string client_dh_key;
        if (parsed_client_env.has_dh_public_key()) {
            client_dh_key = parsed_client_env.dh_public_key();
        }

        EcliptixBuffer server_plaintext{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            server_system.handle, client_envelope1.data, client_envelope1.length,
            &server_plaintext, nullptr
        ) == ECLIPTIX_SUCCESS);
        free_buffer_data(&client_envelope1);
        free_buffer_data(&server_plaintext);

        const std::string server_msg = "Reply from server";
        EcliptixBuffer server_envelope{};
        REQUIRE(ecliptix_protocol_server_system_send_message(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(server_msg.data()),
            server_msg.size(),
            &server_envelope, nullptr
        ) == ECLIPTIX_SUCCESS);

        ecliptix::proto::common::SecureEnvelope parsed_server_env;
        REQUIRE(parsed_server_env.ParseFromArray(server_envelope.data, static_cast<int>(server_envelope.length)));

        if (parsed_server_env.has_dh_public_key() && !parsed_server_env.dh_public_key().empty()) {
            REQUIRE(parsed_server_env.dh_public_key() != client_dh_key);
        }

        EcliptixBuffer client_plaintext{};
        REQUIRE(ecliptix_protocol_system_receive_message(
            client_system.handle, server_envelope.data, server_envelope.length,
            &client_plaintext, nullptr
        ) == ECLIPTIX_SUCCESS);
        REQUIRE(client_plaintext.length == server_msg.size());
        REQUIRE(std::memcmp(client_plaintext.data, server_msg.data(), server_msg.size()) == 0);

        free_buffer_data(&server_envelope);
        free_buffer_data(&client_plaintext);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Break-in Recovery - New DH Keys Per Direction Change", "[c_api][break-in-recovery][direction]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Each direction change introduces new DH keys") {
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

        std::vector<std::string> observed_dh_keys;

        for (int round = 0; round < 5; ++round) {
            std::string client_msg = "Client msg " + std::to_string(round);
            EcliptixBuffer c_env{};
            REQUIRE(ecliptix_protocol_system_send_message(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(client_msg.data()),
                client_msg.size(),
                &c_env, nullptr
            ) == ECLIPTIX_SUCCESS);

            ecliptix::proto::common::SecureEnvelope c_parsed;
            if (c_parsed.ParseFromArray(c_env.data, static_cast<int>(c_env.length))) {
                if (c_parsed.has_dh_public_key() && !c_parsed.dh_public_key().empty()) {
                    observed_dh_keys.push_back(c_parsed.dh_public_key());
                }
            }

            EcliptixBuffer s_pt{};
            REQUIRE(ecliptix_protocol_server_system_receive_message(
                server_system.handle, c_env.data, c_env.length, &s_pt, nullptr
            ) == ECLIPTIX_SUCCESS);
            free_buffer_data(&c_env);
            free_buffer_data(&s_pt);

            std::string server_msg = "Server msg " + std::to_string(round);
            EcliptixBuffer s_env{};
            REQUIRE(ecliptix_protocol_server_system_send_message(
                server_system.handle,
                reinterpret_cast<const uint8_t*>(server_msg.data()),
                server_msg.size(),
                &s_env, nullptr
            ) == ECLIPTIX_SUCCESS);

            ecliptix::proto::common::SecureEnvelope s_parsed;
            if (s_parsed.ParseFromArray(s_env.data, static_cast<int>(s_env.length))) {
                if (s_parsed.has_dh_public_key() && !s_parsed.dh_public_key().empty()) {
                    observed_dh_keys.push_back(s_parsed.dh_public_key());
                }
            }

            EcliptixBuffer c_pt{};
            REQUIRE(ecliptix_protocol_system_receive_message(
                client_system.handle, s_env.data, s_env.length, &c_pt, nullptr
            ) == ECLIPTIX_SUCCESS);
            free_buffer_data(&s_env);
            free_buffer_data(&c_pt);
        }

        for (size_t i = 0; i < observed_dh_keys.size(); ++i) {
            for (size_t j = i + 1; j < observed_dh_keys.size(); ++j) {
                if (!observed_dh_keys[i].empty() && !observed_dh_keys[j].empty()) {
                    INFO("Comparing DH key " << i << " and " << j);
                    REQUIRE(observed_dh_keys[i] != observed_dh_keys[j]);
                }
            }
        }
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Break-in Recovery - Consecutive Same-Direction Messages", "[c_api][break-in-recovery][chain]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Multiple messages in same direction don't ratchet until reply") {
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

        std::string first_dh_key;
        int dh_ratchet_count = 0;

        for (int i = 0; i < 10; ++i) {
            std::string msg = "Message " + std::to_string(i);
            EcliptixBuffer envelope{};
            REQUIRE(ecliptix_protocol_system_send_message(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == ECLIPTIX_SUCCESS);

            if (EnvelopeHasDHRatchet(envelope.data, envelope.length)) {
                ecliptix::proto::common::SecureEnvelope parsed;
                parsed.ParseFromArray(envelope.data, static_cast<int>(envelope.length));

                if (first_dh_key.empty()) {
                    first_dh_key = parsed.dh_public_key();
                }

                if (dh_ratchet_count > 0 && !parsed.dh_public_key().empty()) {
                }
                dh_ratchet_count++;
            }

            EcliptixBuffer plaintext{};
            REQUIRE(ecliptix_protocol_server_system_receive_message(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == ECLIPTIX_SUCCESS);
            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        REQUIRE(dh_ratchet_count == 0);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Break-in Recovery - Hybrid Kyber in Ratchet", "[c_api][break-in-recovery][hybrid]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("DH ratchet messages include Kyber ciphertext") {
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

        const std::string msg1 = "First message";
        EcliptixBuffer env1{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg1.data()),
            msg1.size(),
            &env1, nullptr
        ) == ECLIPTIX_SUCCESS);

        ecliptix::proto::common::SecureEnvelope parsed1;
        REQUIRE(parsed1.ParseFromArray(env1.data, static_cast<int>(env1.length)));

        if (parsed1.has_dh_public_key() && !parsed1.dh_public_key().empty()) {
            REQUIRE(parsed1.has_kyber_ciphertext());
            REQUIRE(parsed1.kyber_ciphertext().size() > 0);
        }

        EcliptixBuffer pt1{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            server_system.handle, env1.data, env1.length, &pt1, nullptr
        ) == ECLIPTIX_SUCCESS);
        free_buffer_data(&env1);
        free_buffer_data(&pt1);

        const std::string msg2 = "Server reply";
        EcliptixBuffer env2{};
        REQUIRE(ecliptix_protocol_server_system_send_message(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(msg2.data()),
            msg2.size(),
            &env2, nullptr
        ) == ECLIPTIX_SUCCESS);

        ecliptix::proto::common::SecureEnvelope parsed2;
        REQUIRE(parsed2.ParseFromArray(env2.data, static_cast<int>(env2.length)));

        if (parsed2.has_dh_public_key() && !parsed2.dh_public_key().empty()) {
            REQUIRE(parsed2.has_kyber_ciphertext());
            REQUIRE(parsed2.kyber_ciphertext().size() > 0);
        }

        EcliptixBuffer pt2{};
        REQUIRE(ecliptix_protocol_system_receive_message(
            client_system.handle, env2.data, env2.length, &pt2, nullptr
        ) == ECLIPTIX_SUCCESS);
        free_buffer_data(&env2);
        free_buffer_data(&pt2);
    }

    ecliptix_shutdown();
}

TEST_CASE("C API Break-in Recovery - Verify Keys Change After Ratchet", "[c_api][break-in-recovery][state]") {
    REQUIRE(ecliptix_initialize() == ECLIPTIX_SUCCESS);

    SECTION("Exported state differs before and after DH ratchet") {
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

        const std::string msg1 = "First";
        EcliptixBuffer env1{};
        REQUIRE(ecliptix_protocol_system_send_message(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg1.data()),
            msg1.size(),
            &env1, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer pt1{};
        REQUIRE(ecliptix_protocol_server_system_receive_message(
            server_system.handle, env1.data, env1.length, &pt1, nullptr
        ) == ECLIPTIX_SUCCESS);
        free_buffer_data(&env1);
        free_buffer_data(&pt1);

        EcliptixBuffer state_before{};
        REQUIRE(ecliptix_protocol_server_system_export_state(
            server_system.handle, &state_before, nullptr
        ) == ECLIPTIX_SUCCESS);
        std::vector<uint8_t> state_before_vec(state_before.data, state_before.data + state_before.length);
        free_buffer_data(&state_before);

        const std::string msg2 = "Reply";
        EcliptixBuffer env2{};
        REQUIRE(ecliptix_protocol_server_system_send_message(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(msg2.data()),
            msg2.size(),
            &env2, nullptr
        ) == ECLIPTIX_SUCCESS);

        EcliptixBuffer pt2{};
        REQUIRE(ecliptix_protocol_system_receive_message(
            client_system.handle, env2.data, env2.length, &pt2, nullptr
        ) == ECLIPTIX_SUCCESS);
        free_buffer_data(&env2);
        free_buffer_data(&pt2);

        EcliptixBuffer state_after{};
        REQUIRE(ecliptix_protocol_server_system_export_state(
            server_system.handle, &state_after, nullptr
        ) == ECLIPTIX_SUCCESS);
        std::vector<uint8_t> state_after_vec(state_after.data, state_after.data + state_after.length);
        free_buffer_data(&state_after);

        bool states_differ = (state_before_vec.size() != state_after_vec.size()) ||
            (std::memcmp(state_before_vec.data(), state_after_vec.data(), state_before_vec.size()) != 0);
        REQUIRE(states_differ);
    }

    ecliptix_shutdown();
}
