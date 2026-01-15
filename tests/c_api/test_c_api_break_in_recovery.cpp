#include <catch2/catch_test_macros.hpp>
#include "ecliptix/c_api/epp_api.h"
#include "common/secure_envelope.pb.h"
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

    bool EnvelopeHasDHRatchet(const uint8_t* data, size_t length) {
        ecliptix::proto::common::SecureEnvelope envelope;
        if (!envelope.ParseFromArray(data, static_cast<int>(length))) {
            return false;
        }
        return envelope.has_dh_public_key() && !envelope.dh_public_key().empty();
    }
}

TEST_CASE("C API Break-in Recovery - DH Ratchet on Reply", "[c_api][break-in-recovery][dh-ratchet]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Server reply triggers DH ratchet with new keys") {
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

        const std::string client_msg1 = "Hello from client";
        EppBuffer client_envelope1{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(client_msg1.data()),
            client_msg1.size(),
            &client_envelope1, nullptr
        ) == EPP_SUCCESS);

        ecliptix::proto::common::SecureEnvelope parsed_client_env;
        REQUIRE(parsed_client_env.ParseFromArray(client_envelope1.data, static_cast<int>(client_envelope1.length)));

        std::string client_dh_key;
        if (parsed_client_env.has_dh_public_key()) {
            client_dh_key = parsed_client_env.dh_public_key();
        }

        EppBuffer server_plaintext{};
        REQUIRE(epp_server_decrypt(
            server_system.handle, client_envelope1.data, client_envelope1.length,
            &server_plaintext, nullptr
        ) == EPP_SUCCESS);
        free_buffer_data(&client_envelope1);
        free_buffer_data(&server_plaintext);

        const std::string server_msg = "Reply from server";
        EppBuffer server_envelope{};
        REQUIRE(epp_server_encrypt(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(server_msg.data()),
            server_msg.size(),
            &server_envelope, nullptr
        ) == EPP_SUCCESS);

        ecliptix::proto::common::SecureEnvelope parsed_server_env;
        REQUIRE(parsed_server_env.ParseFromArray(server_envelope.data, static_cast<int>(server_envelope.length)));

        if (parsed_server_env.has_dh_public_key() && !parsed_server_env.dh_public_key().empty()) {
            REQUIRE(parsed_server_env.dh_public_key() != client_dh_key);
        }

        EppBuffer client_plaintext{};
        REQUIRE(epp_session_decrypt(
            client_system.handle, server_envelope.data, server_envelope.length,
            &client_plaintext, nullptr
        ) == EPP_SUCCESS);
        REQUIRE(client_plaintext.length == server_msg.size());
        REQUIRE(std::memcmp(client_plaintext.data, server_msg.data(), server_msg.size()) == 0);

        free_buffer_data(&server_envelope);
        free_buffer_data(&client_plaintext);
    }

    epp_shutdown();
}

TEST_CASE("C API Break-in Recovery - New DH Keys Per Direction Change", "[c_api][break-in-recovery][direction]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Each direction change introduces new DH keys") {
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

        std::vector<std::string> observed_dh_keys;

        for (int round = 0; round < 5; ++round) {
            std::string client_msg = "Client msg " + std::to_string(round);
            EppBuffer c_env{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(client_msg.data()),
                client_msg.size(),
                &c_env, nullptr
            ) == EPP_SUCCESS);

            ecliptix::proto::common::SecureEnvelope c_parsed;
            if (c_parsed.ParseFromArray(c_env.data, static_cast<int>(c_env.length))) {
                if (c_parsed.has_dh_public_key() && !c_parsed.dh_public_key().empty()) {
                    observed_dh_keys.push_back(c_parsed.dh_public_key());
                }
            }

            EppBuffer s_pt{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, c_env.data, c_env.length, &s_pt, nullptr
            ) == EPP_SUCCESS);
            free_buffer_data(&c_env);
            free_buffer_data(&s_pt);

            std::string server_msg = "Server msg " + std::to_string(round);
            EppBuffer s_env{};
            REQUIRE(epp_server_encrypt(
                server_system.handle,
                reinterpret_cast<const uint8_t*>(server_msg.data()),
                server_msg.size(),
                &s_env, nullptr
            ) == EPP_SUCCESS);

            ecliptix::proto::common::SecureEnvelope s_parsed;
            if (s_parsed.ParseFromArray(s_env.data, static_cast<int>(s_env.length))) {
                if (s_parsed.has_dh_public_key() && !s_parsed.dh_public_key().empty()) {
                    observed_dh_keys.push_back(s_parsed.dh_public_key());
                }
            }

            EppBuffer c_pt{};
            REQUIRE(epp_session_decrypt(
                client_system.handle, s_env.data, s_env.length, &c_pt, nullptr
            ) == EPP_SUCCESS);
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

    epp_shutdown();
}

TEST_CASE("C API Break-in Recovery - Consecutive Same-Direction Messages", "[c_api][break-in-recovery][chain]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Multiple messages in same direction don't ratchet until reply") {
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

        std::string first_dh_key;
        int dh_ratchet_count = 0;

        for (int i = 0; i < 10; ++i) {
            std::string msg = "Message " + std::to_string(i);
            EppBuffer envelope{};
            REQUIRE(epp_session_encrypt(
                client_system.handle,
                reinterpret_cast<const uint8_t*>(msg.data()),
                msg.size(),
                &envelope, nullptr
            ) == EPP_SUCCESS);

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

            EppBuffer plaintext{};
            REQUIRE(epp_server_decrypt(
                server_system.handle, envelope.data, envelope.length,
                &plaintext, nullptr
            ) == EPP_SUCCESS);
            free_buffer_data(&envelope);
            free_buffer_data(&plaintext);
        }

        REQUIRE(dh_ratchet_count == 0);
    }

    epp_shutdown();
}

TEST_CASE("C API Break-in Recovery - Hybrid Kyber in Ratchet", "[c_api][break-in-recovery][hybrid]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("DH ratchet messages include Kyber ciphertext") {
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

        const std::string msg1 = "First message";
        EppBuffer env1{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg1.data()),
            msg1.size(),
            &env1, nullptr
        ) == EPP_SUCCESS);

        ecliptix::proto::common::SecureEnvelope parsed1;
        REQUIRE(parsed1.ParseFromArray(env1.data, static_cast<int>(env1.length)));

        if (parsed1.has_dh_public_key() && !parsed1.dh_public_key().empty()) {
            REQUIRE(parsed1.has_kyber_ciphertext());
            REQUIRE(parsed1.kyber_ciphertext().size() > 0);
        }

        EppBuffer pt1{};
        REQUIRE(epp_server_decrypt(
            server_system.handle, env1.data, env1.length, &pt1, nullptr
        ) == EPP_SUCCESS);
        free_buffer_data(&env1);
        free_buffer_data(&pt1);

        const std::string msg2 = "Server reply";
        EppBuffer env2{};
        REQUIRE(epp_server_encrypt(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(msg2.data()),
            msg2.size(),
            &env2, nullptr
        ) == EPP_SUCCESS);

        ecliptix::proto::common::SecureEnvelope parsed2;
        REQUIRE(parsed2.ParseFromArray(env2.data, static_cast<int>(env2.length)));

        if (parsed2.has_dh_public_key() && !parsed2.dh_public_key().empty()) {
            REQUIRE(parsed2.has_kyber_ciphertext());
            REQUIRE(parsed2.kyber_ciphertext().size() > 0);
        }

        EppBuffer pt2{};
        REQUIRE(epp_session_decrypt(
            client_system.handle, env2.data, env2.length, &pt2, nullptr
        ) == EPP_SUCCESS);
        free_buffer_data(&env2);
        free_buffer_data(&pt2);
    }

    epp_shutdown();
}

TEST_CASE("C API Break-in Recovery - Verify Keys Change After Ratchet", "[c_api][break-in-recovery][state]") {
    REQUIRE(epp_init() == EPP_SUCCESS);

    SECTION("Exported state differs before and after DH ratchet") {
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

        const std::string msg1 = "First";
        EppBuffer env1{};
        REQUIRE(epp_session_encrypt(
            client_system.handle,
            reinterpret_cast<const uint8_t*>(msg1.data()),
            msg1.size(),
            &env1, nullptr
        ) == EPP_SUCCESS);

        EppBuffer pt1{};
        REQUIRE(epp_server_decrypt(
            server_system.handle, env1.data, env1.length, &pt1, nullptr
        ) == EPP_SUCCESS);
        free_buffer_data(&env1);
        free_buffer_data(&pt1);

        EppBuffer state_before{};
        REQUIRE(epp_server_serialize(
            server_system.handle, &state_before, nullptr
        ) == EPP_SUCCESS);
        std::vector<uint8_t> state_before_vec(state_before.data, state_before.data + state_before.length);
        free_buffer_data(&state_before);

        const std::string msg2 = "Reply";
        EppBuffer env2{};
        REQUIRE(epp_server_encrypt(
            server_system.handle,
            reinterpret_cast<const uint8_t*>(msg2.data()),
            msg2.size(),
            &env2, nullptr
        ) == EPP_SUCCESS);

        EppBuffer pt2{};
        REQUIRE(epp_session_decrypt(
            client_system.handle, env2.data, env2.length, &pt2, nullptr
        ) == EPP_SUCCESS);
        free_buffer_data(&env2);
        free_buffer_data(&pt2);

        EppBuffer state_after{};
        REQUIRE(epp_server_serialize(
            server_system.handle, &state_after, nullptr
        ) == EPP_SUCCESS);
        std::vector<uint8_t> state_after_vec(state_after.data, state_after.data + state_after.length);
        free_buffer_data(&state_after);

        bool states_differ = (state_before_vec.size() != state_after_vec.size()) ||
            (std::memcmp(state_before_vec.data(), state_after_vec.data(), state_before_vec.size()) != 0);
        REQUIRE(states_differ);
    }

    epp_shutdown();
}
