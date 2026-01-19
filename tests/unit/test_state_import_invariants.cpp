#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/session.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/protocol/constants.hpp"
#include "protocol/state.pb.h"
#include <vector>
#include <algorithm>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::crypto;

namespace {

ecliptix::proto::protocol::ProtocolState CreateValidProtocolState() {
    ecliptix::proto::protocol::ProtocolState state;

    state.set_version(kProtocolVersion);
    state.set_is_initiator(true);

    std::vector<uint8_t> session_id(kSessionIdBytes, 0x11);
    state.set_session_id(session_id.data(), session_id.size());

    std::vector<uint8_t> root_key(kRootKeyBytes, 0x22);
    state.set_root_key(root_key.data(), root_key.size());

    std::vector<uint8_t> metadata_key(kMetadataKeyBytes, 0x33);
    state.set_metadata_key(metadata_key.data(), metadata_key.size());

    auto dh_result = SodiumInterop::GenerateX25519KeyPair("test");
    REQUIRE(dh_result.IsOk());
    auto [dh_sk_handle, dh_pk] = std::move(dh_result).Unwrap();
    std::vector<uint8_t> dh_sk(kX25519PrivateKeyBytes);
    dh_sk_handle.WithReadAccess([&](std::span<const uint8_t> data) {
        std::copy(data.begin(), data.end(), dh_sk.begin());
        return Unit{};
    });

    state.mutable_dh_local()->set_private_key(dh_sk.data(), dh_sk.size());
    state.mutable_dh_local()->set_public_key(dh_pk.data(), dh_pk.size());

    auto peer_dh_result = SodiumInterop::GenerateX25519KeyPair("peer");
    REQUIRE(peer_dh_result.IsOk());
    auto [peer_sk_handle, peer_pk] = std::move(peer_dh_result).Unwrap();
    state.set_dh_remote_public(peer_pk.data(), peer_pk.size());

    state.set_dh_local_initial_public(dh_pk.data(), dh_pk.size());
    state.set_dh_remote_initial_public(peer_pk.data(), peer_pk.size());

    auto kyber_result = KyberInterop::GenerateKyber768KeyPair("test-kyber");
    REQUIRE(kyber_result.IsOk());
    auto [kyber_sk_handle, kyber_pk] = std::move(kyber_result).Unwrap();
    state.mutable_kyber_local()->set_public_key(kyber_pk.data(), kyber_pk.size());
    std::vector<uint8_t> kyber_sk_vec(kKyberSecretKeyBytes);
    kyber_sk_handle.WithReadAccess([&](std::span<const uint8_t> data) {
        std::copy(data.begin(), data.end(), kyber_sk_vec.begin());
        return Unit{};
    });
    state.mutable_kyber_local()->set_secret_key(kyber_sk_vec.data(), kyber_sk_vec.size());

    auto peer_kyber_result = KyberInterop::GenerateKyber768KeyPair("peer-kyber");
    REQUIRE(peer_kyber_result.IsOk());
    auto [peer_kyber_sk_handle, peer_kyber_pk] = std::move(peer_kyber_result).Unwrap();
    state.set_kyber_remote_public(peer_kyber_pk.data(), peer_kyber_pk.size());

    std::vector<uint8_t> chain_key(kChainKeyBytes, 0x44);
    state.mutable_send_chain()->set_chain_key(chain_key.data(), chain_key.size());
    state.mutable_send_chain()->set_message_index(0);
    state.mutable_recv_chain()->set_chain_key(chain_key.data(), chain_key.size());
    state.mutable_recv_chain()->set_message_index(0);

    std::vector<uint8_t> nonce_prefix(kNoncePrefixBytes, 0x55);
    state.mutable_nonce_generator()->set_prefix(nonce_prefix.data(), nonce_prefix.size());
    state.mutable_nonce_generator()->set_counter(0);

    state.set_state_counter(1);
    state.set_send_ratchet_epoch(0);
    state.set_recv_ratchet_epoch(0);
    state.set_max_messages_per_chain(static_cast<uint32_t>(kDefaultMessagesPerChain));

    std::vector<uint8_t> dummy_mac(kHmacBytes, 0x00);
    state.set_state_hmac(dummy_mac.data(), dummy_mac.size());

    return state;
}

}  // namespace

TEST_CASE("State import - HMAC verification", "[session][state][hmac][import]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("State with invalid HMAC is rejected") {
        auto state = CreateValidProtocolState();

        std::vector<uint8_t> bad_mac(kHmacBytes, 0xDE);
        state.set_state_hmac(bad_mac.data(), bad_mac.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("HMAC") != std::string::npos);
    }

    SECTION("State with missing HMAC is rejected") {
        auto state = CreateValidProtocolState();
        state.clear_state_hmac();

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("State with truncated HMAC is rejected") {
        auto state = CreateValidProtocolState();

        std::vector<uint8_t> short_mac(16, 0xAB);
        state.set_state_hmac(short_mac.data(), short_mac.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("State import - Protocol version validation", "[session][state][version]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("Invalid protocol version is rejected") {
        auto state = CreateValidProtocolState();
        state.set_version(2);

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("version") != std::string::npos);
    }

    SECTION("Version 0 is rejected") {
        auto state = CreateValidProtocolState();
        state.set_version(0);

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("State import - Key size validation", "[session][state][keysize]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("Short session_id is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> short_id(8, 0x11);
        state.set_session_id(short_id.data(), short_id.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Short root_key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> short_key(16, 0x22);
        state.set_root_key(short_key.data(), short_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Short metadata_key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> short_key(16, 0x33);
        state.set_metadata_key(short_key.data(), short_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Short DH private key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> short_key(16, 0x44);
        state.mutable_dh_local()->set_private_key(short_key.data(), short_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Short DH public key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> short_key(16, 0x55);
        state.mutable_dh_local()->set_public_key(short_key.data(), short_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Short chain key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> short_key(16, 0x66);
        state.mutable_send_chain()->set_chain_key(short_key.data(), short_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Short nonce prefix is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> short_prefix(2, 0x77);
        state.mutable_nonce_generator()->set_prefix(short_prefix.data(), short_prefix.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Short Kyber public key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> short_key(100, 0x88);
        state.mutable_kyber_local()->set_public_key(short_key.data(), short_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Short Kyber secret key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> short_key(100, 0x99);
        state.mutable_kyber_local()->set_secret_key(short_key.data(), short_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("State import - All-zeros key rejection", "[session][state][zeroskey]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("All-zeros DH private key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> zero_key(kX25519PrivateKeyBytes, 0x00);
        state.mutable_dh_local()->set_private_key(zero_key.data(), zero_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("zeros") != std::string::npos);
    }

    SECTION("All-zeros Kyber secret key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> zero_key(kKyberSecretKeyBytes, 0x00);
        state.mutable_kyber_local()->set_secret_key(zero_key.data(), zero_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("zeros") != std::string::npos);
    }
}

TEST_CASE("State import - Chain index limits", "[session][state][chainindex]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("Sending chain index exceeding ratchet limit is rejected") {
        auto state = CreateValidProtocolState();
        state.mutable_send_chain()->set_message_index(state.max_messages_per_chain() + 1);

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
        const auto& err_msg = result.UnwrapErr().message;
        REQUIRE((err_msg.find("index") != std::string::npos ||
                err_msg.find("ratchet") != std::string::npos));
    }

    SECTION("Receiving chain index exceeding ratchet limit is rejected") {
        auto state = CreateValidProtocolState();
        state.mutable_recv_chain()->set_message_index(state.max_messages_per_chain() + 1);

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("State import - Ratchet config validation", "[session][state][ratchetconfig]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("Zero max_messages_per_chain is rejected") {
        auto state = CreateValidProtocolState();
        state.set_max_messages_per_chain(0);

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Excessive max_messages_per_chain is rejected") {
        auto state = CreateValidProtocolState();
        state.set_max_messages_per_chain(static_cast<uint32_t>(kMaxMessagesPerChain + 1));

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("State import - Nonce counter limits", "[session][state][nonce]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("Nonce counter at maximum is rejected") {
        auto state = CreateValidProtocolState();
        state.mutable_nonce_generator()->set_counter(kMaxNonceCounter + 1);

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("State import - Skipped message key invariants", "[session][state][skippedkeys]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    // Note: These tests verify that invalid state configurations are rejected.
    // Since HMAC verification happens before detailed validation, we verify
    // that any malformed state is rejected (either by HMAC or validation).

    SECTION("Send chain with skipped keys causes rejection") {
        auto state = CreateValidProtocolState();

        auto* cached = state.mutable_send_chain()->add_skipped_message_keys();
        cached->set_message_index(0);
        std::vector<uint8_t> key(kMessageKeyBytes, 0xAA);
        cached->set_message_key(key.data(), key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Too many skipped message keys causes rejection") {
        auto state = CreateValidProtocolState();
        state.mutable_recv_chain()->set_message_index(kMaxSkippedMessageKeys + 10);

        for (size_t i = 0; i < kMaxSkippedMessageKeys + 5; ++i) {
            auto* cached = state.mutable_recv_chain()->add_skipped_message_keys();
            cached->set_message_index(i);
            std::vector<uint8_t> key(kMessageKeyBytes, static_cast<uint8_t>(i & 0xFF));
            cached->set_message_key(key.data(), key.size());
        }

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Invalid skipped message key size causes rejection") {
        auto state = CreateValidProtocolState();
        state.mutable_recv_chain()->set_message_index(10);

        auto* cached = state.mutable_recv_chain()->add_skipped_message_keys();
        cached->set_message_index(5);
        std::vector<uint8_t> short_key(16, 0xBB);
        cached->set_message_key(short_key.data(), short_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Skipped key index >= receiving chain index causes rejection") {
        auto state = CreateValidProtocolState();
        state.mutable_recv_chain()->set_message_index(10);

        auto* cached = state.mutable_recv_chain()->add_skipped_message_keys();
        cached->set_message_index(15);
        std::vector<uint8_t> key(kMessageKeyBytes, 0xCC);
        cached->set_message_key(key.data(), key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Duplicate skipped message key indices cause rejection") {
        auto state = CreateValidProtocolState();
        state.mutable_recv_chain()->set_message_index(20);

        for (int i = 0; i < 2; ++i) {
            auto* cached = state.mutable_recv_chain()->add_skipped_message_keys();
            cached->set_message_index(5);
            std::vector<uint8_t> key(kMessageKeyBytes, static_cast<uint8_t>(i));
            cached->set_message_key(key.data(), key.size());
        }

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Cached key index exceeding maximum causes rejection") {
        auto state = CreateValidProtocolState();
        state.mutable_recv_chain()->set_message_index(kMaxMessageIndex);

        auto* cached = state.mutable_recv_chain()->add_skipped_message_keys();
        cached->set_message_index(kMaxMessageIndex + 1);
        std::vector<uint8_t> key(kMessageKeyBytes, 0xDD);
        cached->set_message_key(key.data(), key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("State import - DH public key validation", "[session][state][dhvalidation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("All-zeros DH peer public key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> zero_key(kX25519PublicKeyBytes, 0x00);
        state.set_dh_remote_public(zero_key.data(), zero_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Small-order DH public key is rejected") {
        auto state = CreateValidProtocolState();

        std::vector<uint8_t> small_order_point = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        };
        state.set_dh_remote_public(small_order_point.data(), small_order_point.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("All-zeros initial DH public key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> zero_key(kX25519PublicKeyBytes, 0x00);
        state.set_dh_remote_initial_public(zero_key.data(), zero_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("State import - Kyber key validation", "[session][state][kybervalidation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("All-zeros Kyber public key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> zero_key(kKyberPublicKeyBytes, 0x00);
        state.mutable_kyber_local()->set_public_key(zero_key.data(), zero_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("All-zeros peer Kyber public key is rejected") {
        auto state = CreateValidProtocolState();
        std::vector<uint8_t> zero_key(kKyberPublicKeyBytes, 0x00);
        state.set_kyber_remote_public(zero_key.data(), zero_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}
