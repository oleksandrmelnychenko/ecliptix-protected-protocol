#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/protocol_connection.hpp"
#include "protocol/protocol_state.pb.h"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/configuration/ratchet_config.hpp"
#include "ecliptix/enums/key_exchange_type.hpp"
#include "helpers/hybrid_handshake.hpp"

using ecliptix::protocol::connection::ProtocolConnection;
using ecliptix::protocol::configuration::RatchetConfig;
using ecliptix::protocol::crypto::SodiumInterop;
using ecliptix::protocol::enums::KeyExchangeType;
using ecliptix::protocol::Constants;
using namespace ecliptix::protocol::test_helpers;

TEST_CASE("Persisted state rejects tampered Kyber artifacts", "[persistence][pq][state]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    auto conn = CreatePreparedConnection(1001, true);
    auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("persistence-peer");
    REQUIRE(peer_keypair.IsOk());
    auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
    std::vector<uint8_t> root_key(kRootKeyBytes, 0x24);
    REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

    auto state_result = conn->ToProtoState();
    REQUIRE(state_result.IsOk());
    auto state = state_result.Unwrap();
    auto ratchet_config = RatchetConfig::Default();

    SECTION("tampered Kyber ciphertext is rejected on restore") {
        auto tampered = state;
        auto ct = tampered.kyber_ciphertext();
        ct[0] ^= 0x01;
        tampered.set_kyber_ciphertext(ct);
        auto restore = ProtocolConnection::FromProtoState(
            1001,
            tampered,
            ratchet_config,
            KeyExchangeType::X3DH);
        REQUIRE(restore.IsErr());
    }

    SECTION("truncated peer Kyber public key is rejected on restore") {
        auto tampered = state;
        auto peer_pk_str = tampered.peer_kyber_public_key();
        peer_pk_str.resize(peer_pk_str.size() - 1);
        tampered.set_peer_kyber_public_key(peer_pk_str);
        auto restore = ProtocolConnection::FromProtoState(
            1001,
            tampered,
            ratchet_config,
            KeyExchangeType::X3DH);
        REQUIRE(restore.IsErr());
    }

    SECTION("tampered Kyber secret key nonce fails MAC/invariant checks") {
        auto tampered = state;
        tampered.set_kyber_secret_key_nonce("short");
        auto restore = ProtocolConnection::FromProtoState(
            1001,
            tampered,
            ratchet_config,
            KeyExchangeType::X3DH);
        REQUIRE(restore.IsErr());
    }

    SECTION("tampered sealed Kyber secret key is rejected on restore") {
        auto tampered = state;
        auto sealed = tampered.kyber_secret_key();
        sealed[0] ^= 0x42;
        tampered.set_kyber_secret_key(sealed);
        auto restore = ProtocolConnection::FromProtoState(
            1001,
            tampered,
            ratchet_config,
            KeyExchangeType::X3DH);
        REQUIRE(restore.IsErr());
    }

    SECTION("tampered but length-valid wrap nonce is rejected on restore") {
        auto tampered = state;
        auto nonce = tampered.kyber_secret_key_nonce();
        nonce[0] ^= 0x7E;
        tampered.set_kyber_secret_key_nonce(nonce);
        auto restore = ProtocolConnection::FromProtoState(
            1001,
            tampered,
            ratchet_config,
            KeyExchangeType::X3DH);
        REQUIRE(restore.IsErr());
    }
}
