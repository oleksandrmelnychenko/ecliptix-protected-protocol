#pragma once

#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/protocol_connection.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/configuration/ratchet_config.hpp"
#include <optional>
#include <utility>

namespace ecliptix::protocol::test_helpers {
    inline void PrepareHybridHandshake(
        std::unique_ptr<protocol::connection::ProtocolConnection>& initiator,
        std::unique_ptr<protocol::connection::ProtocolConnection>& responder) {
        using protocol::crypto::KyberInterop;
        auto encap = KyberInterop::Encapsulate(responder->GetKyberPublicKeyCopy());
        REQUIRE(encap.IsOk());
        auto [ct, ss_handle] = std::move(encap).Unwrap();
        auto ss_bytes = ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
        REQUIRE(ss_bytes.IsOk());
        REQUIRE(initiator->SetHybridHandshakeSecrets(ct, ss_bytes.Unwrap()).IsOk());
        REQUIRE(responder->DeriveKyberSharedSecretFromCiphertext(ct).IsOk());
        REQUIRE(initiator->DebugSetPeerKyberPublicKey(responder->GetKyberPublicKeyCopy()).IsOk());
        REQUIRE(responder->DebugSetPeerKyberPublicKey(initiator->GetKyberPublicKeyCopy()).IsOk());
    }

    inline void PrepareStandaloneHybridHandshake(
        std::unique_ptr<protocol::connection::ProtocolConnection>& conn) {
        using protocol::crypto::KyberInterop;
        auto peer_pair = KyberInterop::GenerateKyber768KeyPair("test-peer-kyber");
        REQUIRE(peer_pair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_pair).Unwrap();
        auto encap = KyberInterop::Encapsulate(peer_pk);
        REQUIRE(encap.IsOk());
        auto [ct, ss_handle] = std::move(encap).Unwrap();
        auto ss_bytes = ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
        REQUIRE(ss_bytes.IsOk());
        REQUIRE(conn->SetHybridHandshakeSecrets(ct, ss_bytes.Unwrap()).IsOk());
        REQUIRE(conn->DebugSetPeerKyberPublicKey(peer_pk).IsOk());
    }

    inline std::unique_ptr<protocol::connection::ProtocolConnection> CreatePreparedConnection(
        uint32_t id,
        bool is_initiator,
        std::optional<protocol::configuration::RatchetConfig> config = std::nullopt) {
        using protocol::connection::ProtocolConnection;
        auto result = config.has_value()
                          ? ProtocolConnection::Create(id, is_initiator, *config)
                          : ProtocolConnection::Create(id, is_initiator);
        REQUIRE(result.IsOk());
        auto conn = std::move(result).Unwrap();
        PrepareStandaloneHybridHandshake(conn);
        return conn;
    }

    inline std::pair<std::unique_ptr<protocol::connection::ProtocolConnection>,
                     std::unique_ptr<protocol::connection::ProtocolConnection>>
    CreatePreparedPair(uint32_t initiator_id, uint32_t responder_id) {
        auto initiator = CreatePreparedConnection(initiator_id, true);
        auto responder = CreatePreparedConnection(responder_id, false);
        PrepareHybridHandshake(initiator, responder);
        return {std::move(initiator), std::move(responder)};
    }

    inline std::vector<uint8_t> GetKyberCiphertextForSender(
        const std::unique_ptr<protocol::connection::ProtocolConnection>& sender) {
        auto ct_result = sender->GetCurrentKyberCiphertext();
        REQUIRE(ct_result.IsOk());
        auto ct_opt = std::move(ct_result).Unwrap();
        REQUIRE(ct_opt.has_value());
        return std::move(ct_opt).value();
    }

    inline std::vector<uint8_t> EncapsulateTo(
        const std::vector<uint8_t>& recipient_kyber_pk) {
        using protocol::crypto::KyberInterop;
        auto encap = KyberInterop::Encapsulate(recipient_kyber_pk);
        REQUIRE(encap.IsOk());
        auto [ct, _ss] = std::move(encap).Unwrap();
        return ct;
    }
}
