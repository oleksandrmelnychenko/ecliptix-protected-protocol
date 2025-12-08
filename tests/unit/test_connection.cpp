#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/models/bundles/local_public_key_bundle.hpp"
#include "ecliptix/interfaces/i_protocol_event_handler.hpp"
using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::models;
using namespace ecliptix::protocol::enums;
class MockEventHandler : public IProtocolEventHandler {
public:
    void OnProtocolStateChanged(uint32_t connect_id) override {
        call_count++;
        last_connect_id = connect_id;
    }
    int call_count = 0;
    uint32_t last_connect_id = 0;
};
TEST_CASE("EcliptixProtocolConnection - Creation and initialization", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Create initiator connection") {
        auto result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(result.IsOk());
        auto conn = std::move(result).Unwrap();
        REQUIRE(conn->IsInitiator());
        REQUIRE(conn->ExchangeType() == PubKeyExchangeType::X3DH);
    }
    SECTION("Create responder connection") {
        auto result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(result.IsOk());
        auto conn = std::move(result).Unwrap();
        REQUIRE_FALSE(conn->IsInitiator());
        REQUIRE(conn->ExchangeType() == PubKeyExchangeType::X3DH);
    }
    SECTION("Connection IDs are unique") {
        auto conn1_result = EcliptixProtocolConnection::Create(1, true);
        auto conn2_result = EcliptixProtocolConnection::Create(2, true);
        REQUIRE(conn1_result.IsOk());
        REQUIRE(conn2_result.IsOk());
    }
}
TEST_CASE("EcliptixProtocolConnection - SetPeerBundle", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Set peer bundle before finalization succeeds") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> ed25519_pub(Constants::ED_25519_PUBLIC_KEY_SIZE, 0x01);
        std::vector<uint8_t> x25519_pub(Constants::X_25519_PUBLIC_KEY_SIZE, 0x02);
        std::vector<uint8_t> spk_pub(Constants::X_25519_PUBLIC_KEY_SIZE, 0x03);
        std::vector<uint8_t> spk_sig(Constants::ED_25519_SIGNATURE_SIZE, 0x04);
        LocalPublicKeyBundle bundle(
            ed25519_pub,
            x25519_pub,
            1,
            spk_pub,
            spk_sig,
            {},
            std::nullopt
        );
        auto set_result = conn->SetPeerBundle(bundle);
        REQUIRE(set_result.IsOk());
        auto get_result = conn->GetPeerBundle();
        REQUIRE(get_result.IsOk());
        auto retrieved = get_result.Unwrap();
        REQUIRE(retrieved.GetEd25519Public() == ed25519_pub);
    }
    SECTION("Cannot set peer bundle after finalization") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        std::vector<uint8_t> peer_dh_pub(Constants::X_25519_PUBLIC_KEY_SIZE, 0xBB);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer-dh");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        std::vector<uint8_t> ed25519_pub(Constants::ED_25519_PUBLIC_KEY_SIZE, 0x01);
        std::vector<uint8_t> x25519_pub(Constants::X_25519_PUBLIC_KEY_SIZE, 0x02);
        std::vector<uint8_t> spk_pub(Constants::X_25519_PUBLIC_KEY_SIZE, 0x03);
        std::vector<uint8_t> spk_sig(Constants::ED_25519_SIGNATURE_SIZE, 0x04);
        LocalPublicKeyBundle bundle(
            ed25519_pub,
            x25519_pub,
            1,
            spk_pub,
            spk_sig,
            {},
            std::nullopt
        );
        auto set_result = conn->SetPeerBundle(bundle);
        REQUIRE(set_result.IsErr());
    }
}
TEST_CASE("EcliptixProtocolConnection - Finalization", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Successful finalization") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer-dh");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
    }
    SECTION("Cannot finalize twice") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize1 = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize1.IsOk());
        auto finalize2 = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize2.IsErr());
    }
    SECTION("Reject invalid root key size") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> bad_root_key(16, 0xAA);  
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(bad_root_key, peer_pk);
        REQUIRE(finalize_result.IsErr());
    }
    SECTION("Reject invalid peer DH public key size") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        std::vector<uint8_t> bad_peer_pk(16, 0xBB);  
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, bad_peer_pk);
        REQUIRE(finalize_result.IsErr());
    }
}
TEST_CASE("EcliptixProtocolConnection - Nonce generation", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Generate valid nonce") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        auto nonce_result = conn->GenerateNextNonce();
        REQUIRE(nonce_result.IsOk());
        auto nonce = nonce_result.Unwrap();
        REQUIRE(nonce.size() == 12);  
    }
    SECTION("Nonces are unique") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        auto nonce1_result = conn->GenerateNextNonce();
        auto nonce2_result = conn->GenerateNextNonce();
        auto nonce3_result = conn->GenerateNextNonce();
        REQUIRE(nonce1_result.IsOk());
        REQUIRE(nonce2_result.IsOk());
        REQUIRE(nonce3_result.IsOk());
        auto nonce1 = nonce1_result.Unwrap();
        auto nonce2 = nonce2_result.Unwrap();
        auto nonce3 = nonce3_result.Unwrap();
        REQUIRE((nonce1 != nonce2 || nonce2 != nonce3));
    }
    SECTION("Counter increments") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<std::vector<uint8_t>> nonces;
        for (int i = 0; i < 10; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            nonces.push_back(nonce_result.Unwrap());
        }
        for (size_t i = 0; i < nonces.size(); ++i) {
            for (size_t j = i + 1; j < nonces.size(); ++j) {
                REQUIRE(nonces[i] != nonces[j]);
            }
        }
    }
}
TEST_CASE("EcliptixProtocolConnection - Replay protection", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Valid nonce size passes") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> valid_nonce(12, 0x42);
        auto check_result = conn->CheckReplayProtection(valid_nonce, 1);
        REQUIRE(check_result.IsOk());
    }
    SECTION("Invalid nonce size fails") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> bad_nonce(8, 0x42);  
        auto check_result = conn->CheckReplayProtection(bad_nonce, 1);
        REQUIRE(check_result.IsErr());
    }
}
TEST_CASE("EcliptixProtocolConnection - Message preparation", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Cannot prepare message before finalization") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        auto prepare_result = conn->PrepareNextSendMessage();
        REQUIRE(prepare_result.IsErr());
    }
    SECTION("Prepare message after finalization succeeds") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto prepare_result = conn->PrepareNextSendMessage();
        REQUIRE(prepare_result.IsOk());
        auto [ratchet_key, include_dh] = prepare_result.Unwrap();
        REQUIRE(ratchet_key.Index() == 1);  
    }
    SECTION("Multiple message preparation increments index") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto msg1 = conn->PrepareNextSendMessage();
        auto msg2 = conn->PrepareNextSendMessage();
        auto msg3 = conn->PrepareNextSendMessage();
        REQUIRE(msg1.IsOk());
        REQUIRE(msg2.IsOk());
        REQUIRE(msg3.IsOk());
        REQUIRE(msg1.Unwrap().first.Index() == 1);
        REQUIRE(msg2.Unwrap().first.Index() == 2);
        REQUIRE(msg3.Unwrap().first.Index() == 3);
    }
}
TEST_CASE("EcliptixProtocolConnection - Message processing", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Cannot process message before finalization") {
        auto conn_result = EcliptixProtocolConnection::Create(1, false);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        auto process_result = conn->ProcessReceivedMessage(1);
        REQUIRE(process_result.IsErr());
    }
    SECTION("Process message after finalization succeeds") {
        auto conn_result = EcliptixProtocolConnection::Create(1, false);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto process_result = conn->ProcessReceivedMessage(0);
        REQUIRE(process_result.IsOk());
        auto ratchet_key = process_result.Unwrap();
        REQUIRE(ratchet_key.Index() == 0);
    }
}
TEST_CASE("EcliptixProtocolConnection - DH ratchet operations", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Perform receiving ratchet with valid key") {
        auto conn_result = EcliptixProtocolConnection::Create(1, false);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto new_keypair = SodiumInterop::GenerateX25519KeyPair("test-new-ephemeral");
        REQUIRE(new_keypair.IsOk());
        auto [new_sk, new_pk] = std::move(new_keypair).Unwrap();
        auto ratchet_result = conn->PerformReceivingRatchet(new_pk);
        REQUIRE(ratchet_result.IsOk());
    }
    SECTION("Reject invalid DH key size") {
        auto conn_result = EcliptixProtocolConnection::Create(1, false);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        std::vector<uint8_t> bad_dh_key(16, 0xBB);  
        auto ratchet_result = conn->PerformReceivingRatchet(bad_dh_key);
        REQUIRE(ratchet_result.IsErr());
    }
    SECTION("NotifyRatchetRotation sets flag") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        conn->NotifyRatchetRotation();
    }
}
TEST_CASE("EcliptixProtocolConnection - State queries", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Get current sender DH public key") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        auto key_result = conn->GetCurrentSenderDhPublicKey();
        REQUIRE(key_result.IsOk());
        auto key_opt = key_result.Unwrap();
        REQUIRE(key_opt.has_value());
        REQUIRE(key_opt->size() == Constants::X_25519_PUBLIC_KEY_SIZE);
    }
    SECTION("Get metadata encryption key before finalization fails") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        auto key_result = conn->GetMetadataEncryptionKey();
        REQUIRE(key_result.IsErr());
    }
    SECTION("Get metadata encryption key after finalization succeeds") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto key_result = conn->GetMetadataEncryptionKey();
        REQUIRE(key_result.IsOk());
        auto key = key_result.Unwrap();
        REQUIRE(key.size() == Constants::AES_KEY_SIZE);
    }
}
TEST_CASE("EcliptixProtocolConnection - SyncWithRemoteState", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Cannot sync before finalization") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        auto sync_result = conn->SyncWithRemoteState(10, 10);
        REQUIRE(sync_result.IsErr());
    }
    SECTION("Successful sync with remote state") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto sync_result = conn->SyncWithRemoteState(5, 3);
        REQUIRE(sync_result.IsOk());
    }
    SECTION("Sync advances receiving chain") {
        auto conn_result = EcliptixProtocolConnection::Create(1, false);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto msg0 = conn->ProcessReceivedMessage(0);
        REQUIRE(msg0.IsOk());
        auto sync_result = conn->SyncWithRemoteState(10, 0);
        REQUIRE(sync_result.IsOk());
        auto msg10 = conn->ProcessReceivedMessage(10);
        REQUIRE(msg10.IsOk());
    }
    SECTION("Sync advances sending chain") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto msg1 = conn->PrepareNextSendMessage();
        REQUIRE(msg1.IsOk());
        REQUIRE(msg1.Unwrap().first.Index() == 1);
        auto sync_result = conn->SyncWithRemoteState(0, 6);
        REQUIRE(sync_result.IsOk());
        auto msg_next = conn->PrepareNextSendMessage();
        REQUIRE(msg_next.IsOk());
        REQUIRE(msg_next.Unwrap().first.Index() == 7);
    }
    SECTION("Reject sync with gap too large") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto sync_result = conn->SyncWithRemoteState(2000, 0);
        REQUIRE(sync_result.IsErr());
    }
}
TEST_CASE("EcliptixProtocolConnection - Event Handler", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Event handler is called on finalization") {
        auto handler = std::make_shared<MockEventHandler>();
        auto conn_result = EcliptixProtocolConnection::Create(42, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        conn->SetEventHandler(handler);
        REQUIRE(handler->call_count == 0);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x11);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        REQUIRE(handler->call_count == 1);
        REQUIRE(handler->last_connect_id == 42);
    }
    SECTION("Event handler is called on message preparation") {
        auto handler = std::make_shared<MockEventHandler>();
        auto conn_result = EcliptixProtocolConnection::Create(99, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        conn->SetEventHandler(handler);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x22);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        REQUIRE(handler->call_count == 1);
        auto msg_result = conn->PrepareNextSendMessage();
        REQUIRE(msg_result.IsOk());
        REQUIRE(handler->call_count == 2);
        REQUIRE(handler->last_connect_id == 99);
    }
    SECTION("Event handler can be set to nullptr") {
        auto handler = std::make_shared<MockEventHandler>();
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();
        conn->SetEventHandler(handler);
        conn->SetEventHandler(nullptr);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x33);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        REQUIRE(handler->call_count == 0);
    }
    SECTION("Event handler is called on receiving ratchet") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(alice_result.IsOk());
        REQUIRE(bob_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();
        auto bob = std::move(bob_result).Unwrap();
        auto handler = std::make_shared<MockEventHandler>();
        alice->SetEventHandler(handler);
        auto alice_dh_result = alice->GetCurrentSenderDhPublicKey();
        REQUIRE(alice_dh_result.IsOk());
        auto alice_dh_opt = alice_dh_result.Unwrap();
        REQUIRE(alice_dh_opt.has_value());
        auto alice_dh = alice_dh_opt.value();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x44);
        auto bob_keypair = SodiumInterop::GenerateX25519KeyPair("bob");
        REQUIRE(bob_keypair.IsOk());
        auto [bob_sk, bob_pk] = std::move(bob_keypair).Unwrap();
        auto alice_finalize = alice->FinalizeChainAndDhKeys(root_key, bob_pk);
        REQUIRE(alice_finalize.IsOk());
        int calls_after_finalize = handler->call_count;
        auto new_bob_keypair = SodiumInterop::GenerateX25519KeyPair("bob-new");
        REQUIRE(new_bob_keypair.IsOk());
        auto [new_bob_sk, new_bob_pk] = std::move(new_bob_keypair).Unwrap();
        auto ratchet_result = alice->PerformReceivingRatchet(new_bob_pk);
        REQUIRE(ratchet_result.IsOk());
        REQUIRE(handler->call_count > calls_after_finalize);
        REQUIRE(handler->last_connect_id == 1);
    }
}
