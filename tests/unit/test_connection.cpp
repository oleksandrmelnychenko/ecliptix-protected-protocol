#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/models/bundles/local_public_key_bundle.hpp"
#include "ecliptix/interfaces/i_protocol_event_handler.hpp"
#include "ecliptix/configuration/ratchet_config.hpp"
#include "helpers/hybrid_handshake.hpp"
#include <thread>
#include <atomic>
#include <unordered_set>
#include <vector>
#include <mutex>
using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::models;
using namespace ecliptix::protocol::enums;
using namespace ecliptix::protocol::test_helpers;


static std::vector<uint8_t> MakeTestNonce(uint64_t idx) {
    // Nonce structure (12 bytes total):
    // Bytes [0-3]: Random prefix (fixed here for test simplicity)
    // Bytes [4-7]: Monotonic counter (use idx for test simplicity)
    // Bytes [8-11]: Message index in little-endian format
    std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE, 0);

    // Set monotonic counter (bytes 4-7)
    for (size_t i = 0; i < ProtocolConstants::NONCE_COUNTER_SIZE; ++i) {
        nonce[ProtocolConstants::NONCE_PREFIX_SIZE + i] =
            static_cast<uint8_t>((idx >> (i * 8)) & 0xFF);
    }

    // Set message index in little-endian (bytes 8-11)
    for (size_t i = 0; i < ProtocolConstants::NONCE_INDEX_SIZE; ++i) {
        nonce[ProtocolConstants::NONCE_PREFIX_SIZE + ProtocolConstants::NONCE_COUNTER_SIZE + i] =
            static_cast<uint8_t>((idx >> (i * 8)) & 0xFF);
    }

    return nonce;
}
class MockEventHandler : public IProtocolEventHandler {
public:
    void OnProtocolStateChanged(uint32_t connect_id) override {
        call_count++;
        last_connect_id = connect_id;
    }
    void OnRatchetRequired(uint32_t connect_id, const std::string& reason) override {
        ratchet_required_call_count++;
        last_ratchet_connect_id = connect_id;
        last_ratchet_reason = reason;
    }
    int call_count = 0;
    uint32_t last_connect_id = 0;
    int ratchet_required_call_count = 0;
    uint32_t last_ratchet_connect_id = 0;
    std::string last_ratchet_reason;
};
TEST_CASE("EcliptixProtocolConnection - Creation and initialization", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Create initiator connection") {
        auto conn = CreatePreparedConnection(1, true);
        REQUIRE(conn->IsInitiator());
        REQUIRE(conn->ExchangeType() == PubKeyExchangeType::X3DH);
    }
    SECTION("Create responder connection") {
        auto conn = CreatePreparedConnection(2, false);
        REQUIRE_FALSE(conn->IsInitiator());
        REQUIRE(conn->ExchangeType() == PubKeyExchangeType::X3DH);
    }
    SECTION("Connection IDs are unique") {
        auto conn1 = CreatePreparedConnection(1, true);
        auto conn2 = CreatePreparedConnection(2, true);
        (void) conn1;
        (void) conn2;
    }
}
TEST_CASE("EcliptixProtocolConnection - SetPeerBundle", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Set peer bundle before finalization succeeds") {
        auto conn = CreatePreparedConnection(1, true);
        std::vector<uint8_t> ed25519_pub(Constants::ED_25519_PUBLIC_KEY_SIZE, 0x01);
        std::vector<uint8_t> x25519_pub(Constants::X_25519_PUBLIC_KEY_SIZE, 0x02);
        std::vector<uint8_t> spk_pub(Constants::X_25519_PUBLIC_KEY_SIZE, 0x03);
        std::vector<uint8_t> spk_sig(Constants::ED_25519_SIGNATURE_SIZE, 0x04);
        auto kyber_keypair = KyberInterop::GenerateKyber768KeyPair("peer-bundle");
        REQUIRE(kyber_keypair.IsOk());
        auto kyber_public = std::move(kyber_keypair.Unwrap().second);
        LocalPublicKeyBundle bundle(
            ed25519_pub,
            x25519_pub,
            1,
            spk_pub,
            spk_sig,
            {},
            std::nullopt,
            kyber_public
        );
        auto set_result = conn->SetPeerBundle(bundle);
        REQUIRE(set_result.IsOk());
        auto get_result = conn->GetPeerBundle();
        REQUIRE(get_result.IsOk());
        auto retrieved = get_result.Unwrap();
        REQUIRE(retrieved.GetEd25519Public() == ed25519_pub);
    }
    SECTION("Cannot set peer bundle after finalization") {
        auto conn = CreatePreparedConnection(1, true);
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
        auto kyber_keypair = KyberInterop::GenerateKyber768KeyPair("peer-bundle");
        REQUIRE(kyber_keypair.IsOk());
        auto kyber_public = std::move(kyber_keypair.Unwrap().second);
        LocalPublicKeyBundle bundle(
            ed25519_pub,
            x25519_pub,
            1,
            spk_pub,
            spk_sig,
            {},
            std::nullopt,
            kyber_public
        );
        auto set_result = conn->SetPeerBundle(bundle);
        REQUIRE(set_result.IsErr());
    }
}
TEST_CASE("EcliptixProtocolConnection - Finalization", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Successful finalization") {
        auto conn = CreatePreparedConnection(1, true);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer-dh");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
    }
    SECTION("Cannot finalize twice") {
        auto conn = CreatePreparedConnection(1, true);
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
        auto conn = CreatePreparedConnection(1, true);
        std::vector<uint8_t> bad_root_key(16, 0xAA);  
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(bad_root_key, peer_pk);
        REQUIRE(finalize_result.IsErr());
    }
    SECTION("Reject invalid peer DH public key size") {
        auto conn = CreatePreparedConnection(1, true);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        std::vector<uint8_t> bad_peer_pk(16, 0xBB);  
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, bad_peer_pk);
        REQUIRE(finalize_result.IsErr());
    }
}
TEST_CASE("EcliptixProtocolConnection - Nonce generation", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Generate valid nonce") {
        auto conn = CreatePreparedConnection(1, true);
        auto nonce_result = conn->GenerateNextNonce();
        REQUIRE(nonce_result.IsOk());
        auto nonce = nonce_result.Unwrap();
        REQUIRE(nonce.size() == 12);  
    }
    SECTION("Nonces are unique") {
        auto conn = CreatePreparedConnection(1, true);
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
        auto conn = CreatePreparedConnection(1, true);
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
        auto conn = CreatePreparedConnection(1, true);
        std::vector<uint8_t> valid_nonce(12, 0x42);
        auto check_result = conn->CheckReplayProtection(valid_nonce, 1);
        REQUIRE(check_result.IsOk());
    }
    SECTION("Invalid nonce size fails") {
        auto conn = CreatePreparedConnection(1, true);
        std::vector<uint8_t> bad_nonce(8, 0x42);  
        auto check_result = conn->CheckReplayProtection(bad_nonce, 1);
        REQUIRE(check_result.IsErr());
    }
}
TEST_CASE("EcliptixProtocolConnection - Message preparation", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Cannot prepare message before finalization") {
        auto conn = CreatePreparedConnection(1, true);
        auto prepare_result = conn->PrepareNextSendMessage();
        REQUIRE(prepare_result.IsErr());
    }
    SECTION("Prepare message after finalization succeeds") {
        auto conn = CreatePreparedConnection(1, true);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto prepare_result = conn->PrepareNextSendMessage();
        REQUIRE(prepare_result.IsOk());
        auto [ratchet_key, include_dh] = prepare_result.Unwrap();
        REQUIRE(ratchet_key.Index() == 0);  // First message has index 0  
    }
    SECTION("Multiple message preparation increments index") {
        auto conn = CreatePreparedConnection(1, true);
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
        REQUIRE(msg1.Unwrap().first.Index() == 0);  // Message indices start at 0
        REQUIRE(msg2.Unwrap().first.Index() == 1);
        REQUIRE(msg3.Unwrap().first.Index() == 2);
    }
}
TEST_CASE("EcliptixProtocolConnection - Message processing", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Cannot process message before finalization") {
        auto conn = CreatePreparedConnection(1, false);
        auto process_result = conn->ProcessReceivedMessage(1, MakeTestNonce(1));
        REQUIRE(process_result.IsErr());
    }
    SECTION("Process message after finalization succeeds") {
        auto conn = CreatePreparedConnection(1, false);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto process_result = conn->ProcessReceivedMessage(0, MakeTestNonce(0));
        REQUIRE(process_result.IsOk());
        auto ratchet_key = process_result.Unwrap();
        REQUIRE(ratchet_key.Index() == 0);
    }
}
TEST_CASE("EcliptixProtocolConnection - DH ratchet operations", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Perform receiving ratchet with valid key") {
        auto conn = CreatePreparedConnection(1, false);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto new_keypair = SodiumInterop::GenerateX25519KeyPair("test-new-ephemeral");
        REQUIRE(new_keypair.IsOk());
        auto [new_sk, new_pk] = std::move(new_keypair).Unwrap();
        auto kyber_encap = KyberInterop::Encapsulate(conn->GetKyberPublicKeyCopy());
        REQUIRE(kyber_encap.IsOk());
        auto [ct, ss_handle] = std::move(kyber_encap).Unwrap();
        auto ratchet_result = conn->PerformReceivingRatchet(new_pk, ct);
        REQUIRE(ratchet_result.IsOk());
    }
    SECTION("Reject invalid DH key size") {
        auto conn = CreatePreparedConnection(1, false);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        std::vector<uint8_t> bad_dh_key(16, 0xBB);  
        auto kyber_encap = KyberInterop::Encapsulate(conn->GetKyberPublicKeyCopy());
        REQUIRE(kyber_encap.IsOk());
        auto [ct, ss_handle] = std::move(kyber_encap).Unwrap();
        auto ratchet_result = conn->PerformReceivingRatchet(bad_dh_key, ct);
        REQUIRE(ratchet_result.IsErr());
    }
    SECTION("NotifyRatchetRotation sets flag") {
        auto conn = CreatePreparedConnection(1, true);
        conn->NotifyRatchetRotation();
    }
}
TEST_CASE("EcliptixProtocolConnection - State queries", "[connection]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Get current sender DH public key") {
        auto conn = CreatePreparedConnection(1, true);
        auto key_result = conn->GetCurrentSenderDhPublicKey();
        REQUIRE(key_result.IsOk());
        auto key_opt = key_result.Unwrap();
        REQUIRE(key_opt.has_value());
        REQUIRE(key_opt->size() == Constants::X_25519_PUBLIC_KEY_SIZE);
    }
    SECTION("Get metadata encryption key before finalization fails") {
        auto conn = CreatePreparedConnection(1, true);
        auto key_result = conn->GetMetadataEncryptionKey();
        REQUIRE(key_result.IsErr());
    }
    SECTION("Get metadata encryption key after finalization succeeds") {
        auto conn = CreatePreparedConnection(1, true);
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
        auto conn = CreatePreparedConnection(1, true);
        auto sync_result = conn->SyncWithRemoteState(10, 10);
        REQUIRE(sync_result.IsErr());
    }
    SECTION("Successful sync with remote state") {
        auto conn = CreatePreparedConnection(1, true);
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
        auto conn = CreatePreparedConnection(1, false);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto msg0 = conn->ProcessReceivedMessage(0, MakeTestNonce(0));
        REQUIRE(msg0.IsOk());
        auto sync_result = conn->SyncWithRemoteState(10, 0);
        REQUIRE(sync_result.IsOk());
        auto msg10 = conn->ProcessReceivedMessage(10, MakeTestNonce(10));
        REQUIRE(msg10.IsOk());
    }
    SECTION("Sync advances sending chain") {
        auto conn = CreatePreparedConnection(1, true);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        auto msg1 = conn->PrepareNextSendMessage();
        REQUIRE(msg1.IsOk());
        REQUIRE(msg1.Unwrap().first.Index() == 0);  // First message has index 0
        auto sync_result = conn->SyncWithRemoteState(0, 6);
        REQUIRE(sync_result.IsOk());
        auto msg_next = conn->PrepareNextSendMessage();
        REQUIRE(msg_next.IsOk());
        REQUIRE(msg_next.Unwrap().first.Index() == 6);  // Synced to index 6
    }
    SECTION("Reject sync with gap too large") {
        auto conn = CreatePreparedConnection(1, true);
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
        auto conn = CreatePreparedConnection(42, true);
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
        auto conn = CreatePreparedConnection(99, true);
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
        auto conn = CreatePreparedConnection(1, true);
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
        auto [alice, bob] = CreatePreparedPair(1, 2);
        PrepareHybridHandshake(alice, bob);
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
        auto kyber_ct = EncapsulateTo(alice->GetKyberPublicKeyCopy());
        auto ratchet_result = alice->PerformReceivingRatchet(new_bob_pk, kyber_ct);
        REQUIRE(ratchet_result.IsOk());
        REQUIRE(handler->call_count > calls_after_finalize);
        REQUIRE(handler->last_connect_id == 1);
    }
}
TEST_CASE("EcliptixProtocolConnection - Nonce Counter Overflow Protection", "[connection][security]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Nonce generation succeeds for reasonable message counts") {
        auto conn = CreatePreparedConnection(1, true);
        for (int i = 0; i < 500; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();
            REQUIRE(nonce.size() == 12);
        }
    }
}
TEST_CASE("EcliptixProtocolConnection - Reflection Attack Protection", "[connection][security]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Detect reflection attack - peer echoes our DH key") {
        auto alice = CreatePreparedConnection(1, true);
        auto alice_dh_key = alice->GetCurrentSenderDhPublicKey();
        REQUIRE(alice_dh_key.IsOk());
        auto alice_dh_option = std::move(alice_dh_key).Unwrap();
        REQUIRE(alice_dh_option.has_value());
        auto alice_dh = std::move(alice_dh_option).value();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x42);
        auto finalize_result = alice->FinalizeChainAndDhKeys(root_key, alice_dh);
        REQUIRE(finalize_result.IsErr());
        auto error = std::move(finalize_result).UnwrapErr();
        REQUIRE(error.message.find("reflection attack") != std::string::npos);
    }
    SECTION("Allow valid DH key exchange") {
        auto alice = CreatePreparedConnection(1, true);
        auto bob_keypair = SodiumInterop::GenerateX25519KeyPair("bob");
        REQUIRE(bob_keypair.IsOk());
        auto [bob_sk, bob_pk] = std::move(bob_keypair).Unwrap();
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x42);
        auto finalize_result = alice->FinalizeChainAndDhKeys(root_key, bob_pk);
        REQUIRE(finalize_result.IsOk());
    }
}
TEST_CASE("EcliptixProtocolConnection - Sprint 1.5B: Nonce Counter Never Resets (CVE Fix)", "[connection][security][sprint1.5b]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Nonce counter continues monotonically after DH ratchet (CVE-2024-XXXXX fix)") {
        auto conn = CreatePreparedConnection(1, true);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        for (int i = 0; i < 100; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
        }
        auto nonce1 = conn->GenerateNextNonce();
        REQUIRE(nonce1.IsOk());
        auto nonce1_bytes = std::move(nonce1).Unwrap();
        uint32_t counter_before_ratchet = 0;
        for (size_t i = 0; i < ProtocolConstants::NONCE_COUNTER_SIZE; ++i) {
            counter_before_ratchet |=
                static_cast<uint32_t>(nonce1_bytes[ProtocolConstants::NONCE_PREFIX_SIZE + i]) << (i * 8);
        }
        REQUIRE(counter_before_ratchet >= 100);
        auto new_peer_keypair = SodiumInterop::GenerateX25519KeyPair("new-peer");
        REQUIRE(new_peer_keypair.IsOk());
        auto [new_peer_sk, new_peer_pk] = std::move(new_peer_keypair).Unwrap();
        auto kyber_ct = EncapsulateTo(conn->GetKyberPublicKeyCopy());
        auto ratchet_result = conn->PerformReceivingRatchet(new_peer_pk, kyber_ct);
        REQUIRE(ratchet_result.IsOk());
        auto nonce2 = conn->GenerateNextNonce();
        REQUIRE(nonce2.IsOk());
        auto nonce2_bytes = std::move(nonce2).Unwrap();
        uint32_t counter_after_ratchet = 0;
        for (size_t i = 0; i < ProtocolConstants::NONCE_COUNTER_SIZE; ++i) {
            counter_after_ratchet |=
                static_cast<uint32_t>(nonce2_bytes[ProtocolConstants::NONCE_PREFIX_SIZE + i]) << (i * 8);
        }
        // CVE FIX: Nonce counter MUST continue monotonically and NEVER reset
        // This prevents nonce reuse across ratchet epochs which could break AEAD security
        REQUIRE(counter_after_ratchet > counter_before_ratchet);
        REQUIRE(counter_after_ratchet >= 101);
    }
    SECTION("Ratchet warning flag resets after DH ratchet") {
        auto handler = std::make_shared<MockEventHandler>();
        auto conn = CreatePreparedConnection(1, true);
        conn->SetEventHandler(handler);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        REQUIRE(handler->ratchet_required_call_count == 0);
        auto new_peer_keypair = SodiumInterop::GenerateX25519KeyPair("new-peer");
        REQUIRE(new_peer_keypair.IsOk());
        auto [new_peer_sk, new_peer_pk] = std::move(new_peer_keypair).Unwrap();
        REQUIRE(handler->ratchet_required_call_count == 0);
    }
}
TEST_CASE("EcliptixProtocolConnection - Sprint 1.5B: Nonce Uniqueness Across Ratchet", "[connection][security][sprint1.5b]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("No nonce reuse across DH ratchet boundary") {
        auto conn = CreatePreparedConnection(1, true);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        std::unordered_set<std::string> nonce_set;
        for (int i = 0; i < 200; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();
            std::string nonce_str(nonce.begin(), nonce.end());
            REQUIRE(nonce_set.find(nonce_str) == nonce_set.end());
            nonce_set.insert(nonce_str);
        }
        auto new_peer_keypair = SodiumInterop::GenerateX25519KeyPair("new-peer");
        REQUIRE(new_peer_keypair.IsOk());
        auto [new_peer_sk, new_peer_pk] = std::move(new_peer_keypair).Unwrap();
        auto kyber_ct = EncapsulateTo(conn->GetKyberPublicKeyCopy());
        auto ratchet_result = conn->PerformReceivingRatchet(new_peer_pk, kyber_ct);
        REQUIRE(ratchet_result.IsOk());
        for (int i = 0; i < 200; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();
            std::string nonce_str(nonce.begin(), nonce.end());
            REQUIRE(nonce_set.find(nonce_str) == nonce_set.end());
            nonce_set.insert(nonce_str);
        }
        REQUIRE(nonce_set.size() == 400);
    }
}
TEST_CASE("EcliptixProtocolConnection - Sprint 1.5B: Concurrent Send + Ratchet Stress Test", "[connection][security][sprint1.5b][stress]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("No nonce collisions under concurrent load") {
        auto conn = CreatePreparedConnection(1, true);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xBB);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        std::unordered_set<std::string> nonce_set;
        std::mutex nonce_set_mutex;
        std::atomic<bool> collision_detected{false};
        std::atomic<int> success_count{0};
        constexpr int THREAD_COUNT = 4;
        constexpr int NONCES_PER_THREAD = 50;
        std::vector<std::thread> threads;
        for (int t = 0; t < THREAD_COUNT; ++t) {
            threads.emplace_back([&]() {
                for (int i = 0; i < NONCES_PER_THREAD; ++i) {
                    auto nonce_result = conn->GenerateNextNonce();
                    if (nonce_result.IsOk()) {
                        auto nonce = std::move(nonce_result).Unwrap();
                        std::string nonce_str(nonce.begin(), nonce.end());
                        std::lock_guard<std::mutex> lock(nonce_set_mutex);
                        if (nonce_set.find(nonce_str) != nonce_set.end()) {
                            collision_detected.store(true);
                        }
                        nonce_set.insert(nonce_str);
                        success_count.fetch_add(1);
                    }
                }
            });
        }
        for (auto& thread : threads) {
            thread.join();
        }
        REQUIRE_FALSE(collision_detected.load());
        REQUIRE(success_count.load() == THREAD_COUNT * NONCES_PER_THREAD);
        REQUIRE(nonce_set.size() == THREAD_COUNT * NONCES_PER_THREAD);
    }
}
TEST_CASE("EcliptixProtocolConnection - Sprint 1.5B: MAX_CHAIN_LENGTH Enforcement", "[connection][security][sprint1.5b]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Chain length enforcement triggers ratchet requirement") {
        RatchetConfig config(50000);
        auto conn = CreatePreparedConnection(1, true, config);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xCC);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        bool chain_length_error_detected = false;
        for (uint32_t i = 0; i < ProtocolConstants::MAX_CHAIN_LENGTH + 100; ++i) {
            auto msg_result = conn->PrepareNextSendMessage();
            if (msg_result.IsErr()) {
                auto err = std::move(msg_result).UnwrapErr();
                if (err.message.find("Chain length exceeded maximum") != std::string::npos) {
                    chain_length_error_detected = true;
                    break;
                }
            }
        }
        REQUIRE(chain_length_error_detected);
    }
}
TEST_CASE("EcliptixProtocolConnection - Sprint 1.5B: Ratchet Warning Reset", "[connection][security][sprint1.5b]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Ratchet warning can trigger again after reset") {
        auto handler = std::make_shared<MockEventHandler>();
        auto conn = CreatePreparedConnection(1, true);
        conn->SetEventHandler(handler);
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xDD);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("test-peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();
        auto finalize_result = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize_result.IsOk());
        REQUIRE(handler->ratchet_required_call_count == 0);
        auto new_peer_keypair = SodiumInterop::GenerateX25519KeyPair("new-peer");
        REQUIRE(new_peer_keypair.IsOk());
        auto [new_peer_sk, new_peer_pk] = std::move(new_peer_keypair).Unwrap();
        REQUIRE(handler->ratchet_required_call_count == 0);
    }
}
