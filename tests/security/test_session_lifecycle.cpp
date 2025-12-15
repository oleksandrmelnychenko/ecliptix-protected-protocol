#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include <vector>
#include <thread>
#include <chrono>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::crypto;

static std::vector<uint8_t> MakeNonce(uint64_t idx) {
    // Nonce structure (12 bytes total):
    // Bytes [0-7]: Monotonic counter (use idx for test simplicity)
    // Bytes [8-11]: Message index in little-endian format
    std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE, 0);

    // Set monotonic counter (bytes 0-7)
    for (size_t i = 0; i < 8; ++i) {
        nonce[i] = static_cast<uint8_t>((idx >> (i * 8)) & 0xFF);
    }

    // Set message index in little-endian (bytes 8-11)
    for (size_t i = 0; i < 4; ++i) {
        nonce[8 + i] = static_cast<uint8_t>((idx >> (i * 8)) & 0xFF);
    }

    return nonce;
}

TEST_CASE("Session Lifecycle - PrepareNextSendMessage Respects Timeout", "[security][session][timeout]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("PrepareNextSendMessage fails after 24 hour timeout") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

        auto prepare_before = conn->PrepareNextSendMessage();
        REQUIRE(prepare_before.IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(6));
#else
        std::this_thread::sleep_for(std::chrono::hours(24) + std::chrono::seconds(1));
#endif

        auto prepare_after = conn->PrepareNextSendMessage();
        REQUIRE(prepare_after.IsErr());
    }
}

TEST_CASE("Session Lifecycle - GenerateNextNonce Respects Timeout", "[security][session][timeout]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("GenerateNextNonce fails after 24 hour timeout") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xBB);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

        auto nonce_before = conn->GenerateNextNonce();
        REQUIRE(nonce_before.IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(6));
#else
        std::this_thread::sleep_for(std::chrono::hours(24) + std::chrono::seconds(1));
#endif

        auto nonce_after = conn->GenerateNextNonce();
        REQUIRE(nonce_after.IsErr());
    }
}

TEST_CASE("Session Lifecycle - ProcessReceivedMessage Respects Timeout", "[security][session][timeout]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("ProcessReceivedMessage fails after 24 hour timeout") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xCC);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        auto process_before = bob->ProcessReceivedMessage(0, MakeNonce(0x00));
        REQUIRE(process_before.IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(6));
#else
        std::this_thread::sleep_for(std::chrono::hours(24) + std::chrono::seconds(1));
#endif

        auto process_after = bob->ProcessReceivedMessage(1, MakeNonce(0x01));
        REQUIRE(process_after.IsErr());
    }
}

TEST_CASE("Session Lifecycle - Multiple Operations Before Timeout", "[security][session][timeout]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("All operations succeed within 24 hour window") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xDD);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        for (uint32_t i = 0; i < 100; ++i) {
            auto nonce = alice->GenerateNextNonce();
            REQUIRE(nonce.IsOk());

            auto prepare = alice->PrepareNextSendMessage();
            REQUIRE(prepare.IsOk());

            auto process = bob->ProcessReceivedMessage(i, MakeNonce(static_cast<uint8_t>(i & 0xFF)));
            REQUIRE(process.IsOk());
        }
    }
}

TEST_CASE("Session Lifecycle - All Operations Fail After Timeout", "[security][session][timeout]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("All operations fail after 24 hour timeout") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xEE);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(6));
#else
        std::this_thread::sleep_for(std::chrono::hours(24) + std::chrono::seconds(1));
#endif

        auto nonce = alice->GenerateNextNonce();
        REQUIRE(nonce.IsErr());

        auto prepare = alice->PrepareNextSendMessage();
        REQUIRE(prepare.IsErr());

        auto process = bob->ProcessReceivedMessage(0, MakeNonce(0x00));
        REQUIRE(process.IsErr());
    }
}

TEST_CASE("Session Lifecycle - Timeout Boundary Test", "[security][session][timeout][boundary]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Operations succeed just before timeout") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xFF);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(3));  // Well before 5-second timeout
#else
        std::this_thread::sleep_for(std::chrono::hours(23) + std::chrono::minutes(59));
#endif

        auto nonce = conn->GenerateNextNonce();
        REQUIRE(nonce.IsOk());

        auto prepare = conn->PrepareNextSendMessage();
        REQUIRE(prepare.IsOk());
    }
}

TEST_CASE("Session Lifecycle - Independent Connection Timeouts", "[security][session][timeout][isolation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Each connection has independent timeout") {
        auto conn1_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn1_result.IsOk());
        auto conn1 = std::move(conn1_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x11);
        auto peer1 = SodiumInterop::GenerateX25519KeyPair("peer1");
        REQUIRE(peer1.IsOk());
        auto [peer1_sk, peer1_pk] = std::move(peer1).Unwrap();

        REQUIRE(conn1->FinalizeChainAndDhKeys(root_key, peer1_pk).IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(6));
#else
        std::this_thread::sleep_for(std::chrono::hours(24) + std::chrono::seconds(1));
#endif

        auto conn2_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(conn2_result.IsOk());
        auto conn2 = std::move(conn2_result).Unwrap();

        auto peer2 = SodiumInterop::GenerateX25519KeyPair("peer2");
        REQUIRE(peer2.IsOk());
        auto [peer2_sk, peer2_pk] = std::move(peer2).Unwrap();

        REQUIRE(conn2->FinalizeChainAndDhKeys(root_key, peer2_pk).IsOk());

        auto conn1_nonce = conn1->GenerateNextNonce();
        REQUIRE(conn1_nonce.IsErr());

        auto conn2_nonce = conn2->GenerateNextNonce();
        REQUIRE(conn2_nonce.IsOk());

        auto conn1_prepare = conn1->PrepareNextSendMessage();
        REQUIRE(conn1_prepare.IsErr());

        auto conn2_prepare = conn2->PrepareNextSendMessage();
        REQUIRE(conn2_prepare.IsOk());
    }
}

TEST_CASE("Session Lifecycle - Concurrent Timeout Checks", "[security][session][timeout][concurrent]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Concurrent operations all respect timeout") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x22);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(6));
#else
        std::this_thread::sleep_for(std::chrono::hours(24) + std::chrono::seconds(1));
#endif

        std::atomic<uint32_t> failed_operations{0};
        std::atomic<uint32_t> successful_operations{0};

        const uint32_t NUM_THREADS = 10;
        const uint32_t ATTEMPTS_PER_THREAD = 10;

        std::vector<std::thread> threads;
        for (uint32_t t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (uint32_t i = 0; i < ATTEMPTS_PER_THREAD; ++i) {
                    auto nonce_result = conn->GenerateNextNonce();
                    if (nonce_result.IsErr()) {
                        failed_operations.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        successful_operations.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(failed_operations.load() == NUM_THREADS * ATTEMPTS_PER_THREAD);
        REQUIRE(successful_operations.load() == 0);
    }
}
