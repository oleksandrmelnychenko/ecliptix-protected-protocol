#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/protocol_connection.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "helpers/hybrid_handshake.hpp"
#include "ecliptix/core/constants.hpp"
#include <vector>
#include <thread>
#include <chrono>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::test_helpers;

static std::vector<uint8_t> MakeNonce(uint64_t idx) {
    std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE, 0);

    for (size_t i = 0; i < ProtocolConstants::NONCE_COUNTER_SIZE; ++i) {
        nonce[ProtocolConstants::NONCE_PREFIX_SIZE + i] =
            static_cast<uint8_t>((idx >> (i * 8)) & 0xFF);
    }

    for (size_t i = 0; i < ProtocolConstants::NONCE_INDEX_SIZE; ++i) {
        nonce[ProtocolConstants::NONCE_PREFIX_SIZE + ProtocolConstants::NONCE_COUNTER_SIZE + i] =
            static_cast<uint8_t>((idx >> (i * 8)) & 0xFF);
    }

    return nonce;
}

TEST_CASE("Session Lifecycle - GetSessionAgeSeconds Returns Correct Age", "[security][session][age]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Session age increases over time") {
        auto conn = CreatePreparedConnection(1, true);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

        auto age_before = conn->GetSessionAgeSeconds();
        REQUIRE(age_before < 2);

        std::this_thread::sleep_for(std::chrono::seconds(2));

        auto age_after = conn->GetSessionAgeSeconds();
        REQUIRE(age_after >= 2);
        REQUIRE(age_after < 5);
    }
}

TEST_CASE("Session Lifecycle - GetSessionAgeSeconds for New Connection", "[security][session][age]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("New connection has age near zero") {
        auto conn = CreatePreparedConnection(1, true);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xBB);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

        auto age = conn->GetSessionAgeSeconds();
        REQUIRE(age < 2);
    }
}

TEST_CASE("Session Lifecycle - Operations Succeed Without Timeout Enforcement", "[security][session][no-timeout]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("PrepareNextSendMessage succeeds regardless of session age") {
        auto conn = CreatePreparedConnection(1, true);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

        auto prepare_before = conn->PrepareNextSendMessage();
        REQUIRE(prepare_before.IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(2));
#endif

        auto prepare_after = conn->PrepareNextSendMessage();
        REQUIRE(prepare_after.IsOk());
    }
}

TEST_CASE("Session Lifecycle - GenerateNextNonce Without Timeout", "[security][session][no-timeout]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("GenerateNextNonce succeeds regardless of session age") {
        auto conn = CreatePreparedConnection(1, true);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xBB);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

        auto nonce_before = conn->GenerateNextNonce();
        REQUIRE(nonce_before.IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(2));
#endif

        auto nonce_after = conn->GenerateNextNonce();
        REQUIRE(nonce_after.IsOk());
    }
}

TEST_CASE("Session Lifecycle - ProcessReceivedMessage Without Timeout", "[security][session][no-timeout]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("ProcessReceivedMessage succeeds regardless of session age") {
        auto [alice, bob] = CreatePreparedPair(1, 2);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xCC);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        auto process_before = bob->ProcessReceivedMessage(0, MakeNonce(0x00));
        REQUIRE(process_before.IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(2));
#endif

        auto process_after = bob->ProcessReceivedMessage(1, MakeNonce(0x01));
        REQUIRE(process_after.IsOk());
    }
}

TEST_CASE("Session Lifecycle - Multiple Operations Over Time", "[security][session][no-timeout]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("All operations continue to work over time") {
        auto [alice, bob] = CreatePreparedPair(1, 2);

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

        auto age = alice->GetSessionAgeSeconds();
        INFO("Session age after 100 operations: " << age << " seconds");
    }
}

TEST_CASE("Session Lifecycle - All Operations Work After Extended Time", "[security][session][no-timeout]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("All operations succeed after extended time (no timeout enforcement)") {
        auto [alice, bob] = CreatePreparedPair(1, 2);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xEE);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(2));
#endif

        auto nonce = alice->GenerateNextNonce();
        REQUIRE(nonce.IsOk());

        auto prepare = alice->PrepareNextSendMessage();
        REQUIRE(prepare.IsOk());

        auto process = bob->ProcessReceivedMessage(0, MakeNonce(0x00));
        REQUIRE(process.IsOk());

        auto alice_age = alice->GetSessionAgeSeconds();
        auto bob_age = bob->GetSessionAgeSeconds();
        INFO("Alice session age: " << alice_age << " seconds");
        INFO("Bob session age: " << bob_age << " seconds");
        REQUIRE(alice_age >= 2);
        REQUIRE(bob_age >= 2);
    }
}

TEST_CASE("Session Lifecycle - Independent Connection Ages", "[security][session][age][isolation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Each connection tracks age independently") {
        auto conn1 = CreatePreparedConnection(1, true);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x11);
        auto peer1 = SodiumInterop::GenerateX25519KeyPair("peer1");
        REQUIRE(peer1.IsOk());
        auto [peer1_sk, peer1_pk] = std::move(peer1).Unwrap();

        REQUIRE(conn1->FinalizeChainAndDhKeys(root_key, peer1_pk).IsOk());

        std::this_thread::sleep_for(std::chrono::seconds(2));

        auto conn2 = CreatePreparedConnection(2, false);

        auto peer2 = SodiumInterop::GenerateX25519KeyPair("peer2");
        REQUIRE(peer2.IsOk());
        auto [peer2_sk, peer2_pk] = std::move(peer2).Unwrap();

        REQUIRE(conn2->FinalizeChainAndDhKeys(root_key, peer2_pk).IsOk());

        auto conn1_nonce = conn1->GenerateNextNonce();
        REQUIRE(conn1_nonce.IsOk());

        auto conn2_nonce = conn2->GenerateNextNonce();
        REQUIRE(conn2_nonce.IsOk());

        auto age1 = conn1->GetSessionAgeSeconds();
        auto age2 = conn2->GetSessionAgeSeconds();

        REQUIRE(age1 >= 2);
        REQUIRE(age2 < 2);
        REQUIRE(age1 > age2);
    }
}

TEST_CASE("Session Lifecycle - Concurrent Operations Without Timeout", "[security][session][no-timeout][concurrent]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Concurrent operations all succeed") {
        auto conn = CreatePreparedConnection(1, true);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x22);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        std::this_thread::sleep_for(std::chrono::seconds(2));
#endif

        std::atomic<int> success_count{0};
        std::atomic<int> failure_count{0};
        std::vector<std::thread> threads;

        for (int i = 0; i < 10; ++i) {
            threads.emplace_back([&conn, &success_count, &failure_count]() {
                auto result = conn->GenerateNextNonce();
                if (result.IsOk()) {
                    success_count++;
                } else {
                    failure_count++;
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        REQUIRE(success_count == 10);
        REQUIRE(failure_count == 0);
    }
}
