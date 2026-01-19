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

static std::vector<uint8_t> MakeRateNonce(uint64_t idx) {
    std::vector<uint8_t> nonce(kAesGcmNonceBytes, 0);

    for (size_t i = 0; i < kNonceCounterBytes; ++i) {
        nonce[kNoncePrefixBytes + i] =
            static_cast<uint8_t>((idx >> (i * 8)) & 0xFF);
    }

    for (size_t i = 0; i < kNonceIndexBytes; ++i) {
        nonce[kNoncePrefixBytes + kNonceCounterBytes + i] =
            static_cast<uint8_t>((idx >> (i * 8)) & 0xFF);
    }

    return nonce;
}

TEST_CASE("Rate Limiting - Nonce Generation Rate Limit", "[security][rate_limiting][nonce]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Nonce generation respects 1000/second rate limit") {
        auto conn = CreatePreparedConnection(1, true);

        std::vector<uint8_t> root_key(kRootKeyBytes, 0xAA);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

        uint32_t successful_nonces = 0;
        uint32_t rate_limited = 0;

#ifdef ECLIPTIX_TEST_BUILD
        constexpr uint32_t EXPECTED_LIMIT = 100'000;
        constexpr uint32_t TEST_ITERATIONS = 100'500;
        constexpr uint32_t EXPECTED_BLOCKED = 500;
#else
        constexpr uint32_t EXPECTED_LIMIT = 1000;
        constexpr uint32_t TEST_ITERATIONS = 1500;
        constexpr uint32_t EXPECTED_BLOCKED = 500;
#endif

        for (uint32_t i = 0; i < TEST_ITERATIONS; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            if (nonce_result.IsOk()) {
                ++successful_nonces;
            } else {
                ++rate_limited;
            }
        }

        REQUIRE(successful_nonces == EXPECTED_LIMIT);
        REQUIRE(rate_limited == EXPECTED_BLOCKED);
    }
}

TEST_CASE("Rate Limiting - Nonce Rate Limit Resets After One Second", "[security][rate_limiting][nonce][reset]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Rate limit window resets after 1 second") {
        auto conn = CreatePreparedConnection(1, true);

        std::vector<uint8_t> root_key(kRootKeyBytes, 0xBB);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

#ifdef ECLIPTIX_TEST_BUILD
        for (uint32_t i = 0; i < 100'000; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
        }

        auto rate_limited_result = conn->GenerateNextNonce();
        REQUIRE(rate_limited_result.IsErr());

        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto after_reset = conn->GenerateNextNonce();
        REQUIRE(after_reset.IsOk());
#else
        for (uint32_t i = 0; i < 1000; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
        }

        auto rate_limited_result = conn->GenerateNextNonce();
        REQUIRE(rate_limited_result.IsErr());

        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto after_reset = conn->GenerateNextNonce();
        REQUIRE(after_reset.IsOk());
#endif
    }
}

TEST_CASE("Rate Limiting - Concurrent Nonce Generation Respects Rate Limit", "[security][rate_limiting][nonce][concurrent]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Multiple threads respect shared rate limit") {
        auto conn = CreatePreparedConnection(1, true);

        std::vector<uint8_t> root_key(kRootKeyBytes, 0xCC);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

        std::atomic<uint32_t> successful_nonces{0};
        std::atomic<uint32_t> rate_limited{0};

        const uint32_t NUM_THREADS = 10;
        const uint32_t ATTEMPTS_PER_THREAD = 200;

        std::vector<std::thread> threads;
        for (uint32_t t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (uint32_t i = 0; i < ATTEMPTS_PER_THREAD; ++i) {
                    auto nonce_result = conn->GenerateNextNonce();
                    if (nonce_result.IsOk()) {
                        successful_nonces.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        rate_limited.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        const uint32_t total = successful_nonces.load() + rate_limited.load();
        REQUIRE(total == NUM_THREADS * ATTEMPTS_PER_THREAD);
#ifdef ECLIPTIX_TEST_BUILD
        REQUIRE(successful_nonces.load() == 2000);
        REQUIRE(rate_limited.load() == 0);
#else
        REQUIRE(successful_nonces.load() == 1000);
        REQUIRE(rate_limited.load() == 1000);
#endif
    }
}

TEST_CASE("Rate Limiting - DH Ratchet Flood Protection", "[security][rate_limiting][dh_ratchet]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("DH ratchet rate limited to prevent DoS") {
        auto [alice, bob] = CreatePreparedPair(1, 2);

        std::vector<uint8_t> root_key(kRootKeyBytes, 0xDD);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        uint32_t successful_ratchets = 0;

        for (uint32_t attempt = 0; attempt < 20; ++attempt) {
            for (uint32_t i = 0; i < 100; ++i) {
                auto prepare = alice->PrepareNextSendMessage();
                if (prepare.IsOk()) {
                    auto process = bob->ProcessReceivedMessage(attempt * 100 + i, MakeRateNonce(attempt * 100 + i));
                    if (process.IsOk()) {
                        ++successful_ratchets;
                    }
                }
            }
        }

#ifdef ECLIPTIX_TEST_BUILD
        REQUIRE(successful_ratchets > 0);
        REQUIRE(successful_ratchets == 2000);
#else
        REQUIRE(successful_ratchets > 0);
        REQUIRE(successful_ratchets <= 1000);
#endif
    }
}

TEST_CASE("Rate Limiting - DH Ratchet Rate Resets Per Minute", "[security][rate_limiting][dh_ratchet][reset]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("DH ratchet rate limit resets after 1 minute") {
        auto [alice, bob] = CreatePreparedPair(1, 2);

        std::vector<uint8_t> root_key(kRootKeyBytes, 0xEE);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        uint32_t first_window_ratchets = 0;
        for (uint32_t attempt = 0; attempt < 15; ++attempt) {
            for (uint32_t i = 0; i < 100; ++i) {
                auto prepare = alice->PrepareNextSendMessage();
                if (prepare.IsOk()) {
                    auto process = bob->ProcessReceivedMessage(attempt * 100 + i, MakeRateNonce(attempt * 100 + i));
                    if (process.IsOk()) {
                        ++first_window_ratchets;
                    }
                }
            }
        }

#ifdef ECLIPTIX_TEST_BUILD
        REQUIRE(first_window_ratchets == 1500);
#else
        REQUIRE(first_window_ratchets == 10);

        auto blocked_prepare = alice->PrepareNextSendMessage();
        REQUIRE(blocked_prepare.IsErr());

        std::this_thread::sleep_for(std::chrono::seconds(60));

        auto after_reset = alice->PrepareNextSendMessage();
        REQUIRE(after_reset.IsOk());
#endif
    }
}

TEST_CASE("Rate Limiting - Nonce Burst Protection", "[security][rate_limiting][nonce][burst]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Rapid nonce bursts are blocked after limit") {
        auto conn = CreatePreparedConnection(1, true);

        std::vector<uint8_t> root_key(kRootKeyBytes, 0xFF);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        REQUIRE(conn->FinalizeChainAndDhKeys(root_key, peer_pk).IsOk());

        std::vector<uint32_t> burst_sizes = {100, 200, 500, 200};
        std::vector<uint32_t> successful_per_burst;
        std::vector<uint32_t> blocked_per_burst;

        for (const auto burst_size : burst_sizes) {
            uint32_t success = 0;
            uint32_t blocked = 0;

            for (uint32_t i = 0; i < burst_size; ++i) {
                auto nonce_result = conn->GenerateNextNonce();
                if (nonce_result.IsOk()) {
                    ++success;
                } else {
                    ++blocked;
                }
            }

            successful_per_burst.push_back(success);
            blocked_per_burst.push_back(blocked);
        }

        uint32_t total_successful = 0;
        for (const auto count : successful_per_burst) {
            total_successful += count;
        }
        REQUIRE(total_successful == 1000);

        uint32_t total_blocked = 0;
        for (const auto count : blocked_per_burst) {
            total_blocked += count;
        }
        REQUIRE(total_blocked == 100 + 200 + 500 + 200 - 1000);
    }
}

TEST_CASE("Rate Limiting - DH Ratchet Independent of Message Count", "[security][rate_limiting][dh_ratchet][independence]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("DH ratchet rate limit independent of message throughput") {
        auto [alice, bob] = CreatePreparedPair(1, 2);

        std::vector<uint8_t> root_key(kRootKeyBytes, 0x11);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        uint32_t total_messages = 0;
        uint32_t total_ratchets = 0;

        for (uint32_t ratchet = 0; ratchet < 15; ++ratchet) {
            const uint32_t messages_in_ratchet = (ratchet % 3 == 0) ? 50 : 150;

            for (uint32_t i = 0; i < messages_in_ratchet; ++i) {
                auto prepare = alice->PrepareNextSendMessage();
                if (prepare.IsOk()) {
                    auto [key, include_dh] = std::move(prepare).Unwrap();
                    auto process = bob->ProcessReceivedMessage(total_messages, MakeRateNonce(total_messages));
                    if (process.IsOk()) {
                        ++total_messages;
                        if (include_dh) {
                            ++total_ratchets;
                        }
                    }
                }
            }
        }

        REQUIRE(total_messages > 0);
#ifdef ECLIPTIX_TEST_BUILD
        REQUIRE(total_ratchets == 17);
#else
        REQUIRE(total_ratchets <= 10);
#endif
    }
}

TEST_CASE("Rate Limiting - Combined Nonce and DH Rate Limits", "[security][rate_limiting][combined]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Both rate limits enforced independently") {
        auto [alice, bob] = CreatePreparedPair(1, 2);

        std::vector<uint8_t> root_key(kRootKeyBytes, 0x22);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        uint32_t nonce_limit_hits = 0;
        uint32_t successful_ops = 0;

        for (uint32_t i = 0; i < 2000; ++i) {
            auto nonce_result = alice->GenerateNextNonce();
            if (nonce_result.IsErr()) {
                ++nonce_limit_hits;
                continue;
            }

            if (i % 100 == 0) {
                auto prepare = alice->PrepareNextSendMessage();
                if (prepare.IsErr()) {
                    continue;
                }
                auto process = bob->ProcessReceivedMessage(i, MakeRateNonce(i));
                if (process.IsErr()) {
                    continue;
                }
            }

            ++successful_ops;
        }

#ifdef ECLIPTIX_TEST_BUILD
        REQUIRE(nonce_limit_hits == 0);
        REQUIRE(successful_ops == 2000);
#else
        REQUIRE(nonce_limit_hits > 0);
        REQUIRE(successful_ops <= 1000);
#endif
    }
}
