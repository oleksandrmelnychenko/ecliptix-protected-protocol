#include <catch2/catch_test_macros.hpp>
#include "ecliptix/security/ratcheting/replay_protection.hpp"
#include "ecliptix/core/constants.hpp"
#include <sodium.h>
#include <vector>
#include <thread>
#include <chrono>
#include <random>

using namespace ecliptix::protocol::security;
using namespace ecliptix::protocol;

TEST_CASE("Replay Attacks - Classic Replay Detection", "[attacks][replay][critical]") {

    SECTION("Exact replay of same nonce and index must fail") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        constexpr uint64_t message_index = 42;
        const uint64_t chain_index = 0;

        auto first_result = replay_guard.CheckAndRecordMessage(nonce, message_index, chain_index);
        REQUIRE(first_result.IsOk());

        auto replay_result = replay_guard.CheckAndRecordMessage(nonce, message_index, chain_index);
        REQUIRE(replay_result.IsErr());

        auto err = std::move(replay_result).UnwrapErr();
        REQUIRE(err.type == EcliptixProtocolFailureType::Generic);
    }

    SECTION("Replay with different index but same nonce must fail") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        auto result1 = replay_guard.CheckAndRecordMessage(nonce, 10, 0);
        REQUIRE(result1.IsOk());

        auto result2 = replay_guard.CheckAndRecordMessage(nonce, 20, 0);
        REQUIRE(result2.IsErr());
    }

    SECTION("100 sequential messages cannot be replayed") {
        ReplayProtection replay_guard;

        std::vector<std::vector<uint8_t>> nonces;
        nonces.reserve(100);

        for (uint64_t i = 0; i < 100; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            auto result = replay_guard.CheckAndRecordMessage(nonce, i, 0);
            REQUIRE(result.IsOk());

            nonces.push_back(nonce);
        }

        for (uint64_t i = 0; i < 100; ++i) {
            auto replay_result = replay_guard.CheckAndRecordMessage(nonces[i], i, 0);
            REQUIRE(replay_result.IsErr());
        }
    }

    SECTION("Random replay attempts all fail") {
        ReplayProtection replay_guard;

        std::vector<std::vector<uint8_t>> legitimate_nonces;
        std::vector<uint64_t> legitimate_indices;

        std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> dist(0, 10000);

        for (int i = 0; i < 50; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            const uint64_t index = dist(rng);

            auto result = replay_guard.CheckAndRecordMessage(nonce, index, 0);
            if (result.IsOk()) {
                legitimate_nonces.push_back(nonce);
                legitimate_indices.push_back(index);
            }
        }

        for (size_t i = 0; i < legitimate_nonces.size(); ++i) {
            auto replay_result = replay_guard.CheckAndRecordMessage(
                legitimate_nonces[i], legitimate_indices[i], 0);
            REQUIRE(replay_result.IsErr());
        }
    }
}

TEST_CASE("Replay Attacks - Delayed Replay", "[attacks][replay][timing]") {

    SECTION("Nonce cleanup doesn't affect message index tracking") {
        const auto short_lifetime = std::chrono::minutes(0);
        const auto cleanup_interval = std::chrono::minutes(0);

        ReplayProtection replay_guard(1000, cleanup_interval, short_lifetime);

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        auto first_result = replay_guard.CheckAndRecordMessage(nonce, 1, 0);
        REQUIRE(first_result.IsOk());

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        replay_guard.CleanupExpiredNonces();

        auto delayed_replay = replay_guard.CheckAndRecordMessage(nonce, 1, 0);
        REQUIRE(delayed_replay.IsErr());
    }

    SECTION("Replay within lifetime window succeeds for new index") {
        const auto long_lifetime = std::chrono::minutes(60);

        ReplayProtection replay_guard(1000, std::chrono::minutes(10), long_lifetime);

        std::vector<uint8_t> nonce1(Constants::AES_GCM_NONCE_SIZE);
        std::vector<uint8_t> nonce2(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce1.data(), nonce1.size());
        randombytes_buf(nonce2.data(), nonce2.size());

        auto result1 = replay_guard.CheckAndRecordMessage(nonce1, 1, 0);
        REQUIRE(result1.IsOk());

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        auto result2 = replay_guard.CheckAndRecordMessage(nonce2, 2, 0);
        REQUIRE(result2.IsOk());

        auto replay1 = replay_guard.CheckAndRecordMessage(nonce1, 1, 0);
        REQUIRE(replay1.IsErr());
    }

    SECTION("Multiple delayed replays all fail") {
        ReplayProtection replay_guard;

        std::vector<std::vector<uint8_t>> nonces;
        for (int i = 0; i < 20; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            auto result = replay_guard.CheckAndRecordMessage(nonce, i, 0);
            REQUIRE(result.IsOk());

            nonces.push_back(nonce);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        for (size_t i = 0; i < nonces.size(); ++i) {
            auto replay_result = replay_guard.CheckAndRecordMessage(nonces[i], i, 0);
            REQUIRE(replay_result.IsErr());
        }
    }
}

TEST_CASE("Replay Attacks - Cross-Chain Replay", "[attacks][replay][chains]") {

    SECTION("Same nonce different chains is allowed") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        auto chain0_result = replay_guard.CheckAndRecordMessage(nonce, 1, 0);
        REQUIRE(chain0_result.IsOk());

        auto chain1_result = replay_guard.CheckAndRecordMessage(nonce, 1, 1);
        REQUIRE(chain1_result.IsOk());

        auto chain2_result = replay_guard.CheckAndRecordMessage(nonce, 1, 2);
        REQUIRE(chain2_result.IsOk());
    }

    SECTION("Replay within same chain fails") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        auto first = replay_guard.CheckAndRecordMessage(nonce, 5, 10);
        REQUIRE(first.IsOk());

        auto replay = replay_guard.CheckAndRecordMessage(nonce, 5, 10);
        REQUIRE(replay.IsErr());
    }

    SECTION("Cross-chain replay attempts with 100 chains") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        for (uint64_t chain = 0; chain < 100; ++chain) {
            auto result = replay_guard.CheckAndRecordMessage(nonce, 1, chain);
            REQUIRE(result.IsOk());
        }

        for (uint64_t chain = 0; chain < 100; ++chain) {
            auto replay = replay_guard.CheckAndRecordMessage(nonce, 1, chain);
            REQUIRE(replay.IsErr());
        }
    }
}

TEST_CASE("Replay Attacks - Sliding Window Boundary", "[attacks][replay][window]") {

    SECTION("Message outside window (too old) fails") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce_high(Constants::AES_GCM_NONCE_SIZE, 0x01);
        auto result_high = replay_guard.CheckAndRecordMessage(nonce_high, 1000, 0);
        REQUIRE(result_high.IsOk());

        const uint32_t window_size = replay_guard.GetWindowSize(0);

        const uint64_t too_old_index = 1000 - window_size - 1;
        std::vector<uint8_t> nonce_old(Constants::AES_GCM_NONCE_SIZE, 0x02);
        auto result_old = replay_guard.CheckAndRecordMessage(nonce_old, too_old_index, 0);
        REQUIRE(result_old.IsErr());
    }

    SECTION("Message at window boundary succeeds") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce_high(Constants::AES_GCM_NONCE_SIZE, 0x01);
        auto result_high = replay_guard.CheckAndRecordMessage(nonce_high, 1000, 0);
        REQUIRE(result_high.IsOk());

        const uint32_t window_size = replay_guard.GetWindowSize(0);

        const uint64_t boundary_index = 1000 - window_size + 1;
        std::vector<uint8_t> boundary_nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(boundary_nonce.data(), boundary_nonce.size());

        auto result_boundary = replay_guard.CheckAndRecordMessage(boundary_nonce, boundary_index, 0);
        REQUIRE(result_boundary.IsOk());
    }

    SECTION("Fill entire window then attempt replay") {
        ReplayProtection replay_guard(100, std::chrono::minutes(10), std::chrono::minutes(60));

        const uint32_t window_size = 100;

        for (uint64_t i = 0; i < window_size; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            auto result = replay_guard.CheckAndRecordMessage(nonce, i, 0);
            REQUIRE(result.IsOk());
        }

        std::vector<uint8_t> replay_nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(replay_nonce.data(), replay_nonce.size());

        auto first = replay_guard.CheckAndRecordMessage(replay_nonce, 50, 0);
        REQUIRE(first.IsErr());
    }

    SECTION("Window slides forward as messages arrive") {
        ReplayProtection replay_guard(100, std::chrono::minutes(10), std::chrono::minutes(60));

        for (uint64_t i = 0; i < 200; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            auto result = replay_guard.CheckAndRecordMessage(nonce, i, 0);
            REQUIRE(result.IsOk());
        }

        std::vector<uint8_t> old_nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(old_nonce.data(), old_nonce.size());

        auto old_result = replay_guard.CheckAndRecordMessage(old_nonce, 50, 0);
        REQUIRE(old_result.IsErr());
    }
}

TEST_CASE("Replay Attacks - Concurrent Replay", "[attacks][replay][concurrency]") {

    SECTION("100 threads attempting same replay") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        auto first_result = replay_guard.CheckAndRecordMessage(nonce, 1, 0);
        REQUIRE(first_result.IsOk());

        std::atomic<int> failed_count{0};
        std::vector<std::thread> threads;

        for (int i = 0; i < 100; ++i) {
            threads.emplace_back([&replay_guard, &nonce, &failed_count]() {
                auto result = replay_guard.CheckAndRecordMessage(nonce, 1, 0);
                if (result.IsErr()) {
                    failed_count.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        REQUIRE(failed_count.load() == 100);
    }

    SECTION("Concurrent different messages all succeed") {
        ReplayProtection replay_guard;

        std::atomic<int> success_count{0};
        std::vector<std::thread> threads;

        for (int i = 0; i < 100; ++i) {
            threads.emplace_back([&replay_guard, &success_count, i]() {
                std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
                randombytes_buf(nonce.data(), nonce.size());

                auto result = replay_guard.CheckAndRecordMessage(nonce, i, 0);
                if (result.IsOk()) {
                    success_count.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        REQUIRE(success_count.load() == 100);
    }

    SECTION("Race condition on same index different nonces") {
        ReplayProtection replay_guard;

        std::atomic<int> success_count{0};
        std::vector<std::thread> threads;

        for (int i = 0; i < 50; ++i) {
            threads.emplace_back([&replay_guard, &success_count]() {
                std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
                randombytes_buf(nonce.data(), nonce.size());

                auto result = replay_guard.CheckAndRecordMessage(nonce, 42, 0);
                if (result.IsOk()) {
                    success_count.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        REQUIRE(success_count.load() == 1);
    }
}

TEST_CASE("Replay Attacks - Nonce Collision Attempts", "[attacks][replay][collision]") {

    SECTION("Birthday attack simulation - detect duplicates") {
        ReplayProtection replay_guard;

        constexpr size_t num_nonces = 10000;
        std::vector<std::vector<uint8_t>> nonces;
        nonces.reserve(num_nonces);

        for (size_t i = 0; i < num_nonces; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            nonces.push_back(nonce);

            auto result = replay_guard.CheckAndRecordMessage(nonce, i, 0);
            REQUIRE(result.IsOk());
        }

        for (size_t i = 0; i < nonces.size(); ++i) {
            auto replay = replay_guard.CheckAndRecordMessage(nonces[i], i, 0);
            REQUIRE(replay.IsErr());
        }
    }

    SECTION("Intentional collision detection") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce1(Constants::AES_GCM_NONCE_SIZE, 0xAA);
        std::vector<uint8_t> nonce2 = nonce1;

        auto result1 = replay_guard.CheckAndRecordMessage(nonce1, 1, 0);
        REQUIRE(result1.IsOk());

        auto result2 = replay_guard.CheckAndRecordMessage(nonce2, 2, 0);
        REQUIRE(result2.IsErr());
    }

    SECTION("Prefix collision attempt") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce1(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce1.data(), nonce1.size());

        std::vector<uint8_t> nonce2 = nonce1;
        nonce2.back() ^= 0x01;

        auto result1 = replay_guard.CheckAndRecordMessage(nonce1, 1, 0);
        REQUIRE(result1.IsOk());

        auto result2 = replay_guard.CheckAndRecordMessage(nonce2, 2, 0);
        REQUIRE(result2.IsOk());
    }
}

TEST_CASE("Replay Attacks - Cleanup and Resurrection", "[attacks][replay][cleanup]") {

    SECTION("Nonce table cleanup verified but index still tracked") {
        const auto zero_lifetime = std::chrono::minutes(0);
        ReplayProtection replay_guard(1000, zero_lifetime, zero_lifetime);

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        auto first = replay_guard.CheckAndRecordMessage(nonce, 1, 0);
        REQUIRE(first.IsOk());

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        replay_guard.CleanupExpiredNonces();

        const size_t tracked = replay_guard.GetTrackedNonceCount();
        REQUIRE(tracked == 0);

        auto same_index_attempt = replay_guard.CheckAndRecordMessage(nonce, 1, 0);
        REQUIRE(same_index_attempt.IsErr());

        std::vector<uint8_t> new_nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(new_nonce.data(), new_nonce.size());

        auto new_index = replay_guard.CheckAndRecordMessage(new_nonce, 2, 0);
        REQUIRE(new_index.IsOk());
    }

    SECTION("Cleanup preserves recent nonces") {
        const auto long_lifetime = std::chrono::minutes(60);
        ReplayProtection replay_guard(1000, long_lifetime, long_lifetime);

        for (int i = 0; i < 100; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            auto result = replay_guard.CheckAndRecordMessage(nonce, i, 0);
            REQUIRE(result.IsOk());
        }

        const size_t before_cleanup = replay_guard.GetTrackedNonceCount();

        replay_guard.CleanupExpiredNonces();

        const size_t after_cleanup = replay_guard.GetTrackedNonceCount();

        REQUIRE(before_cleanup == after_cleanup);
        REQUIRE(after_cleanup == 100);
    }
}

TEST_CASE("Replay Attacks - Adaptive Window Exploitation", "[attacks][replay][adaptive]") {

    SECTION("Attempting to force window growth") {
        ReplayProtection replay_guard(100, std::chrono::minutes(10), std::chrono::minutes(60));

        const uint32_t initial_window = replay_guard.GetWindowSize(0);

        for (uint64_t i = 0; i < 1000; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            auto result = replay_guard.CheckAndRecordMessage(nonce, i, 0);
            REQUIRE(result.IsOk());
        }

        const uint32_t final_window = replay_guard.GetWindowSize(0);

        REQUIRE(final_window >= initial_window);
    }

    SECTION("Out-of-order messages trigger window adjustment") {
        ReplayProtection replay_guard(100, std::chrono::minutes(10), std::chrono::minutes(60));

        std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> dist(0, 500);

        for (int i = 0; i < 200; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            const uint64_t random_index = dist(rng);

            auto result = replay_guard.CheckAndRecordMessage(nonce, random_index, 0);
        }

        const uint32_t window = replay_guard.GetWindowSize(0);
        REQUIRE(window > 0);
    }
}

TEST_CASE("Replay Attacks - Multi-Session Scenarios", "[attacks][replay][sessions]") {

    SECTION("Reset clears all replay state") {
        ReplayProtection replay_guard;

        std::vector<std::vector<uint8_t>> nonces;
        for (int i = 0; i < 50; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            auto result = replay_guard.CheckAndRecordMessage(nonce, i, 0);
            REQUIRE(result.IsOk());

            nonces.push_back(nonce);
        }

        replay_guard.Reset();

        REQUIRE(replay_guard.GetTrackedNonceCount() == 0);

        for (size_t i = 0; i < nonces.size(); ++i) {
            auto result = replay_guard.CheckAndRecordMessage(nonces[i], i, 0);
            REQUIRE(result.IsOk());
        }
    }

    SECTION("Independent chains maintain separate replay state") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        for (uint64_t chain = 0; chain < 10; ++chain) {
            for (uint64_t index = 0; index < 10; ++index) {
                std::vector<uint8_t> chain_nonce(Constants::AES_GCM_NONCE_SIZE);
                randombytes_buf(chain_nonce.data(), chain_nonce.size());

                auto result = replay_guard.CheckAndRecordMessage(chain_nonce, index, chain);
                REQUIRE(result.IsOk());
            }
        }

        const size_t total_tracked = replay_guard.GetTrackedNonceCount();
        REQUIRE(total_tracked == 100);
    }
}

TEST_CASE("Replay Attacks - Replay After Message Window Reset (DH Ratchet Simulation)", "[attacks][replay][critical][dh_ratchet]") {

    SECTION("Nonces tracked across message window reset") {
        ReplayProtection replay_guard;

        std::vector<std::vector<uint8_t>> nonces_before_reset;

        for (uint64_t i = 0; i < 20; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            auto result = replay_guard.CheckAndRecordMessage(nonce, i, 0);
            REQUIRE(result.IsOk());

            nonces_before_reset.push_back(nonce);
        }

        const size_t nonce_count_before = replay_guard.GetTrackedNonceCount();
        REQUIRE(nonce_count_before == 20);

        replay_guard.ResetMessageWindows();

        const size_t nonce_count_after = replay_guard.GetTrackedNonceCount();
        REQUIRE(nonce_count_after == nonce_count_before);

        for (size_t i = 0; i < nonces_before_reset.size(); ++i) {
            auto replay_result = replay_guard.CheckAndRecordMessage(nonces_before_reset[i], i, 0);
            REQUIRE(replay_result.IsErr());
            REQUIRE(replay_result.UnwrapErr().message.find("Replay attack") != std::string::npos);
        }
    }

    SECTION("New messages with same indices succeed after window reset") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce1(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce1.data(), nonce1.size());

        auto result1 = replay_guard.CheckAndRecordMessage(nonce1, 5, 0);
        REQUIRE(result1.IsOk());

        replay_guard.ResetMessageWindows();

        std::vector<uint8_t> nonce2(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce2.data(), nonce2.size());

        auto result2 = replay_guard.CheckAndRecordMessage(nonce2, 5, 0);
        REQUIRE(result2.IsOk());

        auto replay1 = replay_guard.CheckAndRecordMessage(nonce1, 5, 0);
        REQUIRE(replay1.IsErr());

        auto replay2 = replay_guard.CheckAndRecordMessage(nonce2, 5, 0);
        REQUIRE(replay2.IsErr());
    }

    SECTION("100 messages tracked, window reset, replay all fails") {
        ReplayProtection replay_guard;

        std::vector<std::vector<uint8_t>> captured_nonces;
        captured_nonces.reserve(100);

        for (uint64_t i = 0; i < 100; ++i) {
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
            randombytes_buf(nonce.data(), nonce.size());

            auto result = replay_guard.CheckAndRecordMessage(nonce, i, 0);
            REQUIRE(result.IsOk());

            captured_nonces.push_back(nonce);
        }

        replay_guard.ResetMessageWindows();

        for (uint64_t i = 0; i < 100; ++i) {
            auto replay_result = replay_guard.CheckAndRecordMessage(captured_nonces[i], i, 0);
            REQUIRE(replay_result.IsErr());
        }
    }

    SECTION("Multi-chain - window reset only affects specified chains") {
        ReplayProtection replay_guard;

        std::vector<uint8_t> nonce_chain0(Constants::AES_GCM_NONCE_SIZE, 0x01);
        std::vector<uint8_t> nonce_chain1(Constants::AES_GCM_NONCE_SIZE, 0x02);

        auto result1 = replay_guard.CheckAndRecordMessage(nonce_chain0, 10, 0);
        auto result2 = replay_guard.CheckAndRecordMessage(nonce_chain1, 10, 1);
        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());

        replay_guard.ResetMessageWindows();

        auto replay1 = replay_guard.CheckAndRecordMessage(nonce_chain0, 10, 0);
        auto replay2 = replay_guard.CheckAndRecordMessage(nonce_chain1, 10, 1);
        REQUIRE(replay1.IsErr());
        REQUIRE(replay2.IsErr());
    }
}
