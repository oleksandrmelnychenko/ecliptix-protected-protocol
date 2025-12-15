#include <catch2/catch_test_macros.hpp>
#include "ecliptix/security/ratcheting/replay_protection.hpp"
#include "ecliptix/core/constants.hpp"
#include <vector>
#include <array>
#include <thread>
#include <chrono>
using namespace ecliptix::protocol;
using namespace ecliptix::protocol::security;
using namespace std::chrono_literals;
std::vector<uint8_t> CreateNonce(uint64_t value) {
    std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
    for (size_t i = 0; i < sizeof(uint64_t) && i < nonce.size(); ++i) {
        nonce[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }
    return nonce;
}
TEST_CASE("ReplayProtection - Basic message acceptance", "[replay_protection][security]") {
    ReplayProtection protection;
    SECTION("First message is always accepted") {
        auto nonce = CreateNonce(1);
        auto result = protection.CheckAndRecordMessage(nonce, 0, 0);
        REQUIRE(result.IsOk());
    }
    SECTION("Sequential messages are accepted") {
        for (uint64_t i = 0; i < 10; ++i) {
            auto nonce = CreateNonce(i);
            auto result = protection.CheckAndRecordMessage(nonce, i, 0);
            REQUIRE(result.IsOk());
        }
    }
    SECTION("Different chains don't interfere") {
        auto nonce1 = CreateNonce(1);
        auto nonce2 = CreateNonce(2);
        auto result1 = protection.CheckAndRecordMessage(nonce1, 0, 0);
        auto result2 = protection.CheckAndRecordMessage(nonce2, 0, 1);
        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());
    }
}
TEST_CASE("ReplayProtection - Nonce deduplication", "[replay_protection][security]") {
    ReplayProtection protection;
    SECTION("Exact replay is rejected") {
        auto nonce = CreateNonce(1);
        auto result1 = protection.CheckAndRecordMessage(nonce, 0, 0);
        REQUIRE(result1.IsOk());
        auto result2 = protection.CheckAndRecordMessage(nonce, 1, 0);
        REQUIRE(result2.IsErr());
        REQUIRE(result2.UnwrapErr().message.find("Replay attack") != std::string::npos);
    }
    SECTION("Same nonce on different chains is allowed") {
        auto nonce = CreateNonce(1);
        auto result1 = protection.CheckAndRecordMessage(nonce, 0, 0);
        auto result2 = protection.CheckAndRecordMessage(nonce, 0, 1);
        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());
    }
    SECTION("Different nonces are independent") {
        auto nonce1 = CreateNonce(1);
        auto nonce2 = CreateNonce(2);
        auto result1 = protection.CheckAndRecordMessage(nonce1, 0, 0);
        auto result2 = protection.CheckAndRecordMessage(nonce2, 1, 0);
        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());
    }
}
TEST_CASE("ReplayProtection - Message window validation", "[replay_protection][security]") {
    ReplayProtection protection(100, 1min, 5min); 
    SECTION("Messages within window are accepted") {
        auto nonce1 = CreateNonce(1);
        auto result1 = protection.CheckAndRecordMessage(nonce1, 100, 0);
        REQUIRE(result1.IsOk());
        auto nonce2 = CreateNonce(2);
        auto result2 = protection.CheckAndRecordMessage(nonce2, 50, 0);
        REQUIRE(result2.IsOk());
    }
    SECTION("Messages too far behind are rejected") {
        auto nonce1 = CreateNonce(1);
        auto result1 = protection.CheckAndRecordMessage(nonce1, 200, 0);
        REQUIRE(result1.IsOk());
        auto nonce2 = CreateNonce(2);
        auto result2 = protection.CheckAndRecordMessage(nonce2, 50, 0);
        REQUIRE(result2.IsErr());
        REQUIRE(result2.UnwrapErr().message.find("too old") != std::string::npos);
    }
    SECTION("Messages too far ahead are rejected") {
        auto nonce1 = CreateNonce(1);
        auto result1 = protection.CheckAndRecordMessage(nonce1, 100, 0);
        REQUIRE(result1.IsOk());
        auto nonce2 = CreateNonce(2);
        auto result2 = protection.CheckAndRecordMessage(nonce2, 351, 0);
        REQUIRE(result2.IsErr());
        REQUIRE(result2.UnwrapErr().message.find("too far ahead") != std::string::npos);
    }
    SECTION("Duplicate index in same chain is rejected") {
        auto nonce1 = CreateNonce(1);
        auto nonce2 = CreateNonce(2);
        auto result1 = protection.CheckAndRecordMessage(nonce1, 100, 0);
        REQUIRE(result1.IsOk());
        auto result2 = protection.CheckAndRecordMessage(nonce2, 100, 0);
        REQUIRE(result2.IsErr());
        REQUIRE(result2.UnwrapErr().message.find("already processed") != std::string::npos);
    }
}
TEST_CASE("ReplayProtection - Out-of-order messages", "[replay_protection][security]") {
    ReplayProtection protection(100, 1min, 5min);
    SECTION("Out-of-order messages within window are accepted") {
        std::vector<uint64_t> indices = {10, 5, 15, 3, 20, 8};
        for (size_t i = 0; i < indices.size(); ++i) {
            auto nonce = CreateNonce(i);
            auto result = protection.CheckAndRecordMessage(nonce, indices[i], 0);
            REQUIRE(result.IsOk());
        }
    }
    SECTION("Window slides forward with highest index") {
        auto nonce1 = CreateNonce(1);
        auto result1 = protection.CheckAndRecordMessage(nonce1, 200, 0);
        REQUIRE(result1.IsOk());
        auto nonce2 = CreateNonce(2);
        auto result2 = protection.CheckAndRecordMessage(nonce2, 99, 0);
        REQUIRE(result2.IsErr());
        auto nonce3 = CreateNonce(3);
        auto result3 = protection.CheckAndRecordMessage(nonce3, 100, 0);
        REQUIRE(result3.IsOk());
    }
}
TEST_CASE("ReplayProtection - Cleanup operations", "[replay_protection][security]") {
    ReplayProtection protection(100, 10min, 5min);
    SECTION("Get tracked nonce count") {
        REQUIRE(protection.GetTrackedNonceCount() == 0);
        for (uint64_t i = 0; i < 5; ++i) {
            auto nonce = CreateNonce(i);
            protection.CheckAndRecordMessage(nonce, i, 0);
        }
        REQUIRE(protection.GetTrackedNonceCount() == 5);
    }
    SECTION("Manual cleanup with fresh nonces doesn't remove them") {
        for (uint64_t i = 0; i < 5; ++i) {
            auto nonce = CreateNonce(i);
            protection.CheckAndRecordMessage(nonce, i, 0);
        }
        REQUIRE(protection.GetTrackedNonceCount() == 5);
        protection.CleanupExpiredNonces();
        REQUIRE(protection.GetTrackedNonceCount() == 5);
    }
    SECTION("Reset clears all state") {
        for (uint64_t i = 0; i < 5; ++i) {
            auto nonce = CreateNonce(i);
            protection.CheckAndRecordMessage(nonce, i, 0);
        }
        REQUIRE(protection.GetTrackedNonceCount() == 5);
        protection.Reset();
        REQUIRE(protection.GetTrackedNonceCount() == 0);
        auto nonce = CreateNonce(0);
        auto result = protection.CheckAndRecordMessage(nonce, 0, 0);
        REQUIRE(result.IsOk());
    }
}
TEST_CASE("ReplayProtection - Window sizing", "[replay_protection][security]") {
    ReplayProtection protection(100, 1min, 5min);
    SECTION("Get window size for chain") {
        REQUIRE(protection.GetWindowSize(0) == 100); 
        auto nonce = CreateNonce(1);
        protection.CheckAndRecordMessage(nonce, 0, 0);
        REQUIRE(protection.GetWindowSize(0) == 100);
    }
    SECTION("Different chains have independent windows") {
        auto nonce1 = CreateNonce(1);
        protection.CheckAndRecordMessage(nonce1, 0, 0);
        auto nonce2 = CreateNonce(2);
        protection.CheckAndRecordMessage(nonce2, 0, 1);
        REQUIRE(protection.GetWindowSize(0) == 100);
        REQUIRE(protection.GetWindowSize(1) == 100);
        REQUIRE(protection.GetWindowSize(2) == 100); 
    }
}
TEST_CASE("ReplayProtection - Multiple chains", "[replay_protection][security]") {
    ReplayProtection protection(100, 1min, 5min);
    SECTION("Each chain maintains independent state") {
        for (uint64_t i = 0; i < 5; ++i) {
            auto nonce = CreateNonce(i);
            auto result = protection.CheckAndRecordMessage(nonce, i * 10, 0);
            REQUIRE(result.IsOk());
        }
        for (uint64_t i = 5; i < 10; ++i) {
            auto nonce = CreateNonce(i);
            auto result = protection.CheckAndRecordMessage(nonce, i * 10, 1);
            REQUIRE(result.IsOk());
        }
        auto nonce_chain0 = CreateNonce(100);
        auto result_chain0 = protection.CheckAndRecordMessage(nonce_chain0, 200, 0);
        REQUIRE(result_chain0.IsErr()); 
        auto nonce_chain1 = CreateNonce(101);
        auto result_chain1 = protection.CheckAndRecordMessage(nonce_chain1, 100, 1);
        REQUIRE(result_chain1.IsOk()); 
    }
}
TEST_CASE("ReplayProtection - Edge cases", "[replay_protection][security]") {
    ReplayProtection protection(100, 1min, 5min);
    SECTION("Zero message index is valid") {
        auto nonce = CreateNonce(1);
        auto result = protection.CheckAndRecordMessage(nonce, 0, 0);
        REQUIRE(result.IsOk());
    }
    SECTION("Invalid nonce sizes are rejected") {
        std::vector<uint8_t> short_nonce(4, 0xAA);
        auto result = protection.CheckAndRecordMessage(short_nonce, 0, 0);
        REQUIRE(result.IsErr());
    }
    SECTION("Large message indices") {
        auto nonce = CreateNonce(1);
        uint64_t large_index = 1'000'000'000;
        auto result = protection.CheckAndRecordMessage(nonce, large_index, 0);
        REQUIRE(result.IsOk());
    }
    SECTION("Empty nonce is handled") {
        std::vector<uint8_t> empty_nonce;
        auto result = protection.CheckAndRecordMessage(empty_nonce, 0, 0);
        REQUIRE(result.IsErr());
    }
    SECTION("Large chain indices") {
        auto nonce = CreateNonce(1);
        uint64_t large_chain = 1'000'000;
        auto result = protection.CheckAndRecordMessage(nonce, 0, large_chain);
        REQUIRE(result.IsErr());
    }
    SECTION("Capacity limits are enforced") {
        ReplayProtection small_limits(10, 1min, 5min, 2, 1);
        auto n1 = CreateNonce(1);
        auto n2 = CreateNonce(2);
        auto res1 = small_limits.CheckAndRecordMessage(n1, 0, 0);
        REQUIRE(res1.IsOk());
        auto res2 = small_limits.CheckAndRecordMessage(n2, 1, 0);
        REQUIRE(res2.IsOk());
        auto n3 = CreateNonce(3);
        auto res3 = small_limits.CheckAndRecordMessage(n3, 2, 0);
        REQUIRE(res3.IsOk());
        // Oldest nonce should have been evicted to keep cache bounded
        REQUIRE(small_limits.GetTrackedNonceCount() <= 2);
    }
}
