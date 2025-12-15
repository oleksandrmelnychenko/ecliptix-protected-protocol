#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include <chrono>
#include <numeric>

using namespace ecliptix::protocol::crypto;

TEST_CASE("Crypto Performance Benchmarks", "[benchmark][crypto][performance]") {
    // Initialize libsodium
    auto init_result = SodiumInterop::Initialize();
    REQUIRE(init_result.IsOk());

    SECTION("X25519 Key Generation") {
        BENCHMARK("Generate X25519 key pair") {
            auto result = SodiumInterop::GenerateX25519KeyPair("benchmark");
            return result.IsOk();
        };
    }

    SECTION("Ed25519 Key Generation") {
        BENCHMARK("Generate Ed25519 key pair") {
            auto result = SodiumInterop::GenerateEd25519KeyPair();
            return result.IsOk();
        };
    }

    SECTION("Random Bytes Generation") {
        BENCHMARK("Generate 32 random bytes") {
            return SodiumInterop::GetRandomBytes(32);
        };
    }

    SECTION("Secure Memory Operations") {
        auto handle_result = SecureMemoryHandle::Allocate(32);
        REQUIRE(handle_result.IsOk());
        auto handle = std::move(handle_result).Unwrap();
        std::vector<uint8_t> data(32, 0xAA);

        BENCHMARK("Write to secure memory") {
            auto result = handle.Write(std::span<const uint8_t>(data));
            return result.IsOk();
        };

        BENCHMARK("Read from secure memory") {
            std::vector<uint8_t> output(32);
            auto result = handle.Read(std::span(output));
            return result.IsOk();
        };
    }

    SECTION("Constant-Time Comparison") {
        std::vector<uint8_t> a = SodiumInterop::GetRandomBytes(32);
        std::vector<uint8_t> b = a;

        BENCHMARK("Constant-time equals (32 bytes)") {
            auto result = SodiumInterop::ConstantTimeEquals(std::span(a), std::span(b));
            return result.IsOk();
        };
    }

    SECTION("Secure Wiping") {
        std::vector<uint8_t> buffer(1024);

        BENCHMARK("Secure wipe (1 KB)") {
            std::fill(buffer.begin(), buffer.end(), 0xFF);
            auto result = SodiumInterop::SecureWipe(std::span(buffer));
            return result.IsOk();
        };
    }
}

TEST_CASE("Key Generation Throughput", "[benchmark][crypto][throughput]") {
    auto init_result = SodiumInterop::Initialize();
    REQUIRE(init_result.IsOk());

    SECTION("Batch X25519 Key Generation") {
        constexpr int iterations = 1000;
        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < iterations; ++i) {
            auto result = SodiumInterop::GenerateX25519KeyPair("throughput");
            REQUIRE(result.IsOk());
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double avg_time_us = static_cast<double>(duration.count()) / iterations;
        double ops_per_sec = 1'000'000.0 / avg_time_us;

        INFO("X25519 Key Generation:");
        INFO("  Average time: " << avg_time_us << " µs");
        INFO("  Throughput: " << ops_per_sec << " ops/sec");
        INFO("  Total time: " << duration.count() / 1000.0 << " ms");

        // Performance target: < 100 µs per key pair
        REQUIRE(avg_time_us < 100.0);
    }
}
