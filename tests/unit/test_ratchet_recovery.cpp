#include <catch2/catch_test_macros.hpp>
#include "ecliptix/security/ratcheting/ratchet_recovery.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include <vector>
#include <array>
#include <iostream>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::security;
using namespace ecliptix::protocol::crypto;

// Helper to create a test chain key
std::vector<uint8_t> CreateTestChainKey(uint8_t seed) {
    std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>((seed + i) % 256);
    }
    return key;
}

TEST_CASE("RatchetRecovery - Basic construction", "[ratchet_recovery][security]") {
    // Initialize libsodium
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Default constructor") {
        RatchetRecovery recovery;

        REQUIRE(recovery.GetSkippedKeyCount() == 0);
        REQUIRE(recovery.GetMaxSkippedKeys() == ProtocolConstants::MAX_SKIP_MESSAGE_KEYS);
    }

    SECTION("Custom max skipped keys") {
        RatchetRecovery recovery(500);

        REQUIRE(recovery.GetSkippedKeyCount() == 0);
        REQUIRE(recovery.GetMaxSkippedKeys() == 500);
    }
}

TEST_CASE("RatchetRecovery - Store and retrieve skipped keys", "[ratchet_recovery][security]") {
    // Initialize libsodium
    REQUIRE(SodiumInterop::Initialize().IsOk());

    RatchetRecovery recovery;
    auto chain_key = CreateTestChainKey(42);

    SECTION("Store single key") {
        auto result = recovery.StoreSkippedMessageKeys(chain_key, 10, 11);

        if (result.IsErr()) {
            std::cerr << "Error storing key: " << result.UnwrapErr().message << std::endl;
        }

        REQUIRE(result.IsOk());
        REQUIRE(recovery.GetSkippedKeyCount() == 1);
        REQUIRE(recovery.HasSkippedMessageKey(10));
    }

    SECTION("Store multiple consecutive keys") {
        auto result = recovery.StoreSkippedMessageKeys(chain_key, 10, 15);

        REQUIRE(result.IsOk());
        REQUIRE(recovery.GetSkippedKeyCount() == 5);

        for (uint32_t i = 10; i < 15; ++i) {
            REQUIRE(recovery.HasSkippedMessageKey(i));
        }
    }

    SECTION("Store many keys") {
        auto result = recovery.StoreSkippedMessageKeys(chain_key, 0, 100);

        REQUIRE(result.IsOk());
        REQUIRE(recovery.GetSkippedKeyCount() == 100);
    }

    SECTION("Invalid range (to <= from)") {
        auto result = recovery.StoreSkippedMessageKeys(chain_key, 10, 10);

        REQUIRE(result.IsErr());
        REQUIRE(recovery.GetSkippedKeyCount() == 0);
    }

    SECTION("Invalid range (to < from)") {
        auto result = recovery.StoreSkippedMessageKeys(chain_key, 15, 10);

        REQUIRE(result.IsErr());
        REQUIRE(recovery.GetSkippedKeyCount() == 0);
    }
}

TEST_CASE("RatchetRecovery - Key retrieval", "[ratchet_recovery][security]") {
    // Initialize libsodium
    REQUIRE(SodiumInterop::Initialize().IsOk());

    RatchetRecovery recovery;
    auto chain_key = CreateTestChainKey(123);

    SECTION("Retrieve existing key") {
        // Store keys
        recovery.StoreSkippedMessageKeys(chain_key, 5, 10);

        // Retrieve key at index 7
        auto result = recovery.TryGetSkippedMessageKey(7);

        REQUIRE(result.IsOk());
        REQUIRE(result.Unwrap().has_value());

        auto& key_handle = result.Unwrap().value();
        REQUIRE(key_handle.Size() == Constants::AES_KEY_SIZE);

        // Key should be removed after retrieval
        REQUIRE_FALSE(recovery.HasSkippedMessageKey(7));
        REQUIRE(recovery.GetSkippedKeyCount() == 4); // 5,6,8,9 remain
    }

    SECTION("Retrieve non-existent key") {
        recovery.StoreSkippedMessageKeys(chain_key, 10, 15);

        auto result = recovery.TryGetSkippedMessageKey(20);

        REQUIRE(result.IsOk());
        REQUIRE_FALSE(result.Unwrap().has_value());

        // Count unchanged
        REQUIRE(recovery.GetSkippedKeyCount() == 5);
    }

    SECTION("Multiple retrievals") {
        recovery.StoreSkippedMessageKeys(chain_key, 10, 15);

        // Retrieve all keys
        for (uint32_t i = 10; i < 15; ++i) {
            auto result = recovery.TryGetSkippedMessageKey(i);
            REQUIRE(result.IsOk());
            REQUIRE(result.Unwrap().has_value());
        }

        REQUIRE(recovery.GetSkippedKeyCount() == 0);
    }
}

TEST_CASE("RatchetRecovery - Key uniqueness", "[ratchet_recovery][security]") {
    // Initialize libsodium
    REQUIRE(SodiumInterop::Initialize().IsOk());

    RatchetRecovery recovery;
    auto chain_key = CreateTestChainKey(99);

    SECTION("Each skipped key is unique") {
        recovery.StoreSkippedMessageKeys(chain_key, 0, 3);

        // Retrieve all keys and verify they're different
        auto key0_result = recovery.TryGetSkippedMessageKey(0);
        auto key1_result = recovery.TryGetSkippedMessageKey(1);
        auto key2_result = recovery.TryGetSkippedMessageKey(2);

        REQUIRE(key0_result.IsOk());
        REQUIRE(key1_result.IsOk());
        REQUIRE(key2_result.IsOk());

        auto key0 = std::move(key0_result.Unwrap().value());
        auto key1 = std::move(key1_result.Unwrap().value());
        auto key2 = std::move(key2_result.Unwrap().value());

        // Read keys into vectors for comparison
        auto bytes0_result = key0.ReadBytes(Constants::AES_KEY_SIZE);
        auto bytes1_result = key1.ReadBytes(Constants::AES_KEY_SIZE);
        auto bytes2_result = key2.ReadBytes(Constants::AES_KEY_SIZE);

        REQUIRE(bytes0_result.IsOk());
        REQUIRE(bytes1_result.IsOk());
        REQUIRE(bytes2_result.IsOk());

        auto bytes0 = bytes0_result.Unwrap();
        auto bytes1 = bytes1_result.Unwrap();
        auto bytes2 = bytes2_result.Unwrap();

        // Keys should be different
        REQUIRE(bytes0 != bytes1);
        REQUIRE(bytes1 != bytes2);
        REQUIRE(bytes0 != bytes2);
    }
}

TEST_CASE("RatchetRecovery - Max limit enforcement", "[ratchet_recovery][security]") {
    // Initialize libsodium
    REQUIRE(SodiumInterop::Initialize().IsOk());

    RatchetRecovery recovery(100); // Max 100 keys
    auto chain_key = CreateTestChainKey(55);

    SECTION("Store up to limit") {
        auto result = recovery.StoreSkippedMessageKeys(chain_key, 0, 100);

        REQUIRE(result.IsOk());
        REQUIRE(recovery.GetSkippedKeyCount() == 100);
    }

    SECTION("Exceed limit is rejected") {
        // First store 80 keys
        recovery.StoreSkippedMessageKeys(chain_key, 0, 80);
        REQUIRE(recovery.GetSkippedKeyCount() == 80);

        // Try to store 30 more (would exceed 100)
        auto result = recovery.StoreSkippedMessageKeys(chain_key, 100, 130);

        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr().message.find("maximum limit") != std::string::npos);

        // Original 80 should still be there
        REQUIRE(recovery.GetSkippedKeyCount() == 80);
    }

    SECTION("Exactly at limit") {
        auto result = recovery.StoreSkippedMessageKeys(chain_key, 0, 100);
        REQUIRE(result.IsOk());

        // Try to add one more
        auto result2 = recovery.StoreSkippedMessageKeys(chain_key, 100, 101);
        REQUIRE(result2.IsErr());
    }
}

TEST_CASE("RatchetRecovery - Cleanup operations", "[ratchet_recovery][security]") {
    // Initialize libsodium
    REQUIRE(SodiumInterop::Initialize().IsOk());

    RatchetRecovery recovery;
    auto chain_key = CreateTestChainKey(77);

    SECTION("Cleanup old keys") {
        // Store keys 10-20
        recovery.StoreSkippedMessageKeys(chain_key, 10, 20);
        REQUIRE(recovery.GetSkippedKeyCount() == 10);

        // Cleanup everything below index 15
        recovery.CleanupOldKeys(15);

        REQUIRE(recovery.GetSkippedKeyCount() == 5); // 15,16,17,18,19 remain

        // Verify correct keys remain
        for (uint32_t i = 10; i < 15; ++i) {
            REQUIRE_FALSE(recovery.HasSkippedMessageKey(i));
        }
        for (uint32_t i = 15; i < 20; ++i) {
            REQUIRE(recovery.HasSkippedMessageKey(i));
        }
    }

    SECTION("Cleanup all keys") {
        recovery.StoreSkippedMessageKeys(chain_key, 10, 20);

        recovery.CleanupOldKeys(100); // Cleanup everything

        REQUIRE(recovery.GetSkippedKeyCount() == 0);
    }

    SECTION("Cleanup with no keys") {
        recovery.CleanupOldKeys(50);
        REQUIRE(recovery.GetSkippedKeyCount() == 0);
    }

    SECTION("Cleanup boundary") {
        recovery.StoreSkippedMessageKeys(chain_key, 10, 20);

        // Cleanup below 10 (nothing should be removed)
        recovery.CleanupOldKeys(10);
        REQUIRE(recovery.GetSkippedKeyCount() == 10);

        // Cleanup below 11 (index 10 should be removed)
        recovery.CleanupOldKeys(11);
        REQUIRE(recovery.GetSkippedKeyCount() == 9);
        REQUIRE_FALSE(recovery.HasSkippedMessageKey(10));
        REQUIRE(recovery.HasSkippedMessageKey(11));
    }
}

TEST_CASE("RatchetRecovery - Reset", "[ratchet_recovery][security]") {
    // Initialize libsodium
    REQUIRE(SodiumInterop::Initialize().IsOk());

    RatchetRecovery recovery;
    auto chain_key = CreateTestChainKey(88);

    SECTION("Reset clears all keys") {
        recovery.StoreSkippedMessageKeys(chain_key, 0, 50);
        REQUIRE(recovery.GetSkippedKeyCount() == 50);

        recovery.Reset();

        REQUIRE(recovery.GetSkippedKeyCount() == 0);
        for (uint32_t i = 0; i < 50; ++i) {
            REQUIRE_FALSE(recovery.HasSkippedMessageKey(i));
        }
    }

    SECTION("Reset empty recovery") {
        recovery.Reset();
        REQUIRE(recovery.GetSkippedKeyCount() == 0);
    }

    SECTION("Use after reset") {
        recovery.StoreSkippedMessageKeys(chain_key, 0, 10);
        recovery.Reset();

        // Should be able to store again
        auto result = recovery.StoreSkippedMessageKeys(chain_key, 0, 5);
        REQUIRE(result.IsOk());
        REQUIRE(recovery.GetSkippedKeyCount() == 5);
    }
}

TEST_CASE("RatchetRecovery - Out-of-order message simulation", "[ratchet_recovery][security]") {
    // Initialize libsodium
    REQUIRE(SodiumInterop::Initialize().IsOk());

    RatchetRecovery recovery;
    auto chain_key = CreateTestChainKey(200);

    SECTION("Typical out-of-order scenario") {
        // Receive message 5, need to skip 0-4
        recovery.StoreSkippedMessageKeys(chain_key, 0, 5);

        // Later receive message 2
        auto key2_result = recovery.TryGetSkippedMessageKey(2);
        REQUIRE(key2_result.IsOk());
        REQUIRE(key2_result.Unwrap().has_value());

        // Message 2 can be decrypted with the recovered key
        auto key2 = std::move(key2_result.Unwrap().value());
        REQUIRE(key2.Size() == Constants::AES_KEY_SIZE);

        // Keys 0,1,3,4 should still be available
        REQUIRE(recovery.HasSkippedMessageKey(0));
        REQUIRE(recovery.HasSkippedMessageKey(1));
        REQUIRE_FALSE(recovery.HasSkippedMessageKey(2)); // Retrieved
        REQUIRE(recovery.HasSkippedMessageKey(3));
        REQUIRE(recovery.HasSkippedMessageKey(4));
    }

    SECTION("Multiple gaps") {
        // Skip 10-15
        recovery.StoreSkippedMessageKeys(chain_key, 10, 15);

        // Skip 20-25 (different chain key for simulation)
        auto chain_key2 = CreateTestChainKey(201);
        recovery.StoreSkippedMessageKeys(chain_key2, 20, 25);

        REQUIRE(recovery.GetSkippedKeyCount() == 10);

        // Retrieve from first gap
        auto key12 = recovery.TryGetSkippedMessageKey(12);
        REQUIRE(key12.IsOk());
        REQUIRE(key12.Unwrap().has_value());

        // Retrieve from second gap
        auto key22 = recovery.TryGetSkippedMessageKey(22);
        REQUIRE(key22.IsOk());
        REQUIRE(key22.Unwrap().has_value());

        REQUIRE(recovery.GetSkippedKeyCount() == 8);
    }
}

TEST_CASE("RatchetRecovery - Edge cases", "[ratchet_recovery][security]") {
    // Initialize libsodium
    REQUIRE(SodiumInterop::Initialize().IsOk());

    RatchetRecovery recovery;
    auto chain_key = CreateTestChainKey(111);

    SECTION("Index zero") {
        auto result = recovery.StoreSkippedMessageKeys(chain_key, 0, 1);
        REQUIRE(result.IsOk());
        REQUIRE(recovery.HasSkippedMessageKey(0));
    }

    SECTION("Large indices") {
        uint32_t large_index = 1000000;
        auto result = recovery.StoreSkippedMessageKeys(chain_key, large_index, large_index + 5);

        REQUIRE(result.IsOk());
        REQUIRE(recovery.GetSkippedKeyCount() == 5);
        REQUIRE(recovery.HasSkippedMessageKey(large_index));
    }

    SECTION("Single key ranges") {
        for (uint32_t i = 0; i < 10; ++i) {
            auto result = recovery.StoreSkippedMessageKeys(chain_key, i * 10, i * 10 + 1);
            REQUIRE(result.IsOk());
        }

        REQUIRE(recovery.GetSkippedKeyCount() == 10);
    }

    SECTION("Non-contiguous storage") {
        recovery.StoreSkippedMessageKeys(chain_key, 10, 15);
        recovery.StoreSkippedMessageKeys(chain_key, 20, 25);
        recovery.StoreSkippedMessageKeys(chain_key, 30, 35);

        REQUIRE(recovery.GetSkippedKeyCount() == 15);

        // Check gaps
        REQUIRE_FALSE(recovery.HasSkippedMessageKey(5));
        REQUIRE_FALSE(recovery.HasSkippedMessageKey(17));
        REQUIRE_FALSE(recovery.HasSkippedMessageKey(27));
    }
}

TEST_CASE("RatchetRecovery - Memory management", "[ratchet_recovery][security]") {
    // Initialize libsodium
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Keys are properly freed") {
        {
            RatchetRecovery recovery;
            auto chain_key = CreateTestChainKey(250);

            // Store many keys
            recovery.StoreSkippedMessageKeys(chain_key, 0, 100);
            REQUIRE(recovery.GetSkippedKeyCount() == 100);

            // recovery destructor should clean up all keys
        }
        // If this doesn't crash, memory management is working
        REQUIRE(true);
    }

    SECTION("Retrieved keys are independent") {
        RatchetRecovery recovery;
        auto chain_key = CreateTestChainKey(251);

        recovery.StoreSkippedMessageKeys(chain_key, 0, 5);

        auto key1_result = recovery.TryGetSkippedMessageKey(1);
        auto key1 = std::move(key1_result.Unwrap().value());

        // Original recovery should not have key 1 anymore
        REQUIRE_FALSE(recovery.HasSkippedMessageKey(1));

        // key1 handle should still be valid and usable
        auto bytes_result = key1.ReadBytes(Constants::AES_KEY_SIZE);
        REQUIRE(bytes_result.IsOk());
    }
}
