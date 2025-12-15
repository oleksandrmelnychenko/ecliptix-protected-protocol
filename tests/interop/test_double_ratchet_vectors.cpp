#include <catch2/catch_test_macros.hpp>
#include "helpers/mock_key_provider.hpp"
#include "ecliptix/models/keys/ratchet_chain_key.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include <vector>
#include <map>
#include <algorithm>
#include <random>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::test_helpers;
using namespace ecliptix::protocol::models;
using namespace ecliptix::protocol::crypto;

struct DoubleRatchetTestVector {
    std::vector<uint8_t> initial_chain_key;
    std::map<uint32_t, std::vector<uint8_t>> message_keys;

    [[nodiscard]] static DoubleRatchetTestVector Generate(uint32_t key_count) {
        DoubleRatchetTestVector vec;

        vec.initial_chain_key.resize(Constants::X_25519_KEY_SIZE);
        for (size_t i = 0; i < vec.initial_chain_key.size(); ++i) {
            vec.initial_chain_key[i] = static_cast<uint8_t>(i + 1);
        }

        std::vector<uint8_t> current_chain_key = vec.initial_chain_key;

        for (uint32_t i = 0; i < key_count; ++i) {
            std::vector<uint8_t> message_key(Constants::AES_KEY_SIZE);
            std::vector<uint8_t> next_chain_key(Constants::X_25519_KEY_SIZE);

            const std::vector<uint8_t> message_info(
                Constants::MSG_INFO.begin(),
                Constants::MSG_INFO.end()
            );

            auto message_hkdf_result = Hkdf::DeriveKey(
                current_chain_key,
                message_key,
                {},
                message_info
            );
            REQUIRE(message_hkdf_result.IsOk());

            vec.message_keys[i] = message_key;

            const std::vector<uint8_t> chain_info(
                Constants::CHAIN_INFO.begin(),
                Constants::CHAIN_INFO.end()
            );

            auto chain_hkdf_result = Hkdf::DeriveKey(
                current_chain_key,
                next_chain_key,
                {},
                chain_info
            );
            REQUIRE(chain_hkdf_result.IsOk());

            current_chain_key = next_chain_key;
        }

        return vec;
    }
};

TEST_CASE("Double Ratchet - Sequential Message Keys", "[interop][double-ratchet][sequential]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Generate and use 10,000 sequential message keys") {
        constexpr uint32_t MESSAGE_COUNT = 10'000;

        auto test_vec = DoubleRatchetTestVector::Generate(MESSAGE_COUNT);

        MockKeyProvider mock;
        for (const auto& [index, key] : test_vec.message_keys) {
            mock.SetKey(index, key);
        }

        REQUIRE(mock.KeyCount() == MESSAGE_COUNT);

        uint32_t successful_encryptions = 0;
        uint32_t successful_decryptions = 0;

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            RatchetChainKey chain_key(&mock, i);

            REQUIRE(chain_key.Index() == i);

            const std::vector<uint8_t> plaintext{
                0xDE, 0xAD, 0xBE, 0xEF,
                static_cast<uint8_t>(i & 0xFF),
                static_cast<uint8_t>((i >> 8) & 0xFF)
            };

            std::vector<uint8_t> nonce(12, static_cast<uint8_t>(i & 0xFF));

            auto encrypted_result = chain_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, plaintext, {});
                }
            );

            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();
            ++successful_encryptions;

            auto decrypted_result = chain_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, nonce, encrypted, {});
                }
            );

            REQUIRE(decrypted_result.IsOk());
            auto decrypted = std::move(decrypted_result).Unwrap();
            REQUIRE(decrypted == plaintext);
            ++successful_decryptions;
        }

        REQUIRE(successful_encryptions == MESSAGE_COUNT);
        REQUIRE(successful_decryptions == MESSAGE_COUNT);
    }
}

TEST_CASE("Double Ratchet - Out-of-Order Message Processing", "[interop][double-ratchet][out-of-order]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Process 1000 messages in random order") {
        constexpr uint32_t MESSAGE_COUNT = 1000;

        auto test_vec = DoubleRatchetTestVector::Generate(MESSAGE_COUNT);

        MockKeyProvider sender_mock;
        for (const auto& [index, key] : test_vec.message_keys) {
            sender_mock.SetKey(index, key);
        }

        struct EncryptedMessage {
            uint32_t index;
            std::vector<uint8_t> nonce;
            std::vector<uint8_t> ciphertext;
            std::vector<uint8_t> expected_plaintext;
        };

        std::vector<EncryptedMessage> messages;
        messages.reserve(MESSAGE_COUNT);

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            RatchetChainKey chain_key(&sender_mock, i);

            const std::vector<uint8_t> plaintext{
                0xCA, 0xFE, 0xBA, 0xBE,
                static_cast<uint8_t>(i & 0xFF),
                static_cast<uint8_t>((i >> 8) & 0xFF)
            };

            std::vector<uint8_t> nonce(12, static_cast<uint8_t>((i * 3) & 0xFF));

            auto encrypted_result = chain_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, plaintext, {});
                }
            );

            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            messages.push_back(EncryptedMessage{
                i,
                nonce,
                encrypted,
                plaintext
            });
        }

        std::random_device rd;
        std::mt19937 gen(42);
        std::shuffle(messages.begin(), messages.end(), gen);

        MockKeyProvider receiver_mock;
        for (const auto& [index, key] : test_vec.message_keys) {
            receiver_mock.SetKey(index, key);
        }

        uint32_t successful_decryptions = 0;

        for (const auto& msg : messages) {
            RatchetChainKey chain_key(&receiver_mock, msg.index);

            auto decrypted_result = chain_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, msg.nonce, msg.ciphertext, {});
                }
            );

            REQUIRE(decrypted_result.IsOk());
            auto decrypted = std::move(decrypted_result).Unwrap();
            REQUIRE(decrypted == msg.expected_plaintext);
            ++successful_decryptions;
        }

        REQUIRE(successful_decryptions == MESSAGE_COUNT);
    }
}

TEST_CASE("Double Ratchet - Skip Messages Scenario", "[interop][double-ratchet][skip]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Skip first 100,000 messages and process message 100,000") {
        constexpr uint32_t SKIP_COUNT = 100'000;
        constexpr uint32_t TARGET_INDEX = 100'000;

        auto test_vec = DoubleRatchetTestVector::Generate(TARGET_INDEX + 1);

        MockKeyProvider mock;
        for (const auto& [index, key] : test_vec.message_keys) {
            if (index >= SKIP_COUNT) {
                mock.SetKey(index, key);
            }
        }

        RatchetChainKey target_key(&mock, TARGET_INDEX);

        const std::vector<uint8_t> plaintext{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
        std::vector<uint8_t> nonce(12, 0x42);

        auto encrypted_result = target_key.WithKeyMaterial<std::vector<uint8_t>>(
            [&](std::span<const uint8_t> key) {
                return AesGcm::Encrypt(key, nonce, plaintext, {});
            }
        );

        REQUIRE(encrypted_result.IsOk());
        auto encrypted = std::move(encrypted_result).Unwrap();

        auto decrypted_result = target_key.WithKeyMaterial<std::vector<uint8_t>>(
            [&](std::span<const uint8_t> key) {
                return AesGcm::Decrypt(key, nonce, encrypted, {});
            }
        );

        REQUIRE(decrypted_result.IsOk());
        auto decrypted = std::move(decrypted_result).Unwrap();
        REQUIRE(decrypted == plaintext);
    }

    SECTION("Process sparse messages: 0, 1000, 2000, 3000, ..., 10000") {
        constexpr uint32_t MAX_INDEX = 10'000;
        constexpr uint32_t STEP = 1000;

        auto test_vec = DoubleRatchetTestVector::Generate(MAX_INDEX + 1);

        MockKeyProvider mock;
        for (uint32_t i = 0; i <= MAX_INDEX; i += STEP) {
            if (test_vec.message_keys.count(i) > 0) {
                mock.SetKey(i, test_vec.message_keys[i]);
            }
        }

        uint32_t processed_messages = 0;

        for (uint32_t i = 0; i <= MAX_INDEX; i += STEP) {
            if (!mock.HasKey(i)) {
                continue;
            }

            RatchetChainKey chain_key(&mock, i);

            const std::vector<uint8_t> plaintext{
                0x12, 0x34,
                static_cast<uint8_t>(i & 0xFF),
                static_cast<uint8_t>((i >> 8) & 0xFF)
            };

            std::vector<uint8_t> nonce(12, static_cast<uint8_t>(i & 0xFF));

            auto encrypted_result = chain_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, plaintext, {});
                }
            );

            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            auto decrypted_result = chain_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, nonce, encrypted, {});
                }
            );

            REQUIRE(decrypted_result.IsOk());
            auto decrypted = std::move(decrypted_result).Unwrap();
            REQUIRE(decrypted == plaintext);

            ++processed_messages;
        }

        REQUIRE(processed_messages == (MAX_INDEX / STEP + 1));
    }
}

TEST_CASE("Double Ratchet - Bidirectional Communication", "[interop][double-ratchet][bidirectional]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Alternate between Alice and Bob for 5000 round-trips") {
        constexpr uint32_t ROUND_TRIPS = 5000;

        auto alice_vec = DoubleRatchetTestVector::Generate(ROUND_TRIPS);
        auto bob_vec = DoubleRatchetTestVector::Generate(ROUND_TRIPS);

        MockKeyProvider alice_mock;
        for (const auto& [index, key] : alice_vec.message_keys) {
            alice_mock.SetKey(index, key);
        }

        MockKeyProvider bob_mock;
        for (const auto& [index, key] : bob_vec.message_keys) {
            bob_mock.SetKey(index, key);
        }

        uint32_t alice_to_bob_success = 0;
        uint32_t bob_to_alice_success = 0;

        for (uint32_t i = 0; i < ROUND_TRIPS; ++i) {
            RatchetChainKey alice_key(&alice_mock, i);
            const std::vector<uint8_t> alice_plaintext{0xA1, 0xA2, static_cast<uint8_t>(i & 0xFF)};
            std::vector<uint8_t> alice_nonce(12, static_cast<uint8_t>((i * 2) & 0xFF));

            auto alice_encrypted = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, alice_nonce, alice_plaintext, {});
                }
            );

            REQUIRE(alice_encrypted.IsOk());

            auto alice_decrypted = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, alice_nonce, alice_encrypted.Unwrap(), {});
                }
            );

            REQUIRE(alice_decrypted.IsOk());
            REQUIRE(alice_decrypted.Unwrap() == alice_plaintext);
            ++alice_to_bob_success;

            RatchetChainKey bob_key(&bob_mock, i);
            const std::vector<uint8_t> bob_plaintext{0xB1, 0xB2, static_cast<uint8_t>(i & 0xFF)};
            std::vector<uint8_t> bob_nonce(12, static_cast<uint8_t>((i * 2 + 1) & 0xFF));

            auto bob_encrypted = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, bob_nonce, bob_plaintext, {});
                }
            );

            REQUIRE(bob_encrypted.IsOk());

            auto bob_decrypted = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, bob_nonce, bob_encrypted.Unwrap(), {});
                }
            );

            REQUIRE(bob_decrypted.IsOk());
            REQUIRE(bob_decrypted.Unwrap() == bob_plaintext);
            ++bob_to_alice_success;
        }

        REQUIRE(alice_to_bob_success == ROUND_TRIPS);
        REQUIRE(bob_to_alice_success == ROUND_TRIPS);
    }
}

TEST_CASE("Double Ratchet - Key Derivation Consistency", "[interop][double-ratchet][derivation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Verify HKDF-derived keys are deterministic across 1000 iterations") {
        constexpr uint32_t KEY_COUNT = 1000;

        auto vec1 = DoubleRatchetTestVector::Generate(KEY_COUNT);
        auto vec2 = DoubleRatchetTestVector::Generate(KEY_COUNT);

        REQUIRE(vec1.initial_chain_key == vec2.initial_chain_key);

        uint32_t matching_keys = 0;

        for (uint32_t i = 0; i < KEY_COUNT; ++i) {
            REQUIRE(vec1.message_keys.count(i) > 0);
            REQUIRE(vec2.message_keys.count(i) > 0);

            if (vec1.message_keys[i] == vec2.message_keys[i]) {
                ++matching_keys;
            }
        }

        REQUIRE(matching_keys == KEY_COUNT);
    }
}

TEST_CASE("Double Ratchet - Memory Management Under Load", "[interop][double-ratchet][memory]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Process 50,000 keys with pruning every 10,000") {
        constexpr uint32_t TOTAL_KEYS = 50'000;
        constexpr uint32_t PRUNE_THRESHOLD = 10'000;

        auto test_vec = DoubleRatchetTestVector::Generate(TOTAL_KEYS);

        MockKeyProvider mock;

        uint32_t processed_keys = 0;

        for (uint32_t i = 0; i < TOTAL_KEYS; ++i) {
            if (test_vec.message_keys.count(i) > 0) {
                mock.SetKey(i, test_vec.message_keys[i]);
            }

            if (i > 0 && i % PRUNE_THRESHOLD == 0) {
                mock.PruneKeysBelow(i - PRUNE_THRESHOLD);
            }

            RatchetChainKey chain_key(&mock, i);

            const std::vector<uint8_t> plaintext{0xFF, 0xEE, static_cast<uint8_t>(i & 0xFF)};
            std::vector<uint8_t> nonce(12, 0x99);

            auto encrypted_result = chain_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, plaintext, {});
                }
            );

            if (encrypted_result.IsOk()) {
                ++processed_keys;
            }
        }

        // Final pruning to keep only the last PRUNE_THRESHOLD keys
        mock.PruneKeysBelow(TOTAL_KEYS - PRUNE_THRESHOLD);

        REQUIRE(processed_keys == TOTAL_KEYS);
        REQUIRE(mock.KeyCount() <= PRUNE_THRESHOLD);
    }
}

TEST_CASE("Double Ratchet - Large Payload Encryption", "[interop][double-ratchet][payload]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Encrypt 1MB payloads with 100 different message keys") {
        constexpr uint32_t MESSAGE_COUNT = 100;
        constexpr size_t PAYLOAD_SIZE = 1024 * 1024;

        auto test_vec = DoubleRatchetTestVector::Generate(MESSAGE_COUNT);

        MockKeyProvider mock;
        for (const auto& [index, key] : test_vec.message_keys) {
            mock.SetKey(index, key);
        }

        uint32_t successful_roundtrips = 0;

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            std::vector<uint8_t> large_payload(PAYLOAD_SIZE);
            for (size_t j = 0; j < PAYLOAD_SIZE; ++j) {
                large_payload[j] = static_cast<uint8_t>((i + j) & 0xFF);
            }

            RatchetChainKey chain_key(&mock, i);

            std::vector<uint8_t> nonce(12, static_cast<uint8_t>(i & 0xFF));

            auto encrypted_result = chain_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, large_payload, {});
                }
            );

            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            auto decrypted_result = chain_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, nonce, encrypted, {});
                }
            );

            REQUIRE(decrypted_result.IsOk());
            auto decrypted = std::move(decrypted_result).Unwrap();
            REQUIRE(decrypted == large_payload);

            ++successful_roundtrips;
        }

        REQUIRE(successful_roundtrips == MESSAGE_COUNT);
    }
}
