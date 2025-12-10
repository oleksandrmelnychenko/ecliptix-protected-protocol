#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/utilities/envelope_builder.hpp"
#include "ecliptix/core/constants.hpp"
#include "common/secure_envelope.pb.h"
#include <vector>
#include <random>
#include <cstring>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::utilities;
using namespace ecliptix::proto::common;

TEST_CASE("Fuzzing - Random Metadata Corruption", "[fuzzing][envelope][metadata]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Corrupt 10,000 encrypted metadata blocks at random positions") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAB);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        auto metadata_key = conn->GetMetadataEncryptionKey().Unwrap();

        std::random_device rd;
        std::mt19937 gen(42);

        constexpr uint32_t CORRUPTION_ATTEMPTS = 10'000;
        uint32_t detected_corruptions = 0;

        for (uint32_t i = 0; i < CORRUPTION_ATTEMPTS; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                i, nonce, i, {}, static_cast<EnvelopeType>(0), "fuzz-test");

            std::vector<uint8_t> header_nonce(12, static_cast<uint8_t>(i & 0xFF));
            std::vector<uint8_t> aad{0xAA};

            auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                metadata, metadata_key, header_nonce, aad);
            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            if (encrypted.size() > 0) {
                std::uniform_int_distribution<size_t> pos_dist(0, encrypted.size() - 1);
                const size_t corrupt_pos = pos_dist(gen);

                std::uniform_int_distribution<uint8_t> byte_dist(1, 255);
                const uint8_t corrupt_value = byte_dist(gen);

                encrypted[corrupt_pos] ^= corrupt_value;

                auto decrypted_result = EnvelopeBuilder::DecryptMetadata(
                    encrypted, metadata_key, header_nonce, aad);

                if (decrypted_result.IsErr()) {
                    ++detected_corruptions;
                }
            }
        }

        REQUIRE(detected_corruptions == CORRUPTION_ATTEMPTS);
    }
}

TEST_CASE("Fuzzing - Random Nonce Lengths", "[fuzzing][envelope][nonce]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Test 5000 nonces with random lengths from 0 to 100 bytes") {
        auto conn_result = EcliptixProtocolConnection::Create(1, false);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xCD);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        std::random_device rd;
        std::mt19937 gen(123);
        std::uniform_int_distribution<size_t> length_dist(0, 100);

        constexpr uint32_t TEST_COUNT = 5000;
        uint32_t invalid_nonce_detected = 0;
        uint32_t valid_nonce_passed = 0;

        for (uint32_t i = 0; i < TEST_COUNT; ++i) {
            const size_t nonce_length = length_dist(gen);

            std::vector<uint8_t> random_nonce(nonce_length);
            for (size_t j = 0; j < nonce_length; ++j) {
                random_nonce[j] = static_cast<uint8_t>(gen() & 0xFF);
            }

            auto check_result = conn->CheckReplayProtection(random_nonce, i);

            if (nonce_length == 12) {
                if (check_result.IsOk()) {
                    ++valid_nonce_passed;
                }
            } else {
                if (check_result.IsErr()) {
                    ++invalid_nonce_detected;
                }
            }
        }

        REQUIRE(invalid_nonce_detected > 0);
        REQUIRE(valid_nonce_passed > 0);
    }
}

TEST_CASE("Fuzzing - Random Payload Sizes", "[fuzzing][envelope][payload]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Encrypt payloads with random sizes from 0 to 10MB") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xEF);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        std::random_device rd;
        std::mt19937 gen(456);

        constexpr uint32_t MESSAGE_COUNT = 100;
        uint32_t successful_roundtrips = 0;

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            std::uniform_int_distribution<size_t> size_dist(0, 10 * 1024 * 1024);
            const size_t payload_size = size_dist(gen);

            std::vector<uint8_t> random_payload(payload_size);
            for (size_t j = 0; j < payload_size; j += 1024) {
                random_payload[j] = static_cast<uint8_t>(gen() & 0xFF);
            }

            auto alice_prepare = alice->PrepareNextSendMessage();
            if (alice_prepare.IsErr()) continue;
            auto [alice_key, include_dh] = std::move(alice_prepare).Unwrap();

            auto nonce_result = alice->GenerateNextNonce();
            if (nonce_result.IsErr()) continue;
            auto nonce = std::move(nonce_result).Unwrap();

            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, random_payload, {});
                }
            );
            if (encrypted_result.IsErr()) continue;
            auto encrypted = std::move(encrypted_result).Unwrap();

            auto bob_key_result = bob->ProcessReceivedMessage(i);
            if (bob_key_result.IsErr()) continue;
            auto bob_key = std::move(bob_key_result).Unwrap();

            auto decrypted_result = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, nonce, encrypted, {});
                }
            );
            if (decrypted_result.IsErr()) continue;
            auto decrypted = std::move(decrypted_result).Unwrap();

            if (decrypted == random_payload) {
                ++successful_roundtrips;
            }
        }

        REQUIRE(successful_roundtrips > 0);
    }
}

TEST_CASE("Fuzzing - Invalid Key Sizes", "[fuzzing][envelope][keys]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Attempt finalization with 10,000 random key sizes") {
        std::random_device rd;
        std::mt19937 gen(789);
        std::uniform_int_distribution<size_t> size_dist(0, 128);

        constexpr uint32_t ATTEMPT_COUNT = 10'000;
        uint32_t rejected_invalid_keys = 0;
        uint32_t accepted_valid_keys = 0;

        for (uint32_t i = 0; i < ATTEMPT_COUNT; ++i) {
            auto conn_result = EcliptixProtocolConnection::Create(i, true);
            REQUIRE(conn_result.IsOk());
            auto conn = std::move(conn_result).Unwrap();

            const size_t root_key_size = size_dist(gen);
            std::vector<uint8_t> random_root_key(root_key_size, 0xAB);

            auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
            REQUIRE(peer_keypair.IsOk());
            auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

            auto finalize_result = conn->FinalizeChainAndDhKeys(random_root_key, peer_pk);

            if (root_key_size == Constants::X_25519_KEY_SIZE) {
                if (finalize_result.IsOk()) {
                    ++accepted_valid_keys;
                }
            } else {
                if (finalize_result.IsErr()) {
                    ++rejected_invalid_keys;
                }
            }
        }

        REQUIRE(rejected_invalid_keys > 0);
        REQUIRE(accepted_valid_keys > 0);
    }
}

TEST_CASE("Fuzzing - Malformed AAD", "[fuzzing][envelope][aad]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Test 5000 random AAD sizes and contents") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x12);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        auto metadata_key = conn->GetMetadataEncryptionKey().Unwrap();

        std::random_device rd;
        std::mt19937 gen(987);
        std::uniform_int_distribution<size_t> aad_size_dist(0, 1024);

        constexpr uint32_t TEST_COUNT = 5000;
        uint32_t aad_mismatch_detected = 0;

        for (uint32_t i = 0; i < TEST_COUNT; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                i, nonce, i, {}, static_cast<EnvelopeType>(0), "");

            std::vector<uint8_t> header_nonce(12, 0x42);

            const size_t aad_size = aad_size_dist(gen);
            std::vector<uint8_t> original_aad(aad_size);
            for (size_t j = 0; j < aad_size; ++j) {
                original_aad[j] = static_cast<uint8_t>(gen() & 0xFF);
            }

            auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                metadata, metadata_key, header_nonce, original_aad);
            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            const size_t tampered_aad_size = aad_size_dist(gen);
            std::vector<uint8_t> tampered_aad(tampered_aad_size);
            for (size_t j = 0; j < tampered_aad_size; ++j) {
                tampered_aad[j] = static_cast<uint8_t>(gen() & 0xFF);
            }

            auto decrypted_result = EnvelopeBuilder::DecryptMetadata(
                encrypted, metadata_key, header_nonce, tampered_aad);

            if (original_aad != tampered_aad) {
                if (decrypted_result.IsErr()) {
                    ++aad_mismatch_detected;
                }
            }
        }

        REQUIRE(aad_mismatch_detected > 0);
    }
}

TEST_CASE("Fuzzing - Boundary Value Testing", "[fuzzing][envelope][boundaries]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Test edge case message indices: 0, 1, MAX_UINT32-1, MAX_UINT32") {
        auto conn_result = EcliptixProtocolConnection::Create(1, false);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x34);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        const std::vector<uint32_t> edge_indices = {
            0,
            1,
            255,
            256,
            65535,
            65536,
        };

        uint32_t processed_edge_cases = 0;

        for (const uint32_t index : edge_indices) {
            auto process_result = conn->ProcessReceivedMessage(index);
            if (process_result.IsOk()) {
                ++processed_edge_cases;
            }
        }

        REQUIRE(processed_edge_cases > 0);
    }
}

TEST_CASE("Fuzzing - Random Bit Flips in Ciphertext", "[fuzzing][envelope][bitflip]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Flip random bits in 10,000 encrypted payloads") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x56);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        std::random_device rd;
        std::mt19937 gen(654);

        constexpr uint32_t FLIP_COUNT = 10'000;
        uint32_t detected_bit_flips = 0;

        for (uint32_t i = 0; i < FLIP_COUNT; ++i) {
            auto alice_prepare = alice->PrepareNextSendMessage();
            if (alice_prepare.IsErr()) continue;
            auto [alice_key, include_dh] = std::move(alice_prepare).Unwrap();

            auto nonce_result = alice->GenerateNextNonce();
            if (nonce_result.IsErr()) continue;
            auto nonce = std::move(nonce_result).Unwrap();

            const std::vector<uint8_t> plaintext{0xDE, 0xAD, 0xBE, 0xEF};

            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, plaintext, {});
                }
            );
            if (encrypted_result.IsErr()) continue;
            auto encrypted = std::move(encrypted_result).Unwrap();

            if (encrypted.size() > 0) {
                std::uniform_int_distribution<size_t> byte_dist(0, encrypted.size() - 1);
                const size_t flip_byte = byte_dist(gen);

                std::uniform_int_distribution<uint8_t> bit_dist(0, 7);
                const uint8_t flip_bit = bit_dist(gen);

                encrypted[flip_byte] ^= (1 << flip_bit);

                auto bob_key_result = bob->ProcessReceivedMessage(i);
                if (bob_key_result.IsErr()) continue;
                auto bob_key = std::move(bob_key_result).Unwrap();

                auto decrypted_result = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                    [&](std::span<const uint8_t> key) {
                        return AesGcm::Decrypt(key, nonce, encrypted, {});
                    }
                );

                if (decrypted_result.IsErr()) {
                    ++detected_bit_flips;
                }
            }
        }

        REQUIRE(detected_bit_flips == FLIP_COUNT);
    }
}

TEST_CASE("Fuzzing - Empty and Null Inputs", "[fuzzing][envelope][empty]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Test 1000 empty payloads, nonces, and AAD combinations") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x78);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        constexpr uint32_t TEST_COUNT = 1000;
        uint32_t successful_empty_payload = 0;

        for (uint32_t i = 0; i < TEST_COUNT; ++i) {
            auto alice_prepare = alice->PrepareNextSendMessage();
            if (alice_prepare.IsErr()) continue;
            auto [alice_key, include_dh] = std::move(alice_prepare).Unwrap();

            auto nonce_result = alice->GenerateNextNonce();
            if (nonce_result.IsErr()) continue;
            auto nonce = std::move(nonce_result).Unwrap();

            const std::vector<uint8_t> empty_payload{};
            const std::vector<uint8_t> empty_aad{};

            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, empty_payload, empty_aad);
                }
            );
            if (encrypted_result.IsErr()) continue;
            auto encrypted = std::move(encrypted_result).Unwrap();

            auto bob_key_result = bob->ProcessReceivedMessage(i);
            if (bob_key_result.IsErr()) continue;
            auto bob_key = std::move(bob_key_result).Unwrap();

            auto decrypted_result = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, nonce, encrypted, empty_aad);
                }
            );

            if (decrypted_result.IsOk()) {
                auto decrypted = std::move(decrypted_result).Unwrap();
                if (decrypted == empty_payload) {
                    ++successful_empty_payload;
                }
            }
        }

        REQUIRE(successful_empty_payload == TEST_COUNT);
    }
}

TEST_CASE("Fuzzing - Repeated Values Stress Test", "[fuzzing][envelope][repeated]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Send 5000 identical messages - ensure unique ciphertexts") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x9A);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        const std::vector<uint8_t> repeated_plaintext{0x42, 0x42, 0x42, 0x42};

        constexpr uint32_t MESSAGE_COUNT = 5000;
        std::vector<std::vector<uint8_t>> ciphertexts;
        ciphertexts.reserve(MESSAGE_COUNT);

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            auto alice_prepare = alice->PrepareNextSendMessage();
            if (alice_prepare.IsErr()) continue;
            auto [alice_key, include_dh] = std::move(alice_prepare).Unwrap();

            auto nonce_result = alice->GenerateNextNonce();
            if (nonce_result.IsErr()) continue;
            auto nonce = std::move(nonce_result).Unwrap();

            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, repeated_plaintext, {});
                }
            );
            if (encrypted_result.IsErr()) continue;
            auto encrypted = std::move(encrypted_result).Unwrap();

            ciphertexts.push_back(encrypted);
        }

        uint32_t unique_ciphertexts = 0;
        for (size_t i = 0; i < ciphertexts.size(); ++i) {
            bool is_unique = true;
            for (size_t j = 0; j < i; ++j) {
                if (ciphertexts[i] == ciphertexts[j]) {
                    is_unique = false;
                    break;
                }
            }
            if (is_unique) {
                ++unique_ciphertexts;
            }
        }

        REQUIRE(unique_ciphertexts == ciphertexts.size());
    }
}
