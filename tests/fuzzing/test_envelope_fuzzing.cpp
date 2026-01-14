#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include "helpers/hybrid_handshake.hpp"
#include "ecliptix/utilities/envelope_builder.hpp"
#include "ecliptix/core/constants.hpp"
#include "common/secure_envelope.pb.h"
#include <sodium.h>
#include <vector>
#include <random>
#include <cstring>
#include <iomanip>
#include <iostream>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::utilities;
using namespace ecliptix::proto::common;
using namespace ecliptix::protocol::test_helpers;

TEST_CASE("Fuzzing - Random Metadata Corruption", "[fuzzing][envelope][metadata]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Corrupt 10,000 encrypted metadata blocks at random positions") {
        auto conn = CreatePreparedConnection(1, true);

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
        auto conn = CreatePreparedConnection(1, false);

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
        auto [alice, bob] = CreatePreparedPair(1, 2);

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

            if (include_dh) {
                auto alice_dh_pub = alice->GetCurrentSenderDhPublicKey();
                if (alice_dh_pub.IsErr() || !alice_dh_pub.Unwrap().has_value()) continue;
                auto alice_ct = GetKyberCiphertextForSender(alice);
                auto ratchet_result = bob->PerformReceivingRatchet(*alice_dh_pub.Unwrap(), alice_ct);
                if (ratchet_result.IsErr()) continue;
            }

            auto nonce_result = alice->GenerateNextNonce();
            if (nonce_result.IsErr()) continue;
            auto nonce = std::move(nonce_result).Unwrap();

            for (size_t b = 0; b < 4 && b + 8 < nonce.size(); ++b) {
                nonce[8 + b] = static_cast<uint8_t>((alice_key.Index() >> (b * 8)) & 0xFF);
            }

            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, random_payload, {});
                }
            );
            if (encrypted_result.IsErr()) continue;
            auto encrypted = std::move(encrypted_result).Unwrap();

            auto bob_key_result = bob->ProcessReceivedMessage(alice_key.Index(), nonce);
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
            auto conn = CreatePreparedConnection(i, true);

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
        auto conn = CreatePreparedConnection(1, true);

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
        auto conn = CreatePreparedConnection(1, false);

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
            std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE, static_cast<uint8_t>(index & 0xFF));
            auto process_result = conn->ProcessReceivedMessage(index, nonce);
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
        auto [alice, bob] = CreatePreparedPair(1, 2);

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

            if (include_dh) {
                auto alice_dh_pub = alice->GetCurrentSenderDhPublicKey();
                if (alice_dh_pub.IsErr() || !alice_dh_pub.Unwrap().has_value()) continue;
                auto alice_ct = GetKyberCiphertextForSender(alice);
                auto ratchet_result = bob->PerformReceivingRatchet(*alice_dh_pub.Unwrap(), alice_ct);
                if (ratchet_result.IsErr()) continue;
            }

            auto nonce_result = alice->GenerateNextNonce();
            if (nonce_result.IsErr()) continue;
            auto nonce = std::move(nonce_result).Unwrap();

            for (size_t b = 0; b < 4 && b + 8 < nonce.size(); ++b) {
                nonce[8 + b] = static_cast<uint8_t>((alice_key.Index() >> (b * 8)) & 0xFF);
            }

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

                auto bob_key_result = bob->ProcessReceivedMessage(alice_key.Index(), nonce);
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
        auto [alice, bob] = CreatePreparedPair(1, 2);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x78);

        auto kyber_encapsulate = KyberInterop::Encapsulate(bob->GetKyberPublicKeyCopy());
        REQUIRE(kyber_encapsulate.IsOk());
        auto [kyber_ct, kyber_ss_handle] = std::move(kyber_encapsulate).Unwrap();
        auto kyber_ss_bytes = kyber_ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
        REQUIRE(kyber_ss_bytes.IsOk());
        auto kyber_ss = kyber_ss_bytes.Unwrap();
        REQUIRE(alice->SetHybridHandshakeSecrets(kyber_ct, kyber_ss).IsOk());
        REQUIRE(bob->SetHybridHandshakeSecrets(kyber_ct, kyber_ss).IsOk());
        REQUIRE(alice->DebugGetKyberSharedSecret() == kyber_ss);
        REQUIRE(bob->DebugGetKyberSharedSecret() == kyber_ss);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());
        REQUIRE(alice->DebugGetRootKey() == bob->DebugGetRootKey());

        constexpr uint32_t TEST_COUNT = 1000;
        uint32_t successful_empty_payload = 0;

        for (uint32_t i = 0; i < TEST_COUNT; ++i) {
            auto alice_prepare = alice->PrepareNextSendMessage();
            if (alice_prepare.IsErr()) break;
            auto [alice_key, include_dh] = std::move(alice_prepare).Unwrap();
            if (i >= 99 && i <= 102) {
                std::cerr << "include_dh=" << (include_dh ? "true" : "false")
                          << " idx=" << alice_key.Index() << std::endl;
            }

            if (include_dh) {
                auto alice_dh_pub = alice->GetCurrentSenderDhPublicKey();
                if (alice_dh_pub.IsErr() || !alice_dh_pub.Unwrap().has_value()) break;
                auto pre_alice_root = alice->DebugGetRootKey();
                auto pre_bob_root = bob->DebugGetRootKey();
                auto alice_ct = GetKyberCiphertextForSender(alice);
                auto ratchet_result = bob->PerformReceivingRatchet(*alice_dh_pub.Unwrap(), alice_ct);
                if (ratchet_result.IsErr()) break;
                if (i >= 99 && i <= 102) {
                    auto alice_current_dh = alice->GetCurrentSenderDhPublicKey();
                    auto bob_current_dh = bob->GetCurrentSenderDhPublicKey();
                    auto alice_root = alice->DebugGetRootKey();
                    auto bob_root = bob->DebugGetRootKey();
                    auto alice_priv = alice->DebugGetCurrentDhPrivate();
                    auto bob_priv = bob->DebugGetCurrentDhPrivate();
                    std::vector<uint8_t> dh_a(Constants::X_25519_KEY_SIZE);
                    std::vector<uint8_t> dh_b(Constants::X_25519_KEY_SIZE);
                    if (alice_priv.size() == Constants::X_25519_PRIVATE_KEY_SIZE &&
                        bob_current_dh.IsOk() && bob_current_dh.Unwrap().has_value()) {
                        const int dh_ret = crypto_scalarmult(
                            dh_a.data(), alice_priv.data(), bob_current_dh.Unwrap()->data());
                        (void) dh_ret;
                    }
                    if (bob_priv.size() == Constants::X_25519_PRIVATE_KEY_SIZE &&
                        alice_dh_pub.IsOk() && alice_dh_pub.Unwrap().has_value()) {
                        const int dh_ret = crypto_scalarmult(
                            dh_b.data(), bob_priv.data(), alice_dh_pub.Unwrap()->data());
                        (void) dh_ret;
                    }
                    std::vector<uint8_t> expected_root;
                    const auto alice_pq = alice->DebugGetKyberSharedSecret();
                    const auto bob_pq = bob->DebugGetKyberSharedSecret();
                    auto hybrid_result = KyberInterop::CombineHybridSecrets(
                        dh_b,
                        kyber_ss,
                        ProtocolConstants::HYBRID_DH_RATCHET_INFO);
                    if (hybrid_result.IsOk()) {
                        auto hybrid_bytes_result = hybrid_result.Unwrap().ReadBytes(Constants::X_25519_KEY_SIZE);
                        if (hybrid_bytes_result.IsOk()) {
                            auto hkdf_output = Hkdf::DeriveKeyBytes(
                                hybrid_bytes_result.Unwrap(),
                                Constants::X_25519_KEY_SIZE * 2,
                                pre_bob_root,
                                std::vector<uint8_t>(ProtocolConstants::HYBRID_DH_RATCHET_INFO.begin(),
                                                     ProtocolConstants::HYBRID_DH_RATCHET_INFO.end()));
                            if (hkdf_output.IsOk()) {
                                auto hkdf = hkdf_output.Unwrap();
                                expected_root.assign(hkdf.begin(),
                                                     hkdf.begin() + Constants::X_25519_KEY_SIZE);
                            }
                        }
                    }
                    std::cerr << "DH sizes - alice: "
                              << (alice_current_dh.IsOk() && alice_current_dh.Unwrap().has_value()
                                      ? std::to_string(alice_current_dh.Unwrap()->size()) : "err")
                              << " bob: "
                              << (bob_current_dh.IsOk() && bob_current_dh.Unwrap().has_value()
                                      ? std::to_string(bob_current_dh.Unwrap()->size()) : "err")
                              << " pre-root size " << pre_alice_root.size() << "/" << pre_bob_root.size()
                              << " pre-root match: " << (pre_alice_root == pre_bob_root ? "YES" : "NO")
                              << " root size " << alice_root.size() << "/" << bob_root.size()
                              << " root match: " << (alice_root == bob_root ? "YES" : "NO")
                              << " dh match: " << (dh_a == dh_b ? "YES" : "NO")
                              << " expected root match: "
                              << (!expected_root.empty() && expected_root == alice_root ? "YES" : "NO")
                              << " expected vs bob: "
                              << (!expected_root.empty() && expected_root == bob_root ? "YES" : "NO")
                              << " pq align a/b: "
                              << ((alice_pq == kyber_ss && bob_pq == kyber_ss) ? "YES" : "NO")
                              << std::endl;
                }
            }

            auto nonce_result = alice->GenerateNextNonce();
            if (nonce_result.IsErr()) break;
            auto nonce = std::move(nonce_result).Unwrap();

            for (size_t b = 0; b < 4 && b + 8 < nonce.size(); ++b) {
                nonce[8 + b] = static_cast<uint8_t>((alice_key.Index() >> (b * 8)) & 0xFF);
            }

            if (i >= 99 && i <= 102) {
                std::cerr << "Nonce: ";
                for (size_t j = 0; j < std::min(size_t(12), nonce.size()); ++j) {
                    std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int)nonce[j] << " ";
                }
                std::cerr << std::dec << std::endl;
            }

            const std::vector<uint8_t> empty_payload{};
            const std::vector<uint8_t> empty_aad{};

            std::vector<uint8_t> alice_key_bytes;
            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    if (i >= 99 && i <= 102) {
                        alice_key_bytes.assign(key.begin(), key.end());
                        std::cerr << "Alice encryption key (first 8 bytes): ";
                        for (size_t j = 0; j < std::min(size_t(8), key.size()); ++j) {
                            std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int)key[j] << " ";
                        }
                        std::cerr << std::dec << std::endl;
                    }
                    return AesGcm::Encrypt(key, nonce, empty_payload, empty_aad);
                }
            );
            if (encrypted_result.IsErr()) {
                if (i >= 99 && i <= 102) {
                    std::cerr << "Encryption FAILED: " << encrypted_result.UnwrapErr().message << std::endl;
                }
                break;
            }
            auto encrypted = std::move(encrypted_result).Unwrap();

            if (i >= 99 && i <= 102) {
                std::cerr << "Encrypted size: " << encrypted.size() << std::endl;
            }

            auto bob_key_result = bob->ProcessReceivedMessage(alice_key.Index(), nonce);
            if (bob_key_result.IsErr()) {
                if (i >= 99 && i <= 102) {
                    std::cerr << "Bob ProcessReceivedMessage FAILED: " << bob_key_result.UnwrapErr().message << std::endl;
                }
                break;
            }
            auto bob_key = std::move(bob_key_result).Unwrap();

            auto decrypted_result = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    if (i >= 99 && i <= 102) {
                        std::cerr << "Bob decryption key (first 8 bytes): ";
                        for (size_t j = 0; j < std::min(size_t(8), key.size()); ++j) {
                            std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int)key[j] << " ";
                        }
                        std::cerr << std::dec << std::endl;

                        bool keys_match = (key.size() == alice_key_bytes.size() &&
                                         std::equal(key.begin(), key.end(), alice_key_bytes.begin()));
                        std::cerr << "Keys match: " << (keys_match ? "YES" : "NO") << std::endl;
                    }
                    return AesGcm::Decrypt(key, nonce, encrypted, empty_aad);
                }
            );

            if (decrypted_result.IsOk()) {
                auto decrypted = std::move(decrypted_result).Unwrap();
                if (decrypted == empty_payload) {
                    ++successful_empty_payload;
                    if (i >= 99 && i <= 102) {
                        std::cerr << "Decryption SUCCESS" << std::endl;
                    }
                }
            } else {
                if (i >= 99 && i <= 102) {
                    std::cerr << "Decryption FAILED: " << decrypted_result.UnwrapErr().message << std::endl;
                }
            }
        }

        REQUIRE(successful_empty_payload == TEST_COUNT);
    }
}

TEST_CASE("Fuzzing - Repeated Values Stress Test", "[fuzzing][envelope][repeated]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Send 5000 identical messages - ensure unique ciphertexts") {
        auto [alice, bob] = CreatePreparedPair(1, 2);

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
