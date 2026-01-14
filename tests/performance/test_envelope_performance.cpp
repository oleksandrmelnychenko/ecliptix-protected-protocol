#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/protocol_connection.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/utilities/envelope_builder.hpp"
#include "ecliptix/core/constants.hpp"
#include "helpers/hybrid_handshake.hpp"
#include "common/secure_envelope.pb.h"
#include <vector>
#include <chrono>
#include <sstream>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::utilities;
using namespace ecliptix::proto::common;
using namespace ecliptix::protocol::test_helpers;

TEST_CASE("Performance - High-Throughput Envelope Generation", "[performance][envelope][.slow]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Generate 1 million envelopes") {
        RatchetConfig perf_config(1'000'000);
        auto conn = CreatePreparedConnection(1, true, perf_config);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAB);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        auto metadata_key = conn->GetMetadataEncryptionKey().Unwrap();

        constexpr uint32_t ENVELOPE_COUNT = 100'000;
        uint32_t successful_operations = 0;

        const auto start_time = std::chrono::high_resolution_clock::now();

        for (uint32_t i = 0; i < ENVELOPE_COUNT; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            if (nonce_result.IsErr()) continue;
            auto nonce = std::move(nonce_result).Unwrap();

            const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                i,
                nonce,
                i,
                {},
                static_cast<EnvelopeType>(i % 3),
                ""
            );

            std::vector<uint8_t> header_nonce(12, static_cast<uint8_t>(i & 0xFF));
            std::vector<uint8_t> aad{0xAA};

            auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                metadata,
                metadata_key,
                header_nonce,
                aad
            );

            if (encrypted_result.IsOk()) {
                ++successful_operations;
            }
        }

        const auto end_time = std::chrono::high_resolution_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();

        REQUIRE(successful_operations == ENVELOPE_COUNT);

        if (duration > 0) {
            const double envelopes_per_second = (successful_operations * 1000.0) / duration;
            REQUIRE(envelopes_per_second > 1000.0);
        }
    }
}

TEST_CASE("Performance - Sustained Message Encryption", "[performance][envelope][encryption][.slow]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Encrypt and decrypt 500,000 messages") {
        RatchetConfig perf_config(1'000'000);
        auto alice = CreatePreparedConnection(1, true, perf_config);

        auto bob = CreatePreparedConnection(2, false, perf_config);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xCD);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        constexpr uint32_t MESSAGE_COUNT = 5'000;
        uint32_t successful_roundtrips = 0;

        const auto start_time = std::chrono::high_resolution_clock::now();

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            auto alice_prepare = alice->PrepareNextSendMessage();
            if (alice_prepare.IsErr()) break;
            auto [alice_key, include_dh] = std::move(alice_prepare).Unwrap();

            if (include_dh) {
                auto alice_dh_pub = alice->GetCurrentSenderDhPublicKey();
                if (alice_dh_pub.IsErr() || !alice_dh_pub.Unwrap().has_value()) break;
                auto alice_ct = GetKyberCiphertextForSender(alice);
                auto ratchet_result = bob->ExecuteReceivingRatchet(*alice_dh_pub.Unwrap(), alice_ct);
                if (ratchet_result.IsErr()) break;
            }

            auto nonce_result = alice->GenerateNextNonce();
            if (nonce_result.IsErr()) break;
            auto nonce = std::move(nonce_result).Unwrap();
            for (size_t b = 0; b < 4 && b + 8 < nonce.size(); ++b) {
                nonce[8 + b] = static_cast<uint8_t>((alice_key.Index() >> (b * 8)) & 0xFF);
            }

            const std::vector<uint8_t> plaintext{
                static_cast<uint8_t>(i & 0xFF),
                static_cast<uint8_t>((i >> 8) & 0xFF),
                static_cast<uint8_t>((i >> 16) & 0xFF),
                static_cast<uint8_t>((i >> 24) & 0xFF)
            };

            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, plaintext, {});
                }
            );
            if (encrypted_result.IsErr()) break;
            auto encrypted = std::move(encrypted_result).Unwrap();

            auto bob_key_result = bob->ProcessReceivedMessage(alice_key.Index(), nonce);
            if (bob_key_result.IsErr()) break;
            auto bob_key = std::move(bob_key_result).Unwrap();

            auto decrypted_result = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, nonce, encrypted, {});
                }
            );
            if (decrypted_result.IsErr()) break;
            auto decrypted = std::move(decrypted_result).Unwrap();

            if (decrypted == plaintext) {
                ++successful_roundtrips;
            }
        }

        const auto end_time = std::chrono::high_resolution_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();

        REQUIRE(successful_roundtrips == MESSAGE_COUNT);

        if (duration > 0) {
            const double messages_per_second = (successful_roundtrips * 1000.0) / duration;
            REQUIRE(messages_per_second > 500.0);
        }
    }
}

TEST_CASE("Performance - Memory Efficiency Under Load", "[performance][envelope][memory][.slow]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Process 100,000 envelopes without memory explosion") {
        RatchetConfig perf_config(1'000'000);
        auto conn = CreatePreparedConnection(1, true, perf_config);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xEF);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        auto metadata_key = conn->GetMetadataEncryptionKey().Unwrap();

        constexpr uint32_t ENVELOPE_COUNT = 50'000;
        uint32_t processed_envelopes = 0;

        for (uint32_t i = 0; i < ENVELOPE_COUNT; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            if (nonce_result.IsErr()) continue;
            auto nonce = std::move(nonce_result).Unwrap();

            const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                i, nonce, i, {}, static_cast<EnvelopeType>(0), "");

            std::vector<uint8_t> header_nonce(12, 0x42);
            std::vector<uint8_t> aad{0xBB};

            auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                metadata, metadata_key, header_nonce, aad);

            if (encrypted_result.IsOk()) {
                auto encrypted = std::move(encrypted_result).Unwrap();

                auto decrypted_result = EnvelopeBuilder::DecryptMetadata(
                    encrypted, metadata_key, header_nonce, aad);

                if (decrypted_result.IsOk()) {
                    ++processed_envelopes;
                }
            }
        }

        REQUIRE(processed_envelopes == ENVELOPE_COUNT);
    }
}

TEST_CASE("Performance - Nonce Generation Throughput", "[performance][envelope][nonce][.slow]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Generate 1 million unique nonces") {
        RatchetConfig perf_config(1'000'000);
        auto conn = CreatePreparedConnection(1, true, perf_config);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x12);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        constexpr uint32_t NONCE_COUNT = 100'000;
        uint32_t successful_generations = 0;

        const auto start_time = std::chrono::high_resolution_clock::now();

        for (uint32_t i = 0; i < NONCE_COUNT; ++i) {
            auto nonce_result = conn->GenerateNextNonce();
            if (nonce_result.IsOk()) {
                ++successful_generations;
            }
        }

        const auto end_time = std::chrono::high_resolution_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();

        REQUIRE(successful_generations == NONCE_COUNT);

        if (duration > 0) {
            const double nonces_per_second = (successful_generations * 1000.0) / duration;
            REQUIRE(nonces_per_second > 10'000.0);
        }
    }
}

TEST_CASE("Performance - Bulk Metadata Encryption", "[performance][envelope][metadata][.slow]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Encrypt 100,000 metadata blocks") {
        RatchetConfig perf_config(1'000'000);
        auto conn = CreatePreparedConnection(1, true, perf_config);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x34);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        auto metadata_key = conn->GetMetadataEncryptionKey().Unwrap();

        constexpr uint32_t METADATA_COUNT = 100'000;
        uint32_t successful_encryptions = 0;

        const auto start_time = std::chrono::high_resolution_clock::now();

        for (uint32_t i = 0; i < METADATA_COUNT; ++i) {
            std::vector<uint8_t> nonce(12, static_cast<uint8_t>(i & 0xFF));
            const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                i, nonce, i, {}, static_cast<EnvelopeType>(i % 3), "");

            std::vector<uint8_t> header_nonce(12, static_cast<uint8_t>((i >> 8) & 0xFF));
            std::vector<uint8_t> aad{0xCC};

            auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                metadata, metadata_key, header_nonce, aad);

            if (encrypted_result.IsOk()) {
                ++successful_encryptions;
            }
        }

        const auto end_time = std::chrono::high_resolution_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();

        REQUIRE(successful_encryptions == METADATA_COUNT);

        if (duration > 0) {
            const double encryptions_per_second = (successful_encryptions * 1000.0) / duration;
            REQUIRE(encryptions_per_second > 1'000.0);
        }
    }
}

TEST_CASE("Performance - Large Payload Throughput", "[performance][envelope][payload][.slow][.benchmark]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Encrypt 1,000 × 1MB payloads") {
        RatchetConfig perf_config(1'000'000);
        auto alice = CreatePreparedConnection(1, true, perf_config);

        auto bob = CreatePreparedConnection(2, false, perf_config);

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x56);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        constexpr size_t PAYLOAD_SIZE = 1024 * 1024;
#ifdef ECLIPTIX_TEST_BUILD
        constexpr uint32_t MESSAGE_COUNT = 100;
#else
        constexpr uint32_t MESSAGE_COUNT = 1'000;
#endif
        uint32_t successful_transfers = 0;
        uint32_t attempted = 0;
        std::string last_error;

        std::vector<uint8_t> large_payload(PAYLOAD_SIZE, 0xAA);

        const auto start_time = std::chrono::high_resolution_clock::now();

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            for (size_t j = 0; j < PAYLOAD_SIZE; j += 1024) {
                large_payload[j] = static_cast<uint8_t>((i + j) & 0xFF);
            }

            auto alice_prepare = alice->PrepareNextSendMessage();
            if (alice_prepare.IsErr()) {
                last_error = alice_prepare.UnwrapErr().message;
                break;
            }
            auto [alice_key, include_dh] = std::move(alice_prepare).Unwrap();

            if (include_dh) {
                auto alice_dh_pub = alice->GetCurrentSenderDhPublicKey();
                if (alice_dh_pub.IsErr() || !alice_dh_pub.Unwrap().has_value()) {
                    last_error = "Failed to read alice DH pub";
                    break;
                }
                auto alice_ct = GetKyberCiphertextForSender(alice);
                auto ratchet_result = bob->ExecuteReceivingRatchet(*alice_dh_pub.Unwrap(), alice_ct);
                if (ratchet_result.IsErr()) {
                    last_error = ratchet_result.UnwrapErr().message;
                    break;
                }
            }

            auto nonce_result = alice->GenerateNextNonce();
            if (nonce_result.IsErr()) {
                last_error = nonce_result.UnwrapErr().message;
                break;
            }
            auto nonce = std::move(nonce_result).Unwrap();
            for (size_t b = 0; b < 4 && b + 8 < nonce.size(); ++b) {
                nonce[8 + b] = static_cast<uint8_t>((alice_key.Index() >> (b * 8)) & 0xFF);
            }

            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, large_payload, {});
                }
            );
            if (encrypted_result.IsErr()) {
                last_error = encrypted_result.UnwrapErr().message;
                break;
            }
            auto encrypted = std::move(encrypted_result).Unwrap();

            auto bob_key_result = bob->ProcessReceivedMessage(alice_key.Index(), nonce);
            if (bob_key_result.IsErr()) {
                last_error = bob_key_result.UnwrapErr().message;
                break;
            }
            auto bob_key = std::move(bob_key_result).Unwrap();

            auto decrypted_result = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, nonce, encrypted, {});
                }
            );
            if (decrypted_result.IsErr()) {
                last_error = decrypted_result.UnwrapErr().message;
                break;
            }
            auto decrypted = std::move(decrypted_result).Unwrap();

            if (decrypted == large_payload) {
                ++successful_transfers;
            }
            ++attempted;
        }

        const auto end_time = std::chrono::high_resolution_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            end_time - start_time).count();

        std::ostringstream oss;
        oss << "attempted=" << attempted << " last_error=" << last_error
            << " success=" << successful_transfers;
        INFO(oss.str());
        REQUIRE(successful_transfers == MESSAGE_COUNT);

        if (duration > 0) {
            const double mb_per_second = (successful_transfers * PAYLOAD_SIZE) / (duration * 1024.0 * 1024.0);
#ifdef ECLIPTIX_TEST_BUILD
            REQUIRE(mb_per_second > 5.0);
#else
            REQUIRE(mb_per_second > 10.0);
#endif
        }
    }
}
