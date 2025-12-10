#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/utilities/envelope_builder.hpp"
#include "ecliptix/core/constants.hpp"
#include "common/secure_envelope.pb.h"
#include <vector>
#include <set>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::utilities;
using namespace ecliptix::proto::common;

TEST_CASE("Metadata Key Rotation - Basic Rotation on DH Ratchet", "[security][metadata_rotation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Metadata key rotates on DH ratchet") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAA);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        auto initial_metadata_key = alice->GetMetadataEncryptionKey().Unwrap();

        const EnvelopeMetadata metadata1 = EnvelopeBuilder::CreateEnvelopeMetadata(
            1, std::vector<uint8_t>(12, 0x11), 0, {}, EnvelopeType::REQUEST, "test-1");

        std::vector<uint8_t> header_nonce(12, 0x22);
        std::vector<uint8_t> aad{0xAA};

        auto encrypted1_result = EnvelopeBuilder::EncryptMetadata(
            metadata1, initial_metadata_key, header_nonce, aad);
        REQUIRE(encrypted1_result.IsOk());
        auto encrypted1 = std::move(encrypted1_result).Unwrap();

        for (uint32_t i = 0; i < 100; ++i) {
            auto prepare = alice->PrepareNextSendMessage();
            REQUIRE(prepare.IsOk());
            REQUIRE(bob->ProcessReceivedMessage(i).IsOk());
        }

        auto rotated_metadata_key = alice->GetMetadataEncryptionKey().Unwrap();

        REQUIRE(initial_metadata_key != rotated_metadata_key);

        auto decrypt_with_old_result = EnvelopeBuilder::DecryptMetadata(
            encrypted1, initial_metadata_key, header_nonce, aad);
        REQUIRE(decrypt_with_old_result.IsOk());

        auto decrypt_with_new_result = EnvelopeBuilder::DecryptMetadata(
            encrypted1, rotated_metadata_key, header_nonce, aad);
        REQUIRE(decrypt_with_new_result.IsErr());
    }
}

TEST_CASE("Metadata Key Rotation - Forward Secrecy", "[security][metadata_rotation][forward_secrecy]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Old metadata keys cannot decrypt new messages after rotation") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xBB);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        std::vector<std::vector<uint8_t>> metadata_keys;
        metadata_keys.push_back(alice->GetMetadataEncryptionKey().Unwrap());

        for (uint32_t ratchet = 0; ratchet < 5; ++ratchet) {
            for (uint32_t i = 0; i < 100; ++i) {
                auto prepare = alice->PrepareNextSendMessage();
                REQUIRE(prepare.IsOk());
                REQUIRE(bob->ProcessReceivedMessage(i).IsOk());
            }
            metadata_keys.push_back(alice->GetMetadataEncryptionKey().Unwrap());
        }

        REQUIRE(metadata_keys.size() == 6);

        for (size_t i = 0; i < metadata_keys.size(); ++i) {
            for (size_t j = i + 1; j < metadata_keys.size(); ++j) {
                REQUIRE(metadata_keys[i] != metadata_keys[j]);
            }
        }

        const EnvelopeMetadata current_metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
            1000, std::vector<uint8_t>(12, 0x33), 500, {}, EnvelopeType::REQUEST, "current");

        std::vector<uint8_t> header_nonce(12, 0x44);
        std::vector<uint8_t> aad{0xBB};

        auto current_key = metadata_keys.back();
        auto encrypted_current = EnvelopeBuilder::EncryptMetadata(
            current_metadata, current_key, header_nonce, aad).Unwrap();

        for (size_t i = 0; i < metadata_keys.size() - 1; ++i) {
            auto decrypt_result = EnvelopeBuilder::DecryptMetadata(
                encrypted_current, metadata_keys[i], header_nonce, aad);
            REQUIRE(decrypt_result.IsErr());
        }

        auto decrypt_correct = EnvelopeBuilder::DecryptMetadata(
            encrypted_current, current_key, header_nonce, aad);
        REQUIRE(decrypt_correct.IsOk());
        REQUIRE(decrypt_correct.Unwrap().envelope_id() == "1000");
    }
}

TEST_CASE("Metadata Key Rotation - Uniqueness Across Ratchets", "[security][metadata_rotation][uniqueness]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Each DH ratchet produces unique metadata key") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xCC);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        std::set<std::vector<uint8_t>> observed_keys;
        observed_keys.insert(alice->GetMetadataEncryptionKey().Unwrap());

        for (uint32_t ratchet = 0; ratchet < 50; ++ratchet) {
            for (uint32_t i = 0; i < 100; ++i) {
                auto prepare = alice->PrepareNextSendMessage();
                REQUIRE(prepare.IsOk());
                auto process = bob->ProcessReceivedMessage(i);
                REQUIRE(process.IsOk());
            }

            auto current_key = alice->GetMetadataEncryptionKey().Unwrap();
            REQUIRE(observed_keys.find(current_key) == observed_keys.end());
            observed_keys.insert(current_key);
        }

        REQUIRE(observed_keys.size() == 51);
    }
}

TEST_CASE("Metadata Key Rotation - Decryption Window", "[security][metadata_rotation][decryption]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Messages encrypted with rotated key cannot be decrypted with old key") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xDD);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        struct EncryptedMessage {
            std::vector<uint8_t> ciphertext;
            std::vector<uint8_t> header_nonce;
            std::vector<uint8_t> aad;
            std::vector<uint8_t> expected_key;
        };

        std::vector<EncryptedMessage> messages;

        for (uint32_t ratchet = 0; ratchet < 10; ++ratchet) {
            auto current_key = alice->GetMetadataEncryptionKey().Unwrap();

            const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                ratchet, std::vector<uint8_t>(12, static_cast<uint8_t>(ratchet)),
                ratchet * 100, {}, EnvelopeType::REQUEST, std::to_string(ratchet));

            std::vector<uint8_t> header_nonce(12, static_cast<uint8_t>(ratchet + 0x10));
            std::vector<uint8_t> aad{static_cast<uint8_t>(ratchet + 0xA0)};

            auto encrypted = EnvelopeBuilder::EncryptMetadata(
                metadata, current_key, header_nonce, aad).Unwrap();

            messages.push_back({encrypted, header_nonce, aad, current_key});

            for (uint32_t i = 0; i < 100; ++i) {
                auto prepare = alice->PrepareNextSendMessage();
                REQUIRE(prepare.IsOk());
                REQUIRE(bob->ProcessReceivedMessage(i).IsOk());
            }
        }

        REQUIRE(messages.size() == 10);

        for (size_t i = 0; i < messages.size(); ++i) {
            auto decrypt_correct = EnvelopeBuilder::DecryptMetadata(
                messages[i].ciphertext,
                messages[i].expected_key,
                messages[i].header_nonce,
                messages[i].aad);
            REQUIRE(decrypt_correct.IsOk());
            REQUIRE(decrypt_correct.Unwrap().envelope_id() == std::to_string(i));

            for (size_t j = 0; j < messages.size(); ++j) {
                if (i == j) continue;

                auto decrypt_wrong = EnvelopeBuilder::DecryptMetadata(
                    messages[i].ciphertext,
                    messages[j].expected_key,
                    messages[i].header_nonce,
                    messages[i].aad);
                REQUIRE(decrypt_wrong.IsErr());
            }
        }
    }
}

TEST_CASE("Metadata Key Rotation - High-Frequency Ratchets", "[security][metadata_rotation][stress]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Metadata key remains unique under high-frequency ratcheting") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xEE);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        std::set<std::vector<uint8_t>> observed_keys;
        auto initial_key = alice->GetMetadataEncryptionKey().Unwrap();
        observed_keys.insert(initial_key);

        for (uint32_t ratchet = 0; ratchet < 100; ++ratchet) {
            for (uint32_t i = 0; i < 100; ++i) {
                auto prepare = alice->PrepareNextSendMessage();
                REQUIRE(prepare.IsOk());
                REQUIRE(bob->ProcessReceivedMessage(i).IsOk());
            }

            auto current_key = alice->GetMetadataEncryptionKey().Unwrap();
            REQUIRE(observed_keys.find(current_key) == observed_keys.end());
            observed_keys.insert(current_key);
        }

        REQUIRE(observed_keys.size() == 101);
    }
}

TEST_CASE("Metadata Key Rotation - Bidirectional Ratchets", "[security][metadata_rotation][bidirectional]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Both sides maintain independent metadata key rotation") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xFF);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        std::vector<std::vector<uint8_t>> alice_keys;
        std::vector<std::vector<uint8_t>> bob_keys;

        alice_keys.push_back(alice->GetMetadataEncryptionKey().Unwrap());
        bob_keys.push_back(bob->GetMetadataEncryptionKey().Unwrap());

        for (uint32_t round = 0; round < 20; ++round) {
            for (uint32_t i = 0; i < 100; ++i) {
                auto prepare = alice->PrepareNextSendMessage();
                REQUIRE(prepare.IsOk());
                auto [key, include_dh] = prepare.Unwrap();
                if (include_dh) {
                    auto alice_new_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
                    REQUIRE(bob->PerformReceivingRatchet(alice_new_dh).IsOk());
                }
                REQUIRE(bob->ProcessReceivedMessage(i).IsOk());
            }
            alice_keys.push_back(alice->GetMetadataEncryptionKey().Unwrap());

            for (uint32_t i = 0; i < 100; ++i) {
                auto prepare = bob->PrepareNextSendMessage();
                REQUIRE(prepare.IsOk());
                auto [key, include_dh] = prepare.Unwrap();
                if (include_dh) {
                    auto bob_new_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();
                    REQUIRE(alice->PerformReceivingRatchet(bob_new_dh).IsOk());
                }
                REQUIRE(alice->ProcessReceivedMessage(i).IsOk());
            }
            bob_keys.push_back(bob->GetMetadataEncryptionKey().Unwrap());
        }

        REQUIRE(alice_keys.size() == 21);
        REQUIRE(bob_keys.size() == 21);

        for (size_t i = 0; i < alice_keys.size(); ++i) {
            for (size_t j = i + 1; j < alice_keys.size(); ++j) {
                REQUIRE(alice_keys[i] != alice_keys[j]);
            }
        }

        for (size_t i = 0; i < bob_keys.size(); ++i) {
            for (size_t j = i + 1; j < bob_keys.size(); ++j) {
                REQUIRE(bob_keys[i] != bob_keys[j]);
            }
        }

        for (size_t i = 0; i < alice_keys.size(); ++i) {
            for (size_t j = 0; j < bob_keys.size(); ++j) {
                if (alice_keys[i] == bob_keys[j]) {
                    INFO(std::format("Alice key {} matches Bob key {} (acceptable when root keys sync)", i, j));
                }
            }
        }
    }
}

TEST_CASE("Metadata Key Rotation - Key Derivation Independence", "[security][metadata_rotation][derivation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Metadata keys derived independently from message keys") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x11);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        auto metadata_key_before = alice->GetMetadataEncryptionKey().Unwrap();

        std::vector<std::vector<uint8_t>> message_keys;
        for (uint32_t i = 0; i < 50; ++i) {
            auto prepare = alice->PrepareNextSendMessage();
            REQUIRE(prepare.IsOk());
            auto [key, include_dh] = std::move(prepare).Unwrap();

            std::vector<uint8_t> key_material;
            auto extract_result = key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> k) {
                    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(
                        std::vector<uint8_t>(k.begin(), k.end()));
                }
            );
            REQUIRE(extract_result.IsOk());
            message_keys.push_back(std::move(extract_result).Unwrap());

            REQUIRE(bob->ProcessReceivedMessage(i).IsOk());
        }

        auto metadata_key_after = alice->GetMetadataEncryptionKey().Unwrap();
        REQUIRE(metadata_key_before == metadata_key_after);

        for (const auto& msg_key : message_keys) {
            REQUIRE(msg_key != metadata_key_before);
            REQUIRE(msg_key != metadata_key_after);
        }

        for (size_t i = 0; i < message_keys.size(); ++i) {
            for (size_t j = i + 1; j < message_keys.size(); ++j) {
                REQUIRE(message_keys[i] != message_keys[j]);
            }
        }
    }
}

TEST_CASE("Metadata Key Rotation - Cross-Connection Independence", "[security][metadata_rotation][isolation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Different connections produce different metadata keys") {
        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x22);

        auto conn1_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn1_result.IsOk());
        auto conn1 = std::move(conn1_result).Unwrap();

        auto conn2_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(conn2_result.IsOk());
        auto conn2 = std::move(conn2_result).Unwrap();

        auto conn1_peer = SodiumInterop::GenerateX25519KeyPair("peer1");
        REQUIRE(conn1_peer.IsOk());
        auto [peer1_sk, peer1_pk] = std::move(conn1_peer).Unwrap();

        auto conn2_peer = SodiumInterop::GenerateX25519KeyPair("peer2");
        REQUIRE(conn2_peer.IsOk());
        auto [peer2_sk, peer2_pk] = std::move(conn2_peer).Unwrap();

        REQUIRE(conn1->FinalizeChainAndDhKeys(root_key, peer1_pk).IsOk());
        REQUIRE(conn2->FinalizeChainAndDhKeys(root_key, peer2_pk).IsOk());

        auto key1 = conn1->GetMetadataEncryptionKey().Unwrap();
        auto key2 = conn2->GetMetadataEncryptionKey().Unwrap();

        REQUIRE(key1 != key2);

        for (uint32_t i = 0; i < 10; ++i) {
            auto prepare1 = conn1->PrepareNextSendMessage();
            auto prepare2 = conn2->PrepareNextSendMessage();
            REQUIRE(prepare1.IsOk());
            REQUIRE(prepare2.IsOk());
        }

        auto key1_after = conn1->GetMetadataEncryptionKey().Unwrap();
        auto key2_after = conn2->GetMetadataEncryptionKey().Unwrap();

        REQUIRE(key1_after != key2_after);
        REQUIRE(key1_after != key2);
        REQUIRE(key2_after != key1);
    }
}
