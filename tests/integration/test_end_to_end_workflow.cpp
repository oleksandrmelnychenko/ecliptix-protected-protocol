#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/identity/ecliptix_system_identity_keys.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/utilities/envelope_builder.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/configuration/ratchet_config.hpp"
#include "common/secure_envelope.pb.h"
#include <vector>
#include <map>
#include <algorithm>
#include <random>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::identity;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::utilities;
using namespace ecliptix::protocol::configuration;
using namespace ecliptix::proto::common;

struct EndToEndTestContext {
    std::unique_ptr<EcliptixSystemIdentityKeys> alice_identity;
    std::unique_ptr<EcliptixSystemIdentityKeys> bob_identity;
    std::unique_ptr<EcliptixProtocolConnection> alice_connection;
    std::unique_ptr<EcliptixProtocolConnection> bob_connection;
    std::vector<uint8_t> shared_root_key;

    [[nodiscard]] static Result<EndToEndTestContext, EcliptixProtocolFailure> Create() {
        EndToEndTestContext ctx;

        auto alice_id_result = EcliptixSystemIdentityKeys::Create(5);
        if (alice_id_result.IsErr()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                std::move(alice_id_result).UnwrapErr());
        }
        ctx.alice_identity = std::make_unique<EcliptixSystemIdentityKeys>(std::move(alice_id_result).Unwrap());

        auto bob_id_result = EcliptixSystemIdentityKeys::Create(5);
        if (bob_id_result.IsErr()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                std::move(bob_id_result).UnwrapErr());
        }
        ctx.bob_identity = std::make_unique<EcliptixSystemIdentityKeys>(std::move(bob_id_result).Unwrap());

        auto bob_bundle_result = ctx.bob_identity->CreatePublicBundle();
        if (bob_bundle_result.IsErr()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                std::move(bob_bundle_result).UnwrapErr());
        }
        auto bob_bundle = std::move(bob_bundle_result).Unwrap();

        ctx.alice_identity->GenerateEphemeralKeyPair();

        const std::vector<uint8_t> info(
            Constants::X3DH_INFO.begin(),
            Constants::X3DH_INFO.end());

        auto shared_secret_result = ctx.alice_identity->X3dhDeriveSharedSecret(bob_bundle, info);
        if (shared_secret_result.IsErr()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                std::move(shared_secret_result).UnwrapErr());
        }
        auto shared_secret = std::move(shared_secret_result).Unwrap();
        auto root_key_result = shared_secret.ReadBytes(shared_secret.Size());
        if (root_key_result.IsErr()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    std::format("Failed to read shared secret: {}",
                        root_key_result.UnwrapErr().message)));
        }
        ctx.shared_root_key = std::move(root_key_result).Unwrap();

        auto alice_conn_result = EcliptixProtocolConnection::Create(1, true);
        if (alice_conn_result.IsErr()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                std::move(alice_conn_result).UnwrapErr());
        }
        ctx.alice_connection = std::move(alice_conn_result).Unwrap();

        auto bob_conn_result = EcliptixProtocolConnection::Create(2, false);
        if (bob_conn_result.IsErr()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                std::move(bob_conn_result).UnwrapErr());
        }
        ctx.bob_connection = std::move(bob_conn_result).Unwrap();

        auto alice_dh_result = ctx.alice_connection->GetCurrentSenderDhPublicKey();
        if (alice_dh_result.IsErr()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                std::move(alice_dh_result).UnwrapErr());
        }
        auto alice_dh_opt = std::move(alice_dh_result).Unwrap();
        if (!alice_dh_opt.has_value()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Alice DH key not available"));
        }
        auto alice_dh = std::move(alice_dh_opt).value();

        auto bob_dh_result = ctx.bob_connection->GetCurrentSenderDhPublicKey();
        if (bob_dh_result.IsErr()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                std::move(bob_dh_result).UnwrapErr());
        }
        auto bob_dh_opt = std::move(bob_dh_result).Unwrap();
        if (!bob_dh_opt.has_value()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Bob DH key not available"));
        }
        auto bob_dh = std::move(bob_dh_opt).value();

        auto alice_finalize_result = ctx.alice_connection->FinalizeChainAndDhKeys(
            ctx.shared_root_key, bob_dh);
        if (alice_finalize_result.IsErr()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                std::move(alice_finalize_result).UnwrapErr());
        }

        auto bob_finalize_result = ctx.bob_connection->FinalizeChainAndDhKeys(
            ctx.shared_root_key, alice_dh);
        if (bob_finalize_result.IsErr()) {
            return Result<EndToEndTestContext, EcliptixProtocolFailure>::Err(
                std::move(bob_finalize_result).UnwrapErr());
        }

        return Result<EndToEndTestContext, EcliptixProtocolFailure>::Ok(std::move(ctx));
    }
};

TEST_CASE("Integration - Complete X3DH to Envelope Flow", "[integration][envelope]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Full workflow: X3DH → Connection → Envelope → Encryption → Decryption") {
        auto ctx_result = EndToEndTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        auto alice_prepare_result = ctx.alice_connection->PrepareNextSendMessage();
        REQUIRE(alice_prepare_result.IsOk());
        auto [alice_chain_key, include_dh] = std::move(alice_prepare_result).Unwrap();

        auto alice_nonce_result = ctx.alice_connection->GenerateNextNonce();
        REQUIRE(alice_nonce_result.IsOk());
        auto alice_nonce = std::move(alice_nonce_result).Unwrap();

        auto alice_metadata_key_result = ctx.alice_connection->GetMetadataEncryptionKey();
        REQUIRE(alice_metadata_key_result.IsOk());
        auto alice_metadata_key = std::move(alice_metadata_key_result).Unwrap();

        const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
            1,
            alice_nonce,
            alice_chain_key.Index(),
            {},
            static_cast<EnvelopeType>(0),
            "test-correlation-123"
        );

        std::vector<uint8_t> header_nonce(12, 0x01);
        std::vector<uint8_t> associated_data{0xAA, 0xBB, 0xCC};

        auto encrypted_metadata_result = EnvelopeBuilder::EncryptMetadata(
            metadata,
            alice_metadata_key,
            header_nonce,
            associated_data
        );
        REQUIRE(encrypted_metadata_result.IsOk());
        auto encrypted_metadata = std::move(encrypted_metadata_result).Unwrap();

        const std::vector<uint8_t> plaintext_payload{0x01, 0x02, 0x03, 0x04, 0x05};

        auto encrypted_payload_result = alice_chain_key.WithKeyMaterial<std::vector<uint8_t>>(
            [&](std::span<const uint8_t> key_material) {
                return AesGcm::Encrypt(
                    key_material,
                    alice_nonce,
                    plaintext_payload,
                    associated_data
                );
            }
        );
        REQUIRE(encrypted_payload_result.IsOk());
        auto encrypted_payload = std::move(encrypted_payload_result).Unwrap();

        auto bob_metadata_key_result = ctx.bob_connection->GetMetadataEncryptionKey();
        REQUIRE(bob_metadata_key_result.IsOk());
        auto bob_metadata_key = std::move(bob_metadata_key_result).Unwrap();

        auto decrypted_metadata_result = EnvelopeBuilder::DecryptMetadata(
            encrypted_metadata,
            bob_metadata_key,
            header_nonce,
            associated_data
        );
        REQUIRE(decrypted_metadata_result.IsOk());
        auto decrypted_metadata = std::move(decrypted_metadata_result).Unwrap();

        REQUIRE(decrypted_metadata.envelope_id() == "1");
        REQUIRE(decrypted_metadata.ratchet_index() == alice_chain_key.Index());
        REQUIRE(decrypted_metadata.correlation_id() == "test-correlation-123");

        auto bob_chain_key_result = ctx.bob_connection->ProcessReceivedMessage(
            decrypted_metadata.ratchet_index() - 1
        );
        REQUIRE(bob_chain_key_result.IsOk());
        auto bob_chain_key = std::move(bob_chain_key_result).Unwrap();

        auto decrypted_payload_result = bob_chain_key.WithKeyMaterial<std::vector<uint8_t>>(
            [&](std::span<const uint8_t> key_material) {
                return AesGcm::Decrypt(
                    key_material,
                    alice_nonce,
                    encrypted_payload,
                    associated_data
                );
            }
        );
        REQUIRE(decrypted_payload_result.IsOk());
        auto decrypted_payload = std::move(decrypted_payload_result).Unwrap();

        REQUIRE(decrypted_payload == plaintext_payload);
    }
}

TEST_CASE("Integration - High-Volume Message Exchange", "[integration][envelope][stress]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("10,000 sequential messages from Alice to Bob") {
        auto ctx_result = EndToEndTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        constexpr uint32_t MESSAGE_COUNT = 10000;
        uint32_t successful_roundtrips = 0;

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            auto alice_prepare_result = ctx.alice_connection->PrepareNextSendMessage();
            if (alice_prepare_result.IsErr()) break;
            auto [alice_key, include_dh] = std::move(alice_prepare_result).Unwrap();

            auto alice_nonce_result = ctx.alice_connection->GenerateNextNonce();
            if (alice_nonce_result.IsErr()) break;
            auto alice_nonce = std::move(alice_nonce_result).Unwrap();

            const std::vector<uint8_t> plaintext{
                static_cast<uint8_t>(i & 0xFF),
                static_cast<uint8_t>((i >> 8) & 0xFF),
                static_cast<uint8_t>((i >> 16) & 0xFF),
                static_cast<uint8_t>((i >> 24) & 0xFF)
            };

            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key_material) {
                    return AesGcm::Encrypt(key_material, alice_nonce, plaintext, {});
                }
            );
            if (encrypted_result.IsErr()) break;
            auto encrypted = std::move(encrypted_result).Unwrap();

            auto bob_key_result = ctx.bob_connection->ProcessReceivedMessage(i);
            if (bob_key_result.IsErr()) break;
            auto bob_key = std::move(bob_key_result).Unwrap();

            auto decrypted_result = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key_material) {
                    return AesGcm::Decrypt(key_material, alice_nonce, encrypted, {});
                }
            );
            if (decrypted_result.IsErr()) break;
            auto decrypted = std::move(decrypted_result).Unwrap();

            if (decrypted == plaintext) {
                ++successful_roundtrips;
            }
        }

        REQUIRE(successful_roundtrips == MESSAGE_COUNT);
    }
}

TEST_CASE("Integration - Bidirectional Communication with DH Ratcheting", "[integration][envelope][ratchet]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("1000 bidirectional round-trips with automatic DH ratchet") {
        RatchetConfig config(100);

        auto alice_conn_result = EcliptixProtocolConnection::Create(1, true, config);
        REQUIRE(alice_conn_result.IsOk());
        auto alice_connection = std::move(alice_conn_result).Unwrap();

        auto bob_conn_result = EcliptixProtocolConnection::Create(2, false, config);
        REQUIRE(bob_conn_result.IsOk());
        auto bob_connection = std::move(bob_conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAB);

        auto alice_dh_result = alice_connection->GetCurrentSenderDhPublicKey();
        REQUIRE(alice_dh_result.IsOk());
        auto alice_dh = std::move(alice_dh_result).Unwrap().value();

        auto bob_dh_result = bob_connection->GetCurrentSenderDhPublicKey();
        REQUIRE(bob_dh_result.IsOk());
        auto bob_dh = std::move(bob_dh_result).Unwrap().value();

        auto alice_finalize = alice_connection->FinalizeChainAndDhKeys(root_key, bob_dh);
        REQUIRE(alice_finalize.IsOk());

        auto bob_finalize = bob_connection->FinalizeChainAndDhKeys(root_key, alice_dh);
        REQUIRE(bob_finalize.IsOk());

        constexpr uint32_t ROUND_TRIP_COUNT = 1000;
        uint32_t successful_alice_to_bob = 0;
        uint32_t successful_bob_to_alice = 0;

        for (uint32_t round = 0; round < ROUND_TRIP_COUNT; ++round) {
            auto alice_prepare = alice_connection->PrepareNextSendMessage();
            if (alice_prepare.IsErr()) break;
            auto [alice_key, alice_include_dh] = std::move(alice_prepare).Unwrap();

            auto alice_nonce = alice_connection->GenerateNextNonce();
            if (alice_nonce.IsErr()) break;
            auto a_nonce = std::move(alice_nonce).Unwrap();

            const std::vector<uint8_t> alice_plaintext{0xA1, 0xA2, static_cast<uint8_t>(round & 0xFF)};

            auto alice_encrypted = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, a_nonce, alice_plaintext, {});
                }
            );
            if (alice_encrypted.IsErr()) break;

            auto bob_process = bob_connection->ProcessReceivedMessage(round);
            if (bob_process.IsErr()) break;
            auto bob_key = std::move(bob_process).Unwrap();

            auto bob_decrypted = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, a_nonce, alice_encrypted.Unwrap(), {});
                }
            );
            if (bob_decrypted.IsOk() && bob_decrypted.Unwrap() == alice_plaintext) {
                ++successful_alice_to_bob;
            }

            auto bob_prepare = bob_connection->PrepareNextSendMessage();
            if (bob_prepare.IsErr()) break;
            auto [bob_send_key, bob_include_dh] = std::move(bob_prepare).Unwrap();

            auto bob_nonce = bob_connection->GenerateNextNonce();
            if (bob_nonce.IsErr()) break;
            auto b_nonce = std::move(bob_nonce).Unwrap();

            const std::vector<uint8_t> bob_plaintext{0xB1, 0xB2, static_cast<uint8_t>(round & 0xFF)};

            auto bob_encrypted = bob_send_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, b_nonce, bob_plaintext, {});
                }
            );
            if (bob_encrypted.IsErr()) break;

            auto alice_process = alice_connection->ProcessReceivedMessage(round);
            if (alice_process.IsErr()) break;
            auto alice_recv_key = std::move(alice_process).Unwrap();

            auto alice_decrypted = alice_recv_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, b_nonce, bob_encrypted.Unwrap(), {});
                }
            );
            if (alice_decrypted.IsOk() && alice_decrypted.Unwrap() == bob_plaintext) {
                ++successful_bob_to_alice;
            }
        }

        REQUIRE(successful_alice_to_bob == ROUND_TRIP_COUNT);
        REQUIRE(successful_bob_to_alice == ROUND_TRIP_COUNT);
    }
}

TEST_CASE("Integration - Out-of-Order Message Delivery", "[integration][envelope][out-of-order]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Process 1000 messages in random order") {
        auto ctx_result = EndToEndTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        constexpr uint32_t MESSAGE_COUNT = 1000;

        struct MessagePacket {
            uint32_t index;
            std::vector<uint8_t> nonce;
            std::vector<uint8_t> encrypted_data;
            std::vector<uint8_t> expected_plaintext;
        };

        std::vector<MessagePacket> messages;
        messages.reserve(MESSAGE_COUNT);

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            auto prepare_result = ctx.alice_connection->PrepareNextSendMessage();
            REQUIRE(prepare_result.IsOk());
            auto [chain_key, include_dh] = std::move(prepare_result).Unwrap();

            auto nonce_result = ctx.alice_connection->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            const std::vector<uint8_t> plaintext{
                0xDE, 0xAD, 0xBE, 0xEF,
                static_cast<uint8_t>(i & 0xFF),
                static_cast<uint8_t>((i >> 8) & 0xFF)
            };

            auto encrypted_result = chain_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, plaintext, {});
                }
            );
            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            messages.push_back(MessagePacket{
                i,
                nonce,
                encrypted,
                plaintext
            });
        }

        std::random_device rd;
        std::mt19937 gen(42);
        std::shuffle(messages.begin(), messages.end(), gen);

        uint32_t successful_decryptions = 0;

        for (const auto& msg : messages) {
            auto bob_key_result = ctx.bob_connection->ProcessReceivedMessage(msg.index);
            if (bob_key_result.IsErr()) {
                continue;
            }
            auto bob_key = std::move(bob_key_result).Unwrap();

            auto decrypted_result = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, msg.nonce, msg.encrypted_data, {});
                }
            );

            if (decrypted_result.IsOk()) {
                auto decrypted = std::move(decrypted_result).Unwrap();
                if (decrypted == msg.expected_plaintext) {
                    ++successful_decryptions;
                }
            }
        }

        REQUIRE(successful_decryptions == MESSAGE_COUNT);
    }
}

TEST_CASE("Integration - Envelope Metadata Integrity Across Multiple Messages", "[integration][envelope]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Verify metadata encryption/decryption for 5000 envelopes") {
        auto ctx_result = EndToEndTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        auto alice_metadata_key_result = ctx.alice_connection->GetMetadataEncryptionKey();
        REQUIRE(alice_metadata_key_result.IsOk());
        auto alice_metadata_key = std::move(alice_metadata_key_result).Unwrap();

        auto bob_metadata_key_result = ctx.bob_connection->GetMetadataEncryptionKey();
        REQUIRE(bob_metadata_key_result.IsOk());
        auto bob_metadata_key = std::move(bob_metadata_key_result).Unwrap();

        constexpr uint32_t ENVELOPE_COUNT = 5000;
        uint32_t successful_metadata_roundtrips = 0;

        for (uint32_t i = 0; i < ENVELOPE_COUNT; ++i) {
            auto nonce_result = ctx.alice_connection->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            const std::string correlation_id = "corr-" + std::to_string(i);

            const EnvelopeMetadata original_metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                i,
                nonce,
                i * 2,
                {},
                static_cast<EnvelopeType>(i % 3),
                correlation_id
            );

            std::vector<uint8_t> header_nonce(12, static_cast<uint8_t>(i & 0xFF));
            std::vector<uint8_t> aad{0xAA, static_cast<uint8_t>(i & 0xFF)};

            auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                original_metadata,
                alice_metadata_key,
                header_nonce,
                aad
            );
            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            auto decrypted_result = EnvelopeBuilder::DecryptMetadata(
                encrypted,
                bob_metadata_key,
                header_nonce,
                aad
            );
            REQUIRE(decrypted_result.IsOk());
            auto decrypted = std::move(decrypted_result).Unwrap();

            if (decrypted.envelope_id() == std::to_string(i) &&
                decrypted.ratchet_index() == i * 2 &&
                decrypted.envelope_type() == static_cast<EnvelopeType>(i % 3) &&
                decrypted.correlation_id() == correlation_id) {
                ++successful_metadata_roundtrips;
            }
        }

        REQUIRE(successful_metadata_roundtrips == ENVELOPE_COUNT);
    }
}

TEST_CASE("Integration - Large Payload Encryption with Envelopes", "[integration][envelope][payload]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Encrypt and decrypt 1MB payloads across 100 messages") {
        auto ctx_result = EndToEndTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        constexpr size_t PAYLOAD_SIZE = 1024 * 1024;
        constexpr uint32_t MESSAGE_COUNT = 100;
        uint32_t successful_transfers = 0;

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            std::vector<uint8_t> large_payload(PAYLOAD_SIZE);
            for (size_t j = 0; j < PAYLOAD_SIZE; ++j) {
                large_payload[j] = static_cast<uint8_t>((i + j) & 0xFF);
            }

            auto alice_prepare = ctx.alice_connection->PrepareNextSendMessage();
            REQUIRE(alice_prepare.IsOk());
            auto [alice_key, include_dh] = std::move(alice_prepare).Unwrap();

            auto nonce_result = ctx.alice_connection->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, large_payload, {});
                }
            );
            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            auto bob_key_result = ctx.bob_connection->ProcessReceivedMessage(i);
            REQUIRE(bob_key_result.IsOk());
            auto bob_key = std::move(bob_key_result).Unwrap();

            auto decrypted_result = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, nonce, encrypted, {});
                }
            );
            REQUIRE(decrypted_result.IsOk());
            auto decrypted = std::move(decrypted_result).Unwrap();

            if (decrypted == large_payload) {
                ++successful_transfers;
            }
        }

        REQUIRE(successful_transfers == MESSAGE_COUNT);
    }
}
