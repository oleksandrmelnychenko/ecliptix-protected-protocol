#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/utilities/envelope_builder.hpp"
#include "ecliptix/core/constants.hpp"
#include "common/secure_envelope.pb.h"
#include <vector>
#include <unordered_set>
#include <string>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::utilities;
using namespace ecliptix::proto::common;

static std::vector<uint8_t> MakeBoundNonce(uint32_t index, uint8_t fill = 0x42) {
    std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE, fill);
    for (size_t i = 0; i < 4; ++i) {
        nonce[8 + i] = static_cast<uint8_t>((index >> (i * 8)) & 0xFF);
    }
    return nonce;
}

struct AttackTestContext {
    std::unique_ptr<EcliptixProtocolConnection> alice;
    std::unique_ptr<EcliptixProtocolConnection> bob;
    std::vector<uint8_t> alice_metadata_key;
    std::vector<uint8_t> bob_metadata_key;

    [[nodiscard]] static Result<AttackTestContext, EcliptixProtocolFailure> Create() {
        AttackTestContext ctx;

        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        if (alice_result.IsErr()) {
            return Result<AttackTestContext, EcliptixProtocolFailure>::Err(
                std::move(alice_result).UnwrapErr());
        }
        ctx.alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        if (bob_result.IsErr()) {
            return Result<AttackTestContext, EcliptixProtocolFailure>::Err(
                std::move(bob_result).UnwrapErr());
        }
        ctx.bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAB);

        auto alice_dh_result = ctx.alice->GetCurrentSenderDhPublicKey();
        if (alice_dh_result.IsErr()) {
            return Result<AttackTestContext, EcliptixProtocolFailure>::Err(
                std::move(alice_dh_result).UnwrapErr());
        }
        auto alice_dh = std::move(alice_dh_result).Unwrap().value();

        auto bob_dh_result = ctx.bob->GetCurrentSenderDhPublicKey();
        if (bob_dh_result.IsErr()) {
            return Result<AttackTestContext, EcliptixProtocolFailure>::Err(
                std::move(bob_dh_result).UnwrapErr());
        }
        auto bob_dh = std::move(bob_dh_result).Unwrap().value();

        auto alice_finalize = ctx.alice->FinalizeChainAndDhKeys(root_key, bob_dh);
        if (alice_finalize.IsErr()) {
            return Result<AttackTestContext, EcliptixProtocolFailure>::Err(
                std::move(alice_finalize).UnwrapErr());
        }

        auto bob_finalize = ctx.bob->FinalizeChainAndDhKeys(root_key, alice_dh);
        if (bob_finalize.IsErr()) {
            return Result<AttackTestContext, EcliptixProtocolFailure>::Err(
                std::move(bob_finalize).UnwrapErr());
        }

        auto alice_key_result = ctx.alice->GetMetadataEncryptionKey();
        if (alice_key_result.IsErr()) {
            return Result<AttackTestContext, EcliptixProtocolFailure>::Err(
                std::move(alice_key_result).UnwrapErr());
        }
        ctx.alice_metadata_key = std::move(alice_key_result).Unwrap();

        auto bob_key_result = ctx.bob->GetMetadataEncryptionKey();
        if (bob_key_result.IsErr()) {
            return Result<AttackTestContext, EcliptixProtocolFailure>::Err(
                std::move(bob_key_result).UnwrapErr());
        }
        ctx.bob_metadata_key = std::move(bob_key_result).Unwrap();

        return Result<AttackTestContext, EcliptixProtocolFailure>::Ok(std::move(ctx));
    }
};

TEST_CASE("Attacks - Metadata Tampering Detection", "[attacks][envelope][tampering]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Detect tampering in 1000 encrypted metadata blocks") {
        auto ctx_result = AttackTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        constexpr uint32_t TAMPER_ATTEMPTS = 1000;
        uint32_t detected_tampers = 0;

        for (uint32_t i = 0; i < TAMPER_ATTEMPTS; ++i) {
            auto nonce_result = ctx.alice->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                i,
                nonce,
                i * 2,
                {},
                static_cast<EnvelopeType>(0),
                "test-correlation"
            );

            std::vector<uint8_t> header_nonce(12, static_cast<uint8_t>(i & 0xFF));
            std::vector<uint8_t> aad{0xAA, 0xBB};

            auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                metadata,
                ctx.alice_metadata_key,
                header_nonce,
                aad
            );
            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            if (encrypted.size() > 10) {
                const size_t tamper_position = i % (encrypted.size() - 1);
                encrypted[tamper_position] ^= 0xFF;
            }

            auto decrypted_result = EnvelopeBuilder::DecryptMetadata(
                encrypted,
                ctx.bob_metadata_key,
                header_nonce,
                aad
            );

            if (decrypted_result.IsErr()) {
                ++detected_tampers;
            }
        }

        REQUIRE(detected_tampers == TAMPER_ATTEMPTS);
    }

    SECTION("Detect AAD manipulation in 1000 attempts") {
        auto ctx_result = AttackTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        constexpr uint32_t AAD_ATTACK_ATTEMPTS = 1000;
        uint32_t detected_aad_attacks = 0;

        for (uint32_t i = 0; i < AAD_ATTACK_ATTEMPTS; ++i) {
            auto nonce_result = ctx.alice->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                i,
                nonce,
                i,
                {},
                static_cast<EnvelopeType>(1),
                ""
            );

            std::vector<uint8_t> header_nonce(12, 0x42);
            std::vector<uint8_t> original_aad{0x01, 0x02, 0x03};

            auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                metadata,
                ctx.alice_metadata_key,
                header_nonce,
                original_aad
            );
            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            std::vector<uint8_t> tampered_aad{0x04, 0x05, 0x06};

            auto decrypted_result = EnvelopeBuilder::DecryptMetadata(
                encrypted,
                ctx.bob_metadata_key,
                header_nonce,
                tampered_aad
            );

            if (decrypted_result.IsErr()) {
                ++detected_aad_attacks;
            }
        }

        REQUIRE(detected_aad_attacks == AAD_ATTACK_ATTEMPTS);
    }
}

TEST_CASE("Attacks - Envelope Replay Protection", "[attacks][envelope][replay]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Detect 1000 replay attempts with same nonce") {
        auto ctx_result = AttackTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        auto alice_prepare = ctx.alice->PrepareNextSendMessage();
        REQUIRE(alice_prepare.IsOk());
        auto [alice_key, include_dh] = std::move(alice_prepare).Unwrap();

        auto nonce_result = ctx.alice->GenerateNextNonce();
        REQUIRE(nonce_result.IsOk());
        auto nonce = std::move(nonce_result).Unwrap();

        const std::vector<uint8_t> plaintext{0xDE, 0xAD, 0xBE, 0xEF};

        auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
            [&](std::span<const uint8_t> key) {
                return AesGcm::Encrypt(key, nonce, plaintext, {});
            }
        );
        REQUIRE(encrypted_result.IsOk());
        auto encrypted = std::move(encrypted_result).Unwrap();

        auto first_check = ctx.bob->CheckReplayProtection(nonce, 1);
        REQUIRE(first_check.IsOk());

        constexpr uint32_t REPLAY_ATTEMPTS = 1000;
        uint32_t detected_replays = 0;

        for (uint32_t i = 0; i < REPLAY_ATTEMPTS; ++i) {
            auto replay_check = ctx.bob->CheckReplayProtection(nonce, 1);
            if (replay_check.IsErr()) {
                ++detected_replays;
            }
        }

        REQUIRE(detected_replays == REPLAY_ATTEMPTS);
    }

    SECTION("Block message index reuse across 5000 attempts") {
        auto ctx_result = AttackTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        constexpr uint32_t MESSAGE_COUNT = 5000;
        std::unordered_set<uint32_t> processed_indices;
        uint32_t successful_first_process = 0;
        uint32_t blocked_reuse_attempts = 0;

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            const uint32_t msg_index = i % 1000;
            std::vector<uint8_t> nonce = MakeBoundNonce(msg_index, static_cast<uint8_t>(msg_index & 0xFF));

            if (processed_indices.find(msg_index) == processed_indices.end()) {
                auto bob_key = ctx.bob->ProcessReceivedMessage(msg_index, nonce);
                if (bob_key.IsOk()) {
                    ++successful_first_process;
                    processed_indices.insert(msg_index);
                }
            } else {
                auto bob_key_reuse = ctx.bob->ProcessReceivedMessage(msg_index, nonce);
                if (bob_key_reuse.IsErr()) {
                    ++blocked_reuse_attempts;
                }
            }
        }

        REQUIRE(successful_first_process > 0);
        REQUIRE(blocked_reuse_attempts == (MESSAGE_COUNT - successful_first_process));
    }
}

TEST_CASE("Attacks - Nonce Reuse Scenarios", "[attacks][envelope][nonce]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Force nonce collision detection across 1000 messages") {
        auto ctx_result = AttackTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        std::vector<uint8_t> fixed_nonce(12, 0x42);

        constexpr uint32_t COLLISION_ATTEMPTS = 1000;
        uint32_t detected_collisions = 0;

        for (uint32_t i = 0; i < COLLISION_ATTEMPTS; ++i) {
            auto check_result = ctx.alice->CheckReplayProtection(fixed_nonce, i);
            if (check_result.IsErr()) {
                ++detected_collisions;
            }
        }

        REQUIRE(detected_collisions > 0);
    }

    SECTION("Verify nonce uniqueness under load - 10000 nonces") {
        auto ctx_result = AttackTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        constexpr uint32_t NONCE_COUNT = 10000;
        std::unordered_set<std::string> nonce_set;
        uint32_t unique_nonces = 0;

        for (uint32_t i = 0; i < NONCE_COUNT; ++i) {
            auto nonce_result = ctx.alice->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            const std::string nonce_str(nonce.begin(), nonce.end());
            if (nonce_set.find(nonce_str) == nonce_set.end()) {
                nonce_set.insert(nonce_str);
                ++unique_nonces;
            }
        }

        REQUIRE(unique_nonces == NONCE_COUNT);
        REQUIRE(nonce_set.size() == NONCE_COUNT);
    }
}

TEST_CASE("Attacks - Payload Truncation and Padding", "[attacks][envelope][truncation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Detect truncated ciphertext in 1000 messages") {
        auto ctx_result = AttackTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        constexpr uint32_t TRUNCATION_ATTEMPTS = 1000;
        uint32_t detected_truncations = 0;

        for (uint32_t i = 0; i < TRUNCATION_ATTEMPTS; ++i) {
            auto alice_prepare = ctx.alice->PrepareNextSendMessage();
            REQUIRE(alice_prepare.IsOk());
            auto [alice_key, include_dh] = std::move(alice_prepare).Unwrap();

            auto nonce_result = ctx.alice->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            const std::vector<uint8_t> plaintext(100, static_cast<uint8_t>(i & 0xFF));

            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, plaintext, {});
                }
            );
            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            if (encrypted.size() > 16) {
                encrypted.resize(encrypted.size() / 2);
            }

            auto bob_key_result = ctx.bob->ProcessReceivedMessage(i, MakeBoundNonce(i, nonce[0]));
            REQUIRE(bob_key_result.IsOk());
            auto bob_key = std::move(bob_key_result).Unwrap();

            auto decrypted_result = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, nonce, encrypted, {});
                }
            );

            if (decrypted_result.IsErr()) {
                ++detected_truncations;
            }
        }

        REQUIRE(detected_truncations == TRUNCATION_ATTEMPTS);
    }

    SECTION("Detect padding oracle attacks - 1000 attempts") {
        auto ctx_result = AttackTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        constexpr uint32_t PADDING_ATTEMPTS = 1000;
        uint32_t detected_padding_attacks = 0;

        for (uint32_t i = 0; i < PADDING_ATTEMPTS; ++i) {
            auto alice_prepare = ctx.alice->PrepareNextSendMessage();
            REQUIRE(alice_prepare.IsOk());
            auto [alice_key, include_dh] = std::move(alice_prepare).Unwrap();

            auto nonce_result = ctx.alice->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            const std::vector<uint8_t> plaintext(50, 0xAA);

            auto encrypted_result = alice_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Encrypt(key, nonce, plaintext, {});
                }
            );
            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            encrypted.push_back(0xFF);
            encrypted.push_back(0xFE);
            encrypted.push_back(0xFD);

            auto bob_key_result = ctx.bob->ProcessReceivedMessage(i, MakeBoundNonce(i, nonce[0]));
            REQUIRE(bob_key_result.IsOk());
            auto bob_key = std::move(bob_key_result).Unwrap();

            auto decrypted_result = bob_key.WithKeyMaterial<std::vector<uint8_t>>(
                [&](std::span<const uint8_t> key) {
                    return AesGcm::Decrypt(key, nonce, encrypted, {});
                }
            );

            if (decrypted_result.IsErr()) {
                ++detected_padding_attacks;
            }
        }

        REQUIRE(detected_padding_attacks == PADDING_ATTEMPTS);
    }
}

TEST_CASE("Attacks - Wrong Key Decryption Attempts", "[attacks][envelope][key-confusion]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Detect wrong metadata key usage in 1000 envelopes") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        auto eve_result = EcliptixProtocolConnection::Create(3, false);
        REQUIRE(eve_result.IsOk());
        auto eve = std::move(eve_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x11);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto eve_dh = eve->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        std::vector<uint8_t> eve_root_key(Constants::X_25519_KEY_SIZE, 0x22);
        REQUIRE(eve->FinalizeChainAndDhKeys(eve_root_key, alice_dh).IsOk());

        auto alice_metadata_key = alice->GetMetadataEncryptionKey().Unwrap();
        auto eve_metadata_key = eve->GetMetadataEncryptionKey().Unwrap();

        constexpr uint32_t WRONG_KEY_ATTEMPTS = 1000;
        uint32_t detected_wrong_keys = 0;

        for (uint32_t i = 0; i < WRONG_KEY_ATTEMPTS; ++i) {
            auto nonce_result = alice->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                i, nonce, i, {}, static_cast<EnvelopeType>(0), "");

            std::vector<uint8_t> header_nonce(12, 0x99);
            std::vector<uint8_t> aad{0xCC};

            auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                metadata, alice_metadata_key, header_nonce, aad);
            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            auto decrypted_result = EnvelopeBuilder::DecryptMetadata(
                encrypted, eve_metadata_key, header_nonce, aad);

            if (decrypted_result.IsErr()) {
                ++detected_wrong_keys;
            }
        }

        REQUIRE(detected_wrong_keys == WRONG_KEY_ATTEMPTS);
    }
}

TEST_CASE("Attacks - Header Nonce Manipulation", "[attacks][envelope][header-nonce]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Detect header nonce mismatch in 1000 envelopes") {
        auto ctx_result = AttackTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        constexpr uint32_t NONCE_MISMATCH_ATTEMPTS = 1000;
        uint32_t detected_mismatches = 0;

        for (uint32_t i = 0; i < NONCE_MISMATCH_ATTEMPTS; ++i) {
            auto nonce_result = ctx.alice->GenerateNextNonce();
            REQUIRE(nonce_result.IsOk());
            auto nonce = std::move(nonce_result).Unwrap();

            const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                i, nonce, i, {}, static_cast<EnvelopeType>(0), "");

            std::vector<uint8_t> correct_header_nonce(12, static_cast<uint8_t>(i & 0xFF));
            std::vector<uint8_t> aad{0xAA};

            auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                metadata, ctx.alice_metadata_key, correct_header_nonce, aad);
            REQUIRE(encrypted_result.IsOk());
            auto encrypted = std::move(encrypted_result).Unwrap();

            std::vector<uint8_t> wrong_header_nonce(12, static_cast<uint8_t>((i + 1) & 0xFF));

            auto decrypted_result = EnvelopeBuilder::DecryptMetadata(
                encrypted, ctx.bob_metadata_key, wrong_header_nonce, aad);

            if (decrypted_result.IsErr()) {
                ++detected_mismatches;
            }
        }

        REQUIRE(detected_mismatches == NONCE_MISMATCH_ATTEMPTS);
    }
}
