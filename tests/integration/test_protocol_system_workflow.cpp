#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/protocol_system.hpp"
#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include "protocol/key_exchange.pb.h"
#include <vector>
#include <string>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::identity;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::models;
using ecliptix::proto::protocol::PublicKeyBundle;

namespace {
    PublicKeyBundle ToProtoBundle(const LocalPublicKeyBundle& bundle) {
        PublicKeyBundle proto_bundle;
        proto_bundle.set_identity_public_key(bundle.GetEd25519Public().data(),
                                             bundle.GetEd25519Public().size());
        proto_bundle.set_identity_x25519_public_key(bundle.GetIdentityX25519().data(),
                                                    bundle.GetIdentityX25519().size());
        proto_bundle.set_signed_pre_key_id(bundle.GetSignedPreKeyId());
        proto_bundle.set_signed_pre_key_public_key(bundle.GetSignedPreKeyPublic().data(),
                                                   bundle.GetSignedPreKeyPublic().size());
        proto_bundle.set_signed_pre_key_signature(bundle.GetSignedPreKeySignature().data(),
                                                  bundle.GetSignedPreKeySignature().size());
        for (const auto& otp : bundle.GetOneTimePreKeys()) {
            auto* otp_proto = proto_bundle.add_one_time_pre_keys();
            otp_proto->set_pre_key_id(otp.GetPreKeyId());
            otp_proto->set_public_key(otp.GetPublicKey().data(), otp.GetPublicKey().size());
        }
        if (bundle.HasEphemeralKey()) {
            proto_bundle.set_ephemeral_x25519_public_key(bundle.GetEphemeralX25519Public()->data(),
                                                         bundle.GetEphemeralX25519Public()->size());
        }
        if (bundle.HasKyberKey()) {
            proto_bundle.set_kyber_public_key(bundle.GetKyberPublicKey()->data(),
                                              bundle.GetKyberPublicKey()->size());
        }
        if (bundle.HasKyberCiphertext()) {
            proto_bundle.set_kyber_ciphertext(bundle.GetKyberCiphertext()->data(),
                                              bundle.GetKyberCiphertext()->size());
        }
        return proto_bundle;
    }

    struct ProtocolSystemTestContext {
        std::unique_ptr<ProtocolSystem> alice;
        std::unique_ptr<ProtocolSystem> bob;

        [[nodiscard]] static Result<ProtocolSystemTestContext, ProtocolFailure> Create() {
            ProtocolSystemTestContext ctx;

            auto alice_id_result = IdentityKeys::Create(5);
            if (alice_id_result.IsErr()) {
                return Result<ProtocolSystemTestContext, ProtocolFailure>::Err(
                    std::move(alice_id_result).UnwrapErr());
            }
            auto alice_identity = std::make_unique<IdentityKeys>(
                std::move(alice_id_result).Unwrap());

            auto bob_id_result = IdentityKeys::Create(5);
            if (bob_id_result.IsErr()) {
                return Result<ProtocolSystemTestContext, ProtocolFailure>::Err(
                    std::move(bob_id_result).UnwrapErr());
            }
            auto bob_identity = std::make_unique<IdentityKeys>(
                std::move(bob_id_result).Unwrap());

            auto alice_system_result = ProtocolSystem::Create(std::move(alice_identity));
            if (alice_system_result.IsErr()) {
                return Result<ProtocolSystemTestContext, ProtocolFailure>::Err(
                    std::move(alice_system_result).UnwrapErr());
            }
            ctx.alice = std::move(alice_system_result).Unwrap();

            auto bob_system_result = ProtocolSystem::Create(std::move(bob_identity));
            if (bob_system_result.IsErr()) {
                return Result<ProtocolSystemTestContext, ProtocolFailure>::Err(
                    std::move(bob_system_result).UnwrapErr());
            }
            ctx.bob = std::move(bob_system_result).Unwrap();

            return Result<ProtocolSystemTestContext, ProtocolFailure>::Ok(std::move(ctx));
        }

        [[nodiscard]] Result<Unit, ProtocolFailure> PerformHandshake() {
            auto bob_bundle_result = bob->GetIdentityKeys().CreatePublicBundle();
            if (bob_bundle_result.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    std::move(bob_bundle_result).UnwrapErr());
            }
            auto bob_bundle = std::move(bob_bundle_result).Unwrap();

            alice->GetIdentityKeysMutable().GenerateEphemeralKeyPair();

            auto alice_bundle_result = alice->GetIdentityKeys().CreatePublicBundle();
            if (alice_bundle_result.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    std::move(alice_bundle_result).UnwrapErr());
            }
            auto alice_bundle = std::move(alice_bundle_result).Unwrap();

            const std::vector<uint8_t> info(
                Constants::X3DH_INFO.begin(),
                Constants::X3DH_INFO.end());

            auto alice_ek_public = alice->GetIdentityKeys().GetEphemeralX25519PublicKeyCopy();
            if (!alice_ek_public.has_value()) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::Generic("Alice ephemeral key not available"));
            }
            auto alice_ek_private_result = alice->GetIdentityKeys().GetEphemeralX25519PrivateKeyCopy();
            if (alice_ek_private_result.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    alice_ek_private_result.UnwrapErr());
            }
            auto alice_ek_private = alice_ek_private_result.Unwrap();

            auto bob_spk_public = bob->GetIdentityKeys().GetSignedPreKeyPublicCopy();
            auto bob_spk_private_result = bob->GetIdentityKeys().GetSignedPreKeyPrivateCopy();
            if (bob_spk_private_result.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    bob_spk_private_result.UnwrapErr());
            }
            auto bob_spk_private = bob_spk_private_result.Unwrap();

            alice->SetPendingInitiator(true);
            auto alice_shared_result = alice->GetIdentityKeysMutable().X3dhDeriveSharedSecret(
                bob_bundle, info, true);
            if (alice_shared_result.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    std::move(alice_shared_result).UnwrapErr());
            }
            auto alice_shared = std::move(alice_shared_result).Unwrap();

            auto alice_root_result = alice_shared.ReadBytes(alice_shared.Size());
            if (alice_root_result.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::Generic("Failed to read Alice shared secret"));
            }
            auto alice_root_key = std::move(alice_root_result).Unwrap();

            auto alice_kyber_result = alice->GetIdentityKeysMutable().ConsumePendingKyberHandshake();
            if (alice_kyber_result.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    alice_kyber_result.UnwrapErr());
            }
            auto alice_kyber = std::move(alice_kyber_result).Unwrap();

            bob->SetPendingInitiator(false);
            auto bob_decap_result = bob->GetIdentityKeysMutable().DecapsulateKyberCiphertext(
                alice_kyber.kyber_ciphertext);
            if (bob_decap_result.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    bob_decap_result.UnwrapErr());
            }
            auto bob_kyber = bob_decap_result.Unwrap();

            if (bob_kyber.kyber_shared_secret != alice_kyber.kyber_shared_secret) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::Generic("Kyber shared secret mismatch"));
            }

            auto alice_finalize = alice->FinalizeWithRootAndPeerBundle(
                alice_root_key,
                ToProtoBundle(bob_bundle),
                alice->ConsumePendingInitiator().value_or(true),
                alice_kyber.kyber_ciphertext,
                alice_kyber.kyber_shared_secret,
                alice_ek_public.value(),
                alice_ek_private);
            if (alice_finalize.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    std::move(alice_finalize).UnwrapErr());
            }

            auto bob_finalize = bob->FinalizeWithRootAndPeerBundle(
                alice_root_key,
                ToProtoBundle(alice_bundle),
                bob->ConsumePendingInitiator().value_or(false),
                alice_kyber.kyber_ciphertext,
                alice_kyber.kyber_shared_secret,
                bob_spk_public,
                bob_spk_private);
            if (bob_finalize.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    std::move(bob_finalize).UnwrapErr());
            }

            return Result<Unit, ProtocolFailure>::Ok(Unit{});
        }
    };
}

TEST_CASE("Protocol System - Full Handshake and Message Exchange", "[protocol-system][integration][handshake]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Complete handshake and exchange bidirectional messages") {
        auto ctx_result = ProtocolSystemTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        auto handshake_result = ctx.PerformHandshake();
        if (handshake_result.IsErr()) {
            FAIL("Handshake failed: " + handshake_result.UnwrapErr().message);
        }

        REQUIRE(ctx.alice->HasConnection());
        REQUIRE(ctx.bob->HasConnection());

        constexpr uint32_t MESSAGE_COUNT = 50;
        uint32_t successful_alice_to_bob = 0;
        uint32_t successful_bob_to_alice = 0;

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            std::vector<uint8_t> alice_plaintext{
                0xA1, 0xA2,
                static_cast<uint8_t>(i & 0xFF),
                static_cast<uint8_t>((i >> 8) & 0xFF)
            };

            auto alice_send_result = ctx.alice->SendMessage(alice_plaintext);
            if (alice_send_result.IsErr()) {
                FAIL("Alice send failed at message " + std::to_string(i) +
                     ": " + alice_send_result.UnwrapErr().message);
            }
            auto alice_envelope = std::move(alice_send_result).Unwrap();

            auto bob_receive_result = ctx.bob->ReceiveMessage(alice_envelope);
            if (bob_receive_result.IsErr()) {
                FAIL("Bob receive failed at message " + std::to_string(i) +
                     ": " + bob_receive_result.UnwrapErr().message);
            }
            auto bob_decrypted = std::move(bob_receive_result).Unwrap();

            if (bob_decrypted == alice_plaintext) {
                ++successful_alice_to_bob;
            }

            std::vector<uint8_t> bob_plaintext{
                0xB1, 0xB2,
                static_cast<uint8_t>(i & 0xFF),
                static_cast<uint8_t>((i >> 8) & 0xFF)
            };

            auto bob_send_result = ctx.bob->SendMessage(bob_plaintext);
            if (bob_send_result.IsErr()) {
                FAIL("Bob send failed at message " + std::to_string(i) +
                     ": " + bob_send_result.UnwrapErr().message);
            }
            auto bob_envelope = std::move(bob_send_result).Unwrap();

            auto alice_receive_result = ctx.alice->ReceiveMessage(bob_envelope);
            if (alice_receive_result.IsErr()) {
                FAIL("Alice receive failed at message " + std::to_string(i) +
                     ": " + alice_receive_result.UnwrapErr().message);
            }
            auto alice_decrypted = std::move(alice_receive_result).Unwrap();

            if (alice_decrypted == bob_plaintext) {
                ++successful_bob_to_alice;
            }
        }

        REQUIRE(successful_alice_to_bob == MESSAGE_COUNT);
        REQUIRE(successful_bob_to_alice == MESSAGE_COUNT);
    }
}

TEST_CASE("Protocol System - Sequential Messages", "[protocol-system][integration][sequential]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Sequential messages from Alice to Bob (below ratchet window)") {
        auto ctx_result = ProtocolSystemTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        auto handshake_result = ctx.PerformHandshake();
        REQUIRE(handshake_result.IsOk());

        constexpr uint32_t MESSAGE_COUNT = 80;
        uint32_t successful_messages = 0;

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            std::vector<uint8_t> plaintext{
                static_cast<uint8_t>(i & 0xFF),
                static_cast<uint8_t>((i >> 8) & 0xFF),
                static_cast<uint8_t>((i >> 16) & 0xFF),
                static_cast<uint8_t>((i >> 24) & 0xFF)
            };

            auto send_result = ctx.alice->SendMessage(plaintext);
            if (send_result.IsErr()) break;
            auto envelope = std::move(send_result).Unwrap();

            auto receive_result = ctx.bob->ReceiveMessage(envelope);
            if (receive_result.IsErr()) break;
            auto decrypted = std::move(receive_result).Unwrap();

            if (decrypted == plaintext) {
                ++successful_messages;
            }
        }

        REQUIRE(successful_messages == MESSAGE_COUNT);
    }
}

TEST_CASE("Protocol System - Bidirectional Messages", "[protocol-system][integration][bidirectional]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Bidirectional round-trips (below ratchet window)") {
        auto ctx_result = ProtocolSystemTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        auto handshake_result = ctx.PerformHandshake();
        REQUIRE(handshake_result.IsOk());

        constexpr uint32_t ROUND_TRIP_COUNT = 40;
        uint32_t successful_round_trips = 0;

        for (uint32_t i = 0; i < ROUND_TRIP_COUNT; ++i) {
            std::vector<uint8_t> alice_msg{0xAA, static_cast<uint8_t>(i & 0xFF)};
            std::vector<uint8_t> bob_msg{0xBB, static_cast<uint8_t>(i & 0xFF)};

            auto alice_send = ctx.alice->SendMessage(alice_msg);
            if (alice_send.IsErr()) break;

            auto bob_recv = ctx.bob->ReceiveMessage(alice_send.Unwrap());
            if (bob_recv.IsErr()) break;

            auto bob_send = ctx.bob->SendMessage(bob_msg);
            if (bob_send.IsErr()) break;

            auto alice_recv = ctx.alice->ReceiveMessage(bob_send.Unwrap());
            if (alice_recv.IsErr()) break;

            if (bob_recv.Unwrap() == alice_msg && alice_recv.Unwrap() == bob_msg) {
                ++successful_round_trips;
            }
        }

        REQUIRE(successful_round_trips == ROUND_TRIP_COUNT);
    }
}

TEST_CASE("Protocol System - Initiator Flag Consumed After Handshake", "[protocol-system][integration][state]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Verify pending initiator flag is consumed during handshake") {
        auto ctx_result = ProtocolSystemTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        REQUIRE_FALSE(ctx.alice->GetPendingInitiator().has_value());
        REQUIRE_FALSE(ctx.bob->GetPendingInitiator().has_value());

        auto handshake_result = ctx.PerformHandshake();
        REQUIRE(handshake_result.IsOk());

        REQUIRE_FALSE(ctx.alice->GetPendingInitiator().has_value());
        REQUIRE_FALSE(ctx.bob->GetPendingInitiator().has_value());

        std::vector<uint8_t> test_msg{0x01, 0x02, 0x03, 0x04};

        auto send_result = ctx.alice->SendMessage(test_msg);
        REQUIRE(send_result.IsOk());

        auto receive_result = ctx.bob->ReceiveMessage(send_result.Unwrap());
        REQUIRE(receive_result.IsOk());
        REQUIRE(receive_result.Unwrap() == test_msg);

        REQUIRE_FALSE(ctx.alice->GetPendingInitiator().has_value());
        REQUIRE_FALSE(ctx.bob->GetPendingInitiator().has_value());
    }
}

TEST_CASE("Protocol System - Large Payload Messages", "[protocol-system][integration][payload]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Exchange 100 messages with 64KB payloads") {
        auto ctx_result = ProtocolSystemTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        auto handshake_result = ctx.PerformHandshake();
        REQUIRE(handshake_result.IsOk());

        constexpr size_t PAYLOAD_SIZE = 64 * 1024;
        constexpr uint32_t MESSAGE_COUNT = 100;
        uint32_t successful_messages = 0;

        for (uint32_t i = 0; i < MESSAGE_COUNT; ++i) {
            std::vector<uint8_t> large_payload(PAYLOAD_SIZE);
            for (size_t j = 0; j < PAYLOAD_SIZE; ++j) {
                large_payload[j] = static_cast<uint8_t>((i + j) & 0xFF);
            }

            auto send_result = ctx.alice->SendMessage(large_payload);
            if (send_result.IsErr()) {
                FAIL("Send failed at message " + std::to_string(i) +
                     ": " + send_result.UnwrapErr().message);
            }

            auto receive_result = ctx.bob->ReceiveMessage(send_result.Unwrap());
            if (receive_result.IsErr()) {
                FAIL("Receive failed at message " + std::to_string(i) +
                     ": " + receive_result.UnwrapErr().message);
            }

            if (receive_result.Unwrap() == large_payload) {
                ++successful_messages;
            }
        }

        REQUIRE(successful_messages == MESSAGE_COUNT);
    }
}

TEST_CASE("Protocol System - Session Age Tracking", "[protocol-system][integration][state]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Session age increases after handshake") {
        auto ctx_result = ProtocolSystemTestContext::Create();
        REQUIRE(ctx_result.IsOk());
        auto ctx = std::move(ctx_result).Unwrap();

        auto handshake_result = ctx.PerformHandshake();
        REQUIRE(handshake_result.IsOk());

        const uint64_t alice_age = ctx.alice->GetSessionAgeSeconds();
        const uint64_t bob_age = ctx.bob->GetSessionAgeSeconds();

        (void)alice_age;
        (void)bob_age;
    }
}
