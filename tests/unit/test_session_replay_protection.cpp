#include <catch2/catch_test_macros.hpp>
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/protocol/constants.hpp"
#include "ecliptix/protocol/handshake.hpp"
#include "ecliptix/protocol/session.hpp"
#include "protocol/handshake.pb.h"
#include "protocol/envelope.pb.h"
#include <span>
#include <utility>

namespace {
    using ecliptix::protocol::ProtocolFailure;
    using ecliptix::protocol::Result;

    Result<ecliptix::proto::protocol::PreKeyBundle, ProtocolFailure> BuildPreKeyBundle(
        ecliptix::protocol::identity::IdentityKeys& keys) {
        auto bundle_result = keys.CreatePublicBundle();
        if (bundle_result.IsErr()) {
            return Result<ecliptix::proto::protocol::PreKeyBundle, ProtocolFailure>::Err(
                bundle_result.UnwrapErr());
        }
        const auto& bundle = bundle_result.Unwrap();
        const auto& kyber_public = bundle.GetKyberPublic();
        if (!kyber_public.has_value()) {
            return Result<ecliptix::proto::protocol::PreKeyBundle, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Missing Kyber public key for bundle"));
        }

        ecliptix::proto::protocol::PreKeyBundle proto_bundle;
        proto_bundle.set_version(ecliptix::protocol::kProtocolVersion);
        proto_bundle.set_identity_ed25519_public(
            bundle.GetIdentityEd25519Public().data(),
            bundle.GetIdentityEd25519Public().size());
        proto_bundle.set_identity_x25519_public(
            bundle.GetIdentityX25519Public().data(),
            bundle.GetIdentityX25519Public().size());
        proto_bundle.set_signed_pre_key_id(bundle.GetSignedPreKeyId());
        proto_bundle.set_signed_pre_key_public(
            bundle.GetSignedPreKeyPublic().data(),
            bundle.GetSignedPreKeyPublic().size());
        proto_bundle.set_signed_pre_key_signature(
            bundle.GetSignedPreKeySignature().data(),
            bundle.GetSignedPreKeySignature().size());
        for (const auto& opk : bundle.GetOneTimePreKeys()) {
            auto* opk_proto = proto_bundle.add_one_time_pre_keys();
            opk_proto->set_one_time_pre_key_id(opk.GetOneTimePreKeyId());
            const auto& opk_pub = opk.GetPublicKey();
            opk_proto->set_public_key(opk_pub.data(), opk_pub.size());
        }
        proto_bundle.set_kyber_public(kyber_public->data(), kyber_public->size());
        return Result<ecliptix::proto::protocol::PreKeyBundle, ProtocolFailure>::Ok(
            std::move(proto_bundle));
    }
}

TEST_CASE("Session replay protection rejects duplicate envelope", "[session][replay]") {
    using ecliptix::protocol::HandshakeInitiator;
    using ecliptix::protocol::HandshakeResponder;
    using ecliptix::protocol::ProtocolFailureType;
    using ecliptix::protocol::Session;
    using ecliptix::protocol::crypto::SodiumInterop;
    using ecliptix::protocol::identity::IdentityKeys;

    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto alice_result = IdentityKeys::Create(1);
    auto bob_result = IdentityKeys::Create(1);
    REQUIRE(alice_result.IsOk());
    REQUIRE(bob_result.IsOk());

    auto alice_keys = std::move(alice_result).Unwrap();
    auto bob_keys = std::move(bob_result).Unwrap();

    auto bob_bundle_result = BuildPreKeyBundle(bob_keys);
    REQUIRE(bob_bundle_result.IsOk());
    auto bob_bundle = bob_bundle_result.Unwrap();

    const uint32_t max_messages =
        static_cast<uint32_t>(ecliptix::protocol::kDefaultMessagesPerChain);
    auto initiator_result = HandshakeInitiator::Start(
        alice_keys,
        bob_bundle,
        max_messages);
    REQUIRE(initiator_result.IsOk());
    auto initiator = std::move(initiator_result).Unwrap();

    const auto& init_bytes = initiator->EncodedMessage();
    auto responder_result = HandshakeResponder::Process(
        bob_keys,
        bob_bundle,  // Reuse the same bundle instead of creating a new one
        std::span<const uint8_t>(init_bytes.data(), init_bytes.size()),
        max_messages);
    REQUIRE(responder_result.IsOk());
    auto responder = std::move(responder_result).Unwrap();

    auto initiator_session_result = initiator->Finish(responder->Ack());
    REQUIRE(initiator_session_result.IsOk());
    auto responder_session_result = responder->Finish();
    REQUIRE(responder_session_result.IsOk());

    auto initiator_session = std::move(initiator_session_result).Unwrap();
    auto responder_session = std::move(responder_session_result).Unwrap();

    const std::vector<uint8_t> payload = {0x10, 0x20, 0x30};
    auto envelope_result = initiator_session->Encrypt(
        payload,
        ecliptix::proto::protocol::EnvelopeType::REQUEST,
        1,
        "replay-test");
    REQUIRE(envelope_result.IsOk());
    auto envelope = envelope_result.Unwrap();

    auto first_decrypt = responder_session->Decrypt(envelope);
    REQUIRE(first_decrypt.IsOk());

    auto replay_decrypt = responder_session->Decrypt(envelope);
    REQUIRE(replay_decrypt.IsErr());
    REQUIRE(replay_decrypt.UnwrapErr().type == ProtocolFailureType::ReplayAttack);
}
