#include <catch2/catch_test_macros.hpp>
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/interfaces/i_state_key_provider.hpp"
#include "ecliptix/protocol/constants.hpp"
#include "ecliptix/protocol/handshake.hpp"
#include "ecliptix/protocol/session.hpp"
#include "protocol/handshake.pb.h"
#include <span>
#include <utility>

namespace {
    using ecliptix::protocol::ProtocolFailure;
    using ecliptix::protocol::Result;
    using ecliptix::protocol::Unit;
    using ecliptix::protocol::crypto::SecureMemoryHandle;
    using ecliptix::protocol::crypto::SodiumInterop;

    class TestKeyProvider final : public ecliptix::protocol::interfaces::IStateKeyProvider {
    public:
        explicit TestKeyProvider(std::span<const uint8_t> key) : key_(key.begin(), key.end()) {}
        ~TestKeyProvider() override {
            SodiumInterop::SecureWipe(std::span(key_));
        }

        [[nodiscard]] Result<SecureMemoryHandle, ProtocolFailure> GetStateEncryptionKey() override {
            auto handle_result = SecureMemoryHandle::Allocate(key_.size());
            if (handle_result.IsErr()) {
                return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(handle_result.UnwrapErr()));
            }
            auto handle = std::move(handle_result).Unwrap();
            auto write_result = handle.Write(std::span(key_));
            if (write_result.IsErr()) {
                return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(write_result.UnwrapErr()));
            }
            return Result<SecureMemoryHandle, ProtocolFailure>::Ok(std::move(handle));
        }

        TestKeyProvider(const TestKeyProvider&) = delete;
        TestKeyProvider& operator=(const TestKeyProvider&) = delete;

    private:
        std::vector<uint8_t> key_;
    };

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

TEST_CASE("Session sealed state protects export/import", "[session][state][sealed]") {
    using ecliptix::protocol::HandshakeInitiator;
    using ecliptix::protocol::HandshakeResponder;
    using ecliptix::protocol::Session;
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
        bob_bundle,
        std::span<const uint8_t>(init_bytes.data(), init_bytes.size()),
        max_messages);
    REQUIRE(responder_result.IsOk());
    auto responder = std::move(responder_result).Unwrap();

    auto initiator_session_result = initiator->Finish(responder->Ack());
    REQUIRE(initiator_session_result.IsOk());
    auto responder_session_result = responder->Finish();
    REQUIRE(responder_session_result.IsOk());

    auto initiator_session = std::move(initiator_session_result).Unwrap();

    auto encryption_key = SodiumInterop::GetRandomBytes(ecliptix::protocol::kAesKeyBytes);
    REQUIRE(encryption_key.size() == ecliptix::protocol::kAesKeyBytes);

    SECTION("Export and import sealed state succeeds with correct key") {
        TestKeyProvider key_provider(std::span<const uint8_t>{encryption_key});
        auto sealed_result = initiator_session->ExportSealedState(key_provider);
        REQUIRE(sealed_result.IsOk());
        auto sealed_state = sealed_result.Unwrap();
        REQUIRE(!sealed_state.empty());

        TestKeyProvider key_provider2(std::span<const uint8_t>{encryption_key});
        auto import_result = Session::FromSealedState(
            std::span<const uint8_t>{sealed_state},
            key_provider2);
        REQUIRE(import_result.IsOk());
    }

    SECTION("Import fails with wrong key") {
        TestKeyProvider key_provider(std::span<const uint8_t>{encryption_key});
        auto sealed_result = initiator_session->ExportSealedState(key_provider);
        REQUIRE(sealed_result.IsOk());
        auto sealed_state = sealed_result.Unwrap();

        auto wrong_key = SodiumInterop::GetRandomBytes(ecliptix::protocol::kAesKeyBytes);
        TestKeyProvider wrong_key_provider(std::span<const uint8_t>{wrong_key});
        auto import_result = Session::FromSealedState(
            std::span<const uint8_t>{sealed_state},
            wrong_key_provider);
        REQUIRE(import_result.IsErr());
    }

    SECTION("Import fails with tampered sealed state") {
        TestKeyProvider key_provider(std::span<const uint8_t>{encryption_key});
        auto sealed_result = initiator_session->ExportSealedState(key_provider);
        REQUIRE(sealed_result.IsOk());
        auto sealed_state = sealed_result.Unwrap();
        REQUIRE(sealed_state.size() > 10);

        sealed_state[sealed_state.size() - 5] ^= 0xFF;

        TestKeyProvider key_provider2(std::span<const uint8_t>{encryption_key});
        auto import_result = Session::FromSealedState(
            std::span<const uint8_t>{sealed_state},
            key_provider2);
        REQUIRE(import_result.IsErr());
    }
}
