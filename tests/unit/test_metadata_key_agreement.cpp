#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/protocol_connection.hpp"
#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include "protocol/key_exchange.pb.h"
#include <sodium.h>
#include <vector>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::identity;
using namespace ecliptix::protocol::crypto;

TEST_CASE("Metadata key agreement - correct DH key selection", "[metadata][x3dh][handshake]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto client_identity_result = IdentityKeys::Create(5);
    REQUIRE(client_identity_result.IsOk());
    auto client_identity = std::move(client_identity_result).Unwrap();

    auto server_identity_result = IdentityKeys::Create(5);
    REQUIRE(server_identity_result.IsOk());
    auto server_identity = std::move(server_identity_result).Unwrap();

    client_identity.GenerateEphemeralKeyPair();
    server_identity.GenerateEphemeralKeyPair();

    auto client_ek = client_identity.GetEphemeralX25519PublicKeyCopy();
    REQUIRE(client_ek.has_value());
    REQUIRE(client_ek->size() == Constants::X_25519_PUBLIC_KEY_SIZE);

    auto server_spk = server_identity.GetSignedPreKeyPublicCopy();
    REQUIRE(server_spk.size() == Constants::X_25519_PUBLIC_KEY_SIZE);

    auto client_ek_priv_result = client_identity.GetEphemeralX25519PrivateKeyCopy();
    REQUIRE(client_ek_priv_result.IsOk());
    auto client_ek_priv = client_ek_priv_result.Unwrap();

    auto server_spk_priv_result = server_identity.GetSignedPreKeyPrivateCopy();
    REQUIRE(server_spk_priv_result.IsOk());
    auto server_spk_priv = server_spk_priv_result.Unwrap();

    auto client_bundle_result = client_identity.CreatePublicBundle();
    REQUIRE(client_bundle_result.IsOk());
    auto client_bundle = std::move(client_bundle_result).Unwrap();

    auto server_bundle_result = server_identity.CreatePublicBundle();
    REQUIRE(server_bundle_result.IsOk());
    auto server_bundle = std::move(server_bundle_result).Unwrap();

    std::vector<uint8_t> root_key(32);
    randombytes_buf(root_key.data(), root_key.size());

    std::vector<uint8_t> kyber_ciphertext(KyberInterop::KYBER_768_CIPHERTEXT_SIZE);
    std::vector<uint8_t> kyber_shared_secret(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
    randombytes_buf(kyber_ciphertext.data(), kyber_ciphertext.size());
    randombytes_buf(kyber_shared_secret.data(), kyber_shared_secret.size());

    ecliptix::proto::protocol::PublicKeyBundle client_proto_bundle;
    client_proto_bundle.set_identity_public_key(client_bundle.GetEd25519Public().data(), client_bundle.GetEd25519Public().size());
    client_proto_bundle.set_identity_x25519_public_key(client_bundle.GetIdentityX25519().data(), client_bundle.GetIdentityX25519().size());
    client_proto_bundle.set_signed_pre_key_id(client_bundle.GetSignedPreKeyId());
    client_proto_bundle.set_signed_pre_key_public_key(client_bundle.GetSignedPreKeyPublic().data(), client_bundle.GetSignedPreKeyPublic().size());
    client_proto_bundle.set_signed_pre_key_signature(client_bundle.GetSignedPreKeySignature().data(), client_bundle.GetSignedPreKeySignature().size());
    if (client_bundle.HasEphemeralKey()) {
        const auto& eph = client_bundle.GetEphemeralX25519Public();
        client_proto_bundle.set_ephemeral_x25519_public_key(eph->data(), eph->size());
    }
    if (client_bundle.HasKyberKey()) {
        const auto& kyber = client_bundle.GetKyberPublicKey();
        client_proto_bundle.set_kyber_public_key(kyber->data(), kyber->size());
    }

    ecliptix::proto::protocol::PublicKeyBundle server_proto_bundle;
    server_proto_bundle.set_identity_public_key(server_bundle.GetEd25519Public().data(), server_bundle.GetEd25519Public().size());
    server_proto_bundle.set_identity_x25519_public_key(server_bundle.GetIdentityX25519().data(), server_bundle.GetIdentityX25519().size());
    server_proto_bundle.set_signed_pre_key_id(server_bundle.GetSignedPreKeyId());
    server_proto_bundle.set_signed_pre_key_public_key(server_bundle.GetSignedPreKeyPublic().data(), server_bundle.GetSignedPreKeyPublic().size());
    server_proto_bundle.set_signed_pre_key_signature(server_bundle.GetSignedPreKeySignature().data(), server_bundle.GetSignedPreKeySignature().size());
    if (server_bundle.HasEphemeralKey()) {
        const auto& eph = server_bundle.GetEphemeralX25519Public();
        server_proto_bundle.set_ephemeral_x25519_public_key(eph->data(), eph->size());
    }
    if (server_bundle.HasKyberKey()) {
        const auto& kyber = server_bundle.GetKyberPublicKey();
        server_proto_bundle.set_kyber_public_key(kyber->data(), kyber->size());
    }

    SECTION("Both sides derive same metadata key with correct DH key selection") {
        INFO("Client EK (first 8 bytes): " << std::hex
            << (int)client_ek.value()[0] << (int)client_ek.value()[1]
            << (int)client_ek.value()[2] << (int)client_ek.value()[3]);
        INFO("Server SPK (first 8 bytes): " << std::hex
            << (int)server_spk[0] << (int)server_spk[1]
            << (int)server_spk[2] << (int)server_spk[3]);

        auto client_conn_result = ProtocolConnection::FromRootAndPeerBundle(
            0,
            root_key,
            server_proto_bundle,
            true,
            kyber_ciphertext,
            kyber_shared_secret,
            client_ek.value(),
            client_ek_priv);
        REQUIRE(client_conn_result.IsOk());
        auto client_conn = std::move(client_conn_result).Unwrap();

        auto server_conn_result = ProtocolConnection::FromRootAndPeerBundle(
            0,
            root_key,
            client_proto_bundle,
            false,
            kyber_ciphertext,
            kyber_shared_secret,
            server_spk,
            server_spk_priv);
        REQUIRE(server_conn_result.IsOk());
        auto server_conn = std::move(server_conn_result).Unwrap();

        auto client_metadata_result = client_conn->GetMetadataEncryptionKey();
        REQUIRE(client_metadata_result.IsOk());
        auto client_metadata_key = client_metadata_result.Unwrap();

        auto server_metadata_result = server_conn->GetMetadataEncryptionKey();
        REQUIRE(server_metadata_result.IsOk());
        auto server_metadata_key = server_metadata_result.Unwrap();

        INFO("Client metadata key (first 8 bytes): " << std::hex
            << (int)client_metadata_key[0] << (int)client_metadata_key[1]
            << (int)client_metadata_key[2] << (int)client_metadata_key[3]
            << (int)client_metadata_key[4] << (int)client_metadata_key[5]
            << (int)client_metadata_key[6] << (int)client_metadata_key[7]);
        INFO("Server metadata key (first 8 bytes): " << std::hex
            << (int)server_metadata_key[0] << (int)server_metadata_key[1]
            << (int)server_metadata_key[2] << (int)server_metadata_key[3]
            << (int)server_metadata_key[4] << (int)server_metadata_key[5]
            << (int)server_metadata_key[6] << (int)server_metadata_key[7]);

        REQUIRE(client_metadata_key == server_metadata_key);
    }

    SECTION("Verify sender_dh is correctly set") {
        auto client_conn_result = ProtocolConnection::FromRootAndPeerBundle(
            0,
            root_key,
            server_proto_bundle,
            true,
            kyber_ciphertext,
            kyber_shared_secret,
            client_ek.value(),
            client_ek_priv);
        REQUIRE(client_conn_result.IsOk());
        auto client_conn = std::move(client_conn_result).Unwrap();

        auto server_conn_result = ProtocolConnection::FromRootAndPeerBundle(
            0,
            root_key,
            client_proto_bundle,
            false,
            kyber_ciphertext,
            kyber_shared_secret,
            server_spk,
            server_spk_priv);
        REQUIRE(server_conn_result.IsOk());
        auto server_conn = std::move(server_conn_result).Unwrap();

        auto client_sender_dh_result = client_conn->GetCurrentSenderDhPublicKey();
        REQUIRE(client_sender_dh_result.IsOk());
        auto client_sender_dh = client_sender_dh_result.Unwrap();
        REQUIRE(client_sender_dh.has_value());
        REQUIRE(client_sender_dh.value() == client_ek.value());

        auto server_sender_dh_result = server_conn->GetCurrentSenderDhPublicKey();
        REQUIRE(server_sender_dh_result.IsOk());
        auto server_sender_dh = server_sender_dh_result.Unwrap();
        REQUIRE(server_sender_dh.has_value());
        REQUIRE(server_sender_dh.value() == server_spk);
    }

    SECTION("Verify peer_dh is correctly set") {
        auto client_conn_result = ProtocolConnection::FromRootAndPeerBundle(
            0,
            root_key,
            server_proto_bundle,
            true,
            kyber_ciphertext,
            kyber_shared_secret,
            client_ek.value(),
            client_ek_priv);
        REQUIRE(client_conn_result.IsOk());
        auto client_conn = std::move(client_conn_result).Unwrap();

        auto server_conn_result = ProtocolConnection::FromRootAndPeerBundle(
            0,
            root_key,
            client_proto_bundle,
            false,
            kyber_ciphertext,
            kyber_shared_secret,
            server_spk,
            server_spk_priv);
        REQUIRE(server_conn_result.IsOk());
        auto server_conn = std::move(server_conn_result).Unwrap();

        auto client_peer_dh_result = client_conn->GetCurrentPeerDhPublicKey();
        REQUIRE(client_peer_dh_result.IsOk());
        auto client_peer_dh = client_peer_dh_result.Unwrap();
        REQUIRE(client_peer_dh.has_value());
        REQUIRE(client_peer_dh.value() == server_spk);

        auto server_peer_dh_result = server_conn->GetCurrentPeerDhPublicKey();
        REQUIRE(server_peer_dh_result.IsOk());
        auto server_peer_dh = server_peer_dh_result.Unwrap();
        REQUIRE(server_peer_dh.has_value());
        REQUIRE(server_peer_dh.value() == client_ek.value());
    }
}

TEST_CASE("Metadata key canonical ordering", "[metadata][ordering]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    std::vector<uint8_t> root_key(32);
    randombytes_buf(root_key.data(), root_key.size());

    auto kp_a_result = SodiumInterop::GenerateX25519KeyPair("metadata-a");
    REQUIRE(kp_a_result.IsOk());
    auto [key_a_handle, key_a_public] = std::move(kp_a_result).Unwrap();
    auto key_a_private_result = key_a_handle.ReadBytes(Constants::X_25519_PRIVATE_KEY_SIZE);
    REQUIRE(key_a_private_result.IsOk());
    auto key_a_private = key_a_private_result.Unwrap();

    auto kp_b_result = SodiumInterop::GenerateX25519KeyPair("metadata-b");
    REQUIRE(kp_b_result.IsOk());
    auto [key_b_handle, key_b_public] = std::move(kp_b_result).Unwrap();
    auto key_b_private_result = key_b_handle.ReadBytes(Constants::X_25519_PRIVATE_KEY_SIZE);
    REQUIRE(key_b_private_result.IsOk());
    auto key_b_private = key_b_private_result.Unwrap();

    std::vector<uint8_t> kyber_ciphertext(KyberInterop::KYBER_768_CIPHERTEXT_SIZE);
    std::vector<uint8_t> kyber_shared_secret(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
    randombytes_buf(kyber_ciphertext.data(), kyber_ciphertext.size());
    randombytes_buf(kyber_shared_secret.data(), kyber_shared_secret.size());

    auto identity_result = IdentityKeys::Create(5);
    REQUIRE(identity_result.IsOk());
    auto identity = std::move(identity_result).Unwrap();
    identity.GenerateEphemeralKeyPair();

    auto bundle_result = identity.CreatePublicBundle();
    REQUIRE(bundle_result.IsOk());
    auto bundle = std::move(bundle_result).Unwrap();

    ecliptix::proto::protocol::PublicKeyBundle proto_bundle;
    proto_bundle.set_identity_public_key(bundle.GetEd25519Public().data(), bundle.GetEd25519Public().size());
    proto_bundle.set_identity_x25519_public_key(bundle.GetIdentityX25519().data(), bundle.GetIdentityX25519().size());
    proto_bundle.set_signed_pre_key_id(bundle.GetSignedPreKeyId());
    proto_bundle.set_signed_pre_key_public_key(bundle.GetSignedPreKeyPublic().data(), bundle.GetSignedPreKeyPublic().size());
    proto_bundle.set_signed_pre_key_signature(bundle.GetSignedPreKeySignature().data(), bundle.GetSignedPreKeySignature().size());
    if (bundle.HasEphemeralKey()) {
        const auto& eph = bundle.GetEphemeralX25519Public();
        proto_bundle.set_ephemeral_x25519_public_key(eph->data(), eph->size());
    }
    if (bundle.HasKyberKey()) {
        const auto& kyber = bundle.GetKyberPublicKey();
        proto_bundle.set_kyber_public_key(kyber->data(), kyber->size());
    }

    auto conn1_result = ProtocolConnection::FromRootAndPeerBundle(
        0,
        root_key,
        proto_bundle,
        true,
        kyber_ciphertext,
        kyber_shared_secret,
        key_a_public,
        key_a_private);
    REQUIRE(conn1_result.IsOk());
    auto conn1 = std::move(conn1_result).Unwrap();

    auto conn2_result = ProtocolConnection::FromRootAndPeerBundle(
        0,
        root_key,
        proto_bundle,
        false,
        kyber_ciphertext,
        kyber_shared_secret,
        key_b_public,
        key_b_private);
    REQUIRE(conn2_result.IsOk());
    auto conn2 = std::move(conn2_result).Unwrap();

    auto mk1 = conn1->GetMetadataEncryptionKey();
    REQUIRE(mk1.IsOk());

    auto mk2 = conn2->GetMetadataEncryptionKey();
    REQUIRE(mk2.IsOk());

    REQUIRE(mk1.Unwrap().size() == 32);
    REQUIRE(mk2.Unwrap().size() == 32);
}
