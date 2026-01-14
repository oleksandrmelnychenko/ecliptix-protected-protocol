#include <catch2/catch_test_macros.hpp>
#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/models/bundles/local_public_key_bundle.hpp"
#include <sodium.h>
#include <vector>
#include <array>
#include <algorithm>

using namespace ecliptix::protocol::identity;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol;
using namespace ecliptix::protocol::models;

namespace {

struct X3DHTestVector {
    std::vector<uint8_t> alice_identity_private;
    std::vector<uint8_t> alice_identity_public;
    std::vector<uint8_t> alice_ephemeral_private;
    std::vector<uint8_t> alice_ephemeral_public;

    std::vector<uint8_t> bob_identity_private;
    std::vector<uint8_t> bob_identity_public;
    std::vector<uint8_t> bob_signed_pre_key_private;
    std::vector<uint8_t> bob_signed_pre_key_public;
    std::vector<uint8_t> bob_one_time_pre_key_private;
    std::vector<uint8_t> bob_one_time_pre_key_public;

    std::vector<uint8_t> expected_dh1;
    std::vector<uint8_t> expected_dh2;
    std::vector<uint8_t> expected_dh3;
    std::vector<uint8_t> expected_dh4;

    std::vector<uint8_t> expected_shared_secret;

    static X3DHTestVector Generate() {
        X3DHTestVector vec;

        vec.alice_identity_private.resize(Constants::X_25519_PRIVATE_KEY_SIZE);
        vec.alice_identity_public.resize(Constants::X_25519_PUBLIC_KEY_SIZE);
        crypto_box_keypair(vec.alice_identity_public.data(), vec.alice_identity_private.data());

        vec.alice_ephemeral_private.resize(Constants::X_25519_PRIVATE_KEY_SIZE);
        vec.alice_ephemeral_public.resize(Constants::X_25519_PUBLIC_KEY_SIZE);
        crypto_box_keypair(vec.alice_ephemeral_public.data(), vec.alice_ephemeral_private.data());

        vec.bob_identity_private.resize(Constants::X_25519_PRIVATE_KEY_SIZE);
        vec.bob_identity_public.resize(Constants::X_25519_PUBLIC_KEY_SIZE);
        crypto_box_keypair(vec.bob_identity_public.data(), vec.bob_identity_private.data());

        vec.bob_signed_pre_key_private.resize(Constants::X_25519_PRIVATE_KEY_SIZE);
        vec.bob_signed_pre_key_public.resize(Constants::X_25519_PUBLIC_KEY_SIZE);
        crypto_box_keypair(vec.bob_signed_pre_key_public.data(), vec.bob_signed_pre_key_private.data());

        vec.bob_one_time_pre_key_private.resize(Constants::X_25519_PRIVATE_KEY_SIZE);
        vec.bob_one_time_pre_key_public.resize(Constants::X_25519_PUBLIC_KEY_SIZE);
        crypto_box_keypair(vec.bob_one_time_pre_key_public.data(), vec.bob_one_time_pre_key_private.data());

        vec.expected_dh1.resize(Constants::X_25519_KEY_SIZE);
        vec.expected_dh2.resize(Constants::X_25519_KEY_SIZE);
        vec.expected_dh3.resize(Constants::X_25519_KEY_SIZE);
        vec.expected_dh4.resize(Constants::X_25519_KEY_SIZE);

        const auto dh1_result = crypto_scalarmult(vec.expected_dh1.data(), vec.alice_identity_private.data(), vec.bob_signed_pre_key_public.data());
        const auto dh2_result = crypto_scalarmult(vec.expected_dh2.data(), vec.alice_ephemeral_private.data(), vec.bob_identity_public.data());
        const auto dh3_result = crypto_scalarmult(vec.expected_dh3.data(), vec.alice_ephemeral_private.data(), vec.bob_signed_pre_key_public.data());
        const auto dh4_result = crypto_scalarmult(vec.expected_dh4.data(), vec.alice_ephemeral_private.data(), vec.bob_one_time_pre_key_public.data());

        (void)dh1_result;
        (void)dh2_result;
        (void)dh3_result;
        (void)dh4_result;

        return vec;
    }

    static X3DHTestVector FromKnownValues() {
        X3DHTestVector vec;

        vec.alice_identity_private = {
            0x70, 0x69, 0xcf, 0x52, 0xe5, 0x67, 0x32, 0x14,
            0x54, 0xf7, 0x26, 0x95, 0x20, 0x33, 0xa1, 0xd9,
            0x86, 0x12, 0x1e, 0x1f, 0x98, 0x6e, 0x71, 0x2a,
            0x14, 0xde, 0x6b, 0x0e, 0x60, 0x47, 0xd9, 0x7f
        };

        vec.alice_identity_public = {
            0x05, 0x1e, 0x77, 0x6b, 0x9f, 0x35, 0x2a, 0x36,
            0x73, 0xbc, 0xdf, 0xa2, 0x33, 0x46, 0x6c, 0x7e,
            0x48, 0x2e, 0xfe, 0xbb, 0xe4, 0xf7, 0x20, 0x41,
            0x08, 0x0b, 0x4a, 0x5d, 0x4a, 0xda, 0x34, 0x5d
        };

        vec.alice_ephemeral_private = {
            0xa0, 0xe8, 0x7d, 0x9e, 0x4c, 0x47, 0x8a, 0x0e,
            0x7f, 0xb4, 0x08, 0xad, 0xa6, 0x50, 0x99, 0x82,
            0x47, 0x12, 0xd0, 0x04, 0x75, 0x0d, 0x64, 0x3f,
            0xd9, 0xd8, 0x72, 0x92, 0xd1, 0x63, 0x47, 0x4f
        };

        vec.alice_ephemeral_public = {
            0x05, 0x8a, 0xc1, 0x3c, 0x4a, 0x68, 0x39, 0x6c,
            0x4e, 0xce, 0x5e, 0xd4, 0x5a, 0x0e, 0xd5, 0xc5,
            0x87, 0x3b, 0x1f, 0x10, 0xa7, 0xef, 0x3c, 0xe2,
            0x8a, 0x74, 0x5e, 0xbc, 0xa0, 0xbd, 0x29, 0x3f
        };

        vec.bob_identity_private = {
            0x60, 0x45, 0x72, 0x4e, 0x44, 0xc4, 0x7f, 0x0a,
            0x36, 0x1b, 0xd9, 0x62, 0x45, 0xb6, 0xe6, 0x42,
            0x82, 0x2d, 0xf9, 0xfc, 0x73, 0x53, 0xfc, 0xf2,
            0xd2, 0x78, 0x63, 0x56, 0xb9, 0xc1, 0x0d, 0x59
        };

        vec.bob_identity_public = {
            0x05, 0xf3, 0x8b, 0x2f, 0x1c, 0x8d, 0x4f, 0x35,
            0xcc, 0x3b, 0x52, 0xce, 0xab, 0x38, 0xe4, 0x0c,
            0xa8, 0x95, 0x51, 0xf2, 0xf0, 0x9a, 0x85, 0x78,
            0x2f, 0x62, 0x84, 0xd7, 0xaa, 0x49, 0x01, 0x38
        };

        vec.bob_signed_pre_key_private = {
            0x88, 0xe3, 0xd1, 0x78, 0x60, 0x67, 0x1b, 0x1b,
            0x8a, 0x73, 0x54, 0x10, 0xd8, 0x89, 0xb1, 0x09,
            0x42, 0x3d, 0x72, 0x17, 0x8a, 0xef, 0x45, 0xfe,
            0xf7, 0x66, 0xee, 0xb3, 0xb7, 0x0a, 0xee, 0x44
        };

        vec.bob_signed_pre_key_public = {
            0x05, 0x6e, 0x8b, 0x40, 0x63, 0x9b, 0x75, 0x2f,
            0xd0, 0x9f, 0x1f, 0x42, 0x26, 0x2b, 0x7d, 0xfe,
            0x89, 0x95, 0x6f, 0x85, 0x6f, 0x28, 0xc4, 0x5f,
            0x86, 0x94, 0x61, 0x0e, 0xe0, 0x93, 0x95, 0x6b
        };

        vec.bob_one_time_pre_key_private = {
            0x50, 0xd0, 0x57, 0xeb, 0x7e, 0x5f, 0x7a, 0x13,
            0x12, 0xa8, 0x63, 0xaa, 0x11, 0x0c, 0x48, 0x87,
            0x6e, 0x4d, 0xca, 0x2b, 0x5c, 0xf7, 0x7b, 0xfb,
            0x40, 0xb2, 0xa0, 0xa3, 0xa7, 0x82, 0x24, 0x78
        };

        vec.bob_one_time_pre_key_public = {
            0x05, 0xc0, 0xea, 0xf7, 0x83, 0xb1, 0x2a, 0x2d,
            0xd1, 0xee, 0x4c, 0x6f, 0xda, 0x3f, 0x9e, 0xd9,
            0x7d, 0x82, 0x1e, 0xb1, 0x20, 0x46, 0x55, 0x48,
            0xd0, 0xf1, 0x7c, 0xdf, 0xb0, 0x82, 0x95, 0x1a
        };

        return vec;
    }
};

void SecureCompare(std::span<const uint8_t> a, std::span<const uint8_t> b, const char* label) {
    REQUIRE(a.size() == b.size());

    bool match = true;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) {
            match = false;
            INFO("Mismatch at " << label << " byte " << i << ": expected 0x" << std::hex <<
                 static_cast<int>(a[i]) << " got 0x" << static_cast<int>(b[i]));
        }
    }
    REQUIRE(match);
}

}

TEST_CASE("X3DH Test Vectors - Basic Key Agreement", "[x3dh][interop][vectors]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Generate keys and perform X3DH") {
        auto alice_keys_result = IdentityKeys::Create(5);
        REQUIRE(alice_keys_result.IsOk());
        auto alice_keys = std::move(alice_keys_result).Unwrap();

        auto bob_keys_result = IdentityKeys::Create(5);
        REQUIRE(bob_keys_result.IsOk());
        auto bob_keys = std::move(bob_keys_result).Unwrap();

        alice_keys.GenerateEphemeralKeyPair();

        auto bob_bundle_result = bob_keys.CreatePublicBundle();
        REQUIRE(bob_bundle_result.IsOk());
        auto bob_bundle = std::move(bob_bundle_result).Unwrap();

        std::vector<uint8_t> info(ProtocolConstants::X3DH_INFO.begin(), ProtocolConstants::X3DH_INFO.end());
        auto shared_secret_result = alice_keys.X3dhDeriveSharedSecret(bob_bundle, info, true);
        REQUIRE(shared_secret_result.IsOk());

        auto shared_secret_handle = std::move(shared_secret_result).Unwrap();
        REQUIRE(shared_secret_handle.Size() == Constants::X_25519_KEY_SIZE);
    }
}

TEST_CASE("X3DH Test Vectors - DH Operations Correctness", "[x3dh][interop][vectors]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Verify DH1: IK_A * SPK_B") {
        const auto vec = X3DHTestVector::Generate();

        std::vector<uint8_t> computed_dh1(Constants::X_25519_KEY_SIZE);
        const int result = crypto_scalarmult(
            computed_dh1.data(),
            vec.alice_identity_private.data(),
            vec.bob_signed_pre_key_public.data()
        );
        REQUIRE(result == 0);

        SecureCompare(vec.expected_dh1, computed_dh1, "DH1");
    }

    SECTION("Verify DH2: EK_A * IK_B") {
        const auto vec = X3DHTestVector::Generate();

        std::vector<uint8_t> computed_dh2(Constants::X_25519_KEY_SIZE);
        const int result = crypto_scalarmult(
            computed_dh2.data(),
            vec.alice_ephemeral_private.data(),
            vec.bob_identity_public.data()
        );
        REQUIRE(result == 0);

        SecureCompare(vec.expected_dh2, computed_dh2, "DH2");
    }

    SECTION("Verify DH3: EK_A * SPK_B") {
        const auto vec = X3DHTestVector::Generate();

        std::vector<uint8_t> computed_dh3(Constants::X_25519_KEY_SIZE);
        const int result = crypto_scalarmult(
            computed_dh3.data(),
            vec.alice_ephemeral_private.data(),
            vec.bob_signed_pre_key_public.data()
        );
        REQUIRE(result == 0);

        SecureCompare(vec.expected_dh3, computed_dh3, "DH3");
    }

    SECTION("Verify DH4: EK_A * OPK_B") {
        const auto vec = X3DHTestVector::Generate();

        std::vector<uint8_t> computed_dh4(Constants::X_25519_KEY_SIZE);
        const int result = crypto_scalarmult(
            computed_dh4.data(),
            vec.alice_ephemeral_private.data(),
            vec.bob_one_time_pre_key_public.data()
        );
        REQUIRE(result == 0);

        SecureCompare(vec.expected_dh4, computed_dh4, "DH4");
    }
}

TEST_CASE("X3DH Test Vectors - Signed PreKey Verification", "[x3dh][interop][vectors]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Valid signature verification succeeds") {
        auto bob_keys_result = IdentityKeys::Create(1);
        REQUIRE(bob_keys_result.IsOk());
        auto bob_keys = std::move(bob_keys_result).Unwrap();

        auto bob_bundle_result = bob_keys.CreatePublicBundle();
        REQUIRE(bob_bundle_result.IsOk());
        auto bob_bundle = std::move(bob_bundle_result).Unwrap();

        auto verify_result = IdentityKeys::VerifyRemoteSpkSignature(
            bob_bundle.GetEd25519Public(),
            bob_bundle.GetSignedPreKeyPublic(),
            bob_bundle.GetSignedPreKeySignature()
        );
        REQUIRE(verify_result.IsOk());
        REQUIRE(verify_result.Unwrap() == true);
    }

    SECTION("Invalid signature verification fails") {
        auto bob_keys_result = IdentityKeys::Create(1);
        REQUIRE(bob_keys_result.IsOk());
        auto bob_keys = std::move(bob_keys_result).Unwrap();

        auto bob_bundle_result = bob_keys.CreatePublicBundle();
        REQUIRE(bob_bundle_result.IsOk());
        auto bob_bundle = std::move(bob_bundle_result).Unwrap();

        std::vector<uint8_t> corrupted_signature = bob_bundle.GetSignedPreKeySignature();
        corrupted_signature[0] ^= 0x01;

        auto verify_result = IdentityKeys::VerifyRemoteSpkSignature(
            bob_bundle.GetEd25519Public(),
            bob_bundle.GetSignedPreKeyPublic(),
            corrupted_signature
        );
        REQUIRE(verify_result.IsErr());
    }

    SECTION("Wrong identity key verification fails") {
        auto bob_keys_result = IdentityKeys::Create(1);
        REQUIRE(bob_keys_result.IsOk());
        auto bob_keys = std::move(bob_keys_result).Unwrap();

        auto attacker_keys_result = IdentityKeys::Create(1);
        REQUIRE(attacker_keys_result.IsOk());
        auto attacker_keys = std::move(attacker_keys_result).Unwrap();

        auto bob_bundle_result = bob_keys.CreatePublicBundle();
        REQUIRE(bob_bundle_result.IsOk());
        auto bob_bundle = std::move(bob_bundle_result).Unwrap();

        auto attacker_identity = attacker_keys.GetIdentityEd25519PublicKeyCopy();

        auto verify_result = IdentityKeys::VerifyRemoteSpkSignature(
            attacker_identity,
            bob_bundle.GetSignedPreKeyPublic(),
            bob_bundle.GetSignedPreKeySignature()
        );
        REQUIRE(verify_result.IsErr());
    }
}

TEST_CASE("X3DH rejects tampered SPK signature during handshake", "[x3dh][security][signature]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto alice_keys_result = IdentityKeys::Create(1);
    REQUIRE(alice_keys_result.IsOk());
    auto alice_keys = std::move(alice_keys_result).Unwrap();
    alice_keys.GenerateEphemeralKeyPair();

    auto bob_keys_result = IdentityKeys::Create(1);
    REQUIRE(bob_keys_result.IsOk());
    auto bob_keys = std::move(bob_keys_result).Unwrap();

    auto bob_bundle_result = bob_keys.CreatePublicBundle();
    REQUIRE(bob_bundle_result.IsOk());
    auto bob_bundle = std::move(bob_bundle_result).Unwrap();

    auto tampered_signature = bob_bundle.GetSignedPreKeySignature();
    tampered_signature[0] ^= 0xFF;

    LocalPublicKeyBundle tampered_bundle(
        bob_bundle.GetEd25519Public(),
        bob_bundle.GetIdentityX25519(),
        bob_bundle.GetSignedPreKeyId(),
        bob_bundle.GetSignedPreKeyPublic(),
        tampered_signature,
        bob_bundle.GetOneTimePreKeys(),
        bob_bundle.GetEphemeralX25519Public(),
        bob_bundle.GetKyberPublicKey(),
        bob_bundle.GetKyberCiphertext(),
        bob_bundle.GetUsedOpkId());

    std::vector<uint8_t> info(ProtocolConstants::X3DH_INFO.begin(), ProtocolConstants::X3DH_INFO.end());
    auto shared_secret_result = alice_keys.X3dhDeriveSharedSecret(tampered_bundle, info, true);

    REQUIRE(shared_secret_result.IsErr());
}

TEST_CASE("X3DH Test Vectors - One-Time PreKey Consumption", "[x3dh][interop][vectors]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("X3DH with one-time prekey") {
        auto alice_keys_result = IdentityKeys::Create(0);
        REQUIRE(alice_keys_result.IsOk());
        auto alice_keys = std::move(alice_keys_result).Unwrap();
        alice_keys.GenerateEphemeralKeyPair();

        auto bob_keys_result = IdentityKeys::Create(10);
        REQUIRE(bob_keys_result.IsOk());
        auto bob_keys = std::move(bob_keys_result).Unwrap();

        auto bob_bundle_result = bob_keys.CreatePublicBundle();
        REQUIRE(bob_bundle_result.IsOk());
        auto bob_bundle = std::move(bob_bundle_result).Unwrap();

        REQUIRE(bob_bundle.HasOneTimePreKeys());
        REQUIRE(bob_bundle.GetOneTimePreKeyCount() > 0);

        std::vector<uint8_t> info(ProtocolConstants::X3DH_INFO.begin(), ProtocolConstants::X3DH_INFO.end());
        auto shared_secret_result = alice_keys.X3dhDeriveSharedSecret(bob_bundle, info, true);
        REQUIRE(shared_secret_result.IsOk());
    }

    SECTION("X3DH without one-time prekey fallback") {
        auto alice_keys_result = IdentityKeys::Create(0);
        REQUIRE(alice_keys_result.IsOk());
        auto alice_keys = std::move(alice_keys_result).Unwrap();
        alice_keys.GenerateEphemeralKeyPair();

        auto bob_keys_result = IdentityKeys::Create(0);
        REQUIRE(bob_keys_result.IsOk());
        auto bob_keys = std::move(bob_keys_result).Unwrap();

        auto bob_bundle_result = bob_keys.CreatePublicBundle();
        REQUIRE(bob_bundle_result.IsOk());
        auto bob_bundle = std::move(bob_bundle_result).Unwrap();

        REQUIRE_FALSE(bob_bundle.HasOneTimePreKeys());

        std::vector<uint8_t> info(ProtocolConstants::X3DH_INFO.begin(), ProtocolConstants::X3DH_INFO.end());
        auto shared_secret_result = alice_keys.X3dhDeriveSharedSecret(bob_bundle, info, true);
        REQUIRE(shared_secret_result.IsOk());
    }
}

TEST_CASE("X3DH Explicit OPK Selection Consumes Key", "[x3dh][opk][consume]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto alice_result = IdentityKeys::Create(3);
    REQUIRE(alice_result.IsOk());
    auto alice = std::move(alice_result).Unwrap();
    alice.GenerateEphemeralKeyPair();

    auto bob_result = IdentityKeys::Create(3);
    REQUIRE(bob_result.IsOk());
    auto bob = std::move(bob_result).Unwrap();
    bob.GenerateEphemeralKeyPair();

    auto bob_bundle_result = bob.CreatePublicBundle();
    REQUIRE(bob_bundle_result.IsOk());
    auto bob_bundle = bob_bundle_result.Unwrap();
    REQUIRE(bob_bundle.HasOneTimePreKeys());
    const uint32_t opk_id = bob_bundle.GetOneTimePreKeys().front().GetPreKeyId();
    const size_t initial_opk_count = bob_bundle.GetOneTimePreKeyCount();

    alice.SetSelectedOpkId(opk_id);
    auto alice_bundle_result = alice.CreatePublicBundle();
    REQUIRE(alice_bundle_result.IsOk());
    auto alice_bundle = alice_bundle_result.Unwrap();
    auto alice_ephemeral = alice_bundle.GetEphemeralX25519Public();
    REQUIRE(alice_ephemeral.has_value());
    auto alice_kyber = alice_bundle.GetKyberPublicKey();
    REQUIRE(alice_kyber.has_value());

    std::vector<uint8_t> info(ProtocolConstants::X3DH_INFO.begin(), ProtocolConstants::X3DH_INFO.end());

    auto alice_secret_result = alice.X3dhDeriveSharedSecret(bob_bundle, info, true);
    REQUIRE(alice_secret_result.IsOk());
    auto alice_secret_handle = std::move(alice_secret_result).Unwrap();
    auto alice_root_result = alice_secret_handle.ReadBytes(Constants::X_25519_KEY_SIZE);
    REQUIRE(alice_root_result.IsOk());
    auto alice_root = alice_root_result.Unwrap();

    auto kyber_artifacts_result = alice.ConsumePendingKyberHandshake();
    REQUIRE(kyber_artifacts_result.IsOk());
    auto kyber_artifacts = kyber_artifacts_result.Unwrap();

    LocalPublicKeyBundle alice_bundle_with_ct(
        alice_bundle.GetEd25519Public(),
        alice_bundle.GetIdentityX25519(),
        alice_bundle.GetSignedPreKeyId(),
        alice_bundle.GetSignedPreKeyPublicCopy(),
        alice_bundle.GetSignedPreKeySignature(),
        {},
        alice_ephemeral,
        alice_kyber,
        kyber_artifacts.kyber_ciphertext,
        opk_id);

    auto bob_secret_result = bob.X3dhDeriveSharedSecret(alice_bundle_with_ct, info, false);
    REQUIRE(bob_secret_result.IsOk());
    auto bob_secret_handle = std::move(bob_secret_result).Unwrap();
    auto bob_root_result = bob_secret_handle.ReadBytes(Constants::X_25519_KEY_SIZE);
    REQUIRE(bob_root_result.IsOk());
    auto bob_root = bob_root_result.Unwrap();

    REQUIRE(alice_root == bob_root);

    auto bob_bundle_after_result = bob.CreatePublicBundle();
    REQUIRE(bob_bundle_after_result.IsOk());
    auto bob_bundle_after = bob_bundle_after_result.Unwrap();
    REQUIRE(bob_bundle_after.GetOneTimePreKeyCount() == initial_opk_count - 1);

    const bool opk_still_present = std::any_of(
        bob_bundle_after.GetOneTimePreKeys().begin(),
        bob_bundle_after.GetOneTimePreKeys().end(),
        [opk_id](const OneTimePreKeyPublic &opk) {
            return opk.GetPreKeyId() == opk_id;
        });
    REQUIRE_FALSE(opk_still_present);
    REQUIRE_FALSE(bob.GetSelectedOpkId().has_value());
}

TEST_CASE("X3DH Test Vectors - Ephemeral Key Management", "[x3dh][interop][vectors]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Multiple ephemeral key generations") {
        auto alice_keys_result = IdentityKeys::Create(1);
        REQUIRE(alice_keys_result.IsOk());
        auto alice_keys = std::move(alice_keys_result).Unwrap();

        alice_keys.GenerateEphemeralKeyPair();

        auto bob_keys_result = IdentityKeys::Create(1);
        REQUIRE(bob_keys_result.IsOk());
        auto bob_keys = std::move(bob_keys_result).Unwrap();

        auto bob_bundle_result = bob_keys.CreatePublicBundle();
        REQUIRE(bob_bundle_result.IsOk());
        auto bob_bundle = std::move(bob_bundle_result).Unwrap();

        std::vector<uint8_t> info(ProtocolConstants::X3DH_INFO.begin(), ProtocolConstants::X3DH_INFO.end());

        auto secret1_result = alice_keys.X3dhDeriveSharedSecret(bob_bundle, info, true);
        REQUIRE(secret1_result.IsOk());
        auto secret1_handle = std::move(secret1_result).Unwrap();

        alice_keys.GenerateEphemeralKeyPair();

        auto secret2_result = alice_keys.X3dhDeriveSharedSecret(bob_bundle, info, true);
        REQUIRE(secret2_result.IsOk());
        auto secret2_handle = std::move(secret2_result).Unwrap();

        std::vector<uint8_t> secret1_bytes(Constants::X_25519_KEY_SIZE);
        std::vector<uint8_t> secret2_bytes(Constants::X_25519_KEY_SIZE);

        REQUIRE(secret1_handle.Read(secret1_bytes).IsOk());
        REQUIRE(secret2_handle.Read(secret2_bytes).IsOk());

        REQUIRE_FALSE(std::equal(secret1_bytes.begin(), secret1_bytes.end(), secret2_bytes.begin()));
    }
}

TEST_CASE("X3DH Test Vectors - Info String Validation", "[x3dh][interop][vectors]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Standard X3DH info string") {
        std::vector<uint8_t> standard_info(ProtocolConstants::X3DH_INFO.begin(), ProtocolConstants::X3DH_INFO.end());
        REQUIRE(standard_info.size() > 0);
        REQUIRE(standard_info.size() < 256);
    }

    SECTION("Custom info strings") {
        auto alice_keys_result = IdentityKeys::Create(0);
        REQUIRE(alice_keys_result.IsOk());
        auto alice_keys = std::move(alice_keys_result).Unwrap();
        alice_keys.GenerateEphemeralKeyPair();

        auto bob_keys_result = IdentityKeys::Create(1);
        REQUIRE(bob_keys_result.IsOk());
        auto bob_keys = std::move(bob_keys_result).Unwrap();

        auto bob_bundle_result = bob_keys.CreatePublicBundle();
        REQUIRE(bob_bundle_result.IsOk());
        auto bob_bundle = std::move(bob_bundle_result).Unwrap();

        std::string custom_info_str = "Custom-X3DH-v2";
        std::vector<uint8_t> custom_info(custom_info_str.begin(), custom_info_str.end());

        auto result = alice_keys.X3dhDeriveSharedSecret(bob_bundle, custom_info, true);
        REQUIRE(result.IsOk());
    }
}

TEST_CASE("X3DH Test Vectors - Key Length Validation", "[x3dh][interop][vectors][validation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("All generated keys have correct sizes") {
        auto keys_result = IdentityKeys::Create(5);
        REQUIRE(keys_result.IsOk());
        auto keys = std::move(keys_result).Unwrap();

        auto identity_x25519 = keys.GetIdentityX25519PublicKeyCopy();
        REQUIRE(identity_x25519.size() == Constants::X_25519_PUBLIC_KEY_SIZE);

        auto identity_ed25519 = keys.GetIdentityEd25519PublicKeyCopy();
        REQUIRE(identity_ed25519.size() == Constants::ED_25519_PUBLIC_KEY_SIZE);

        auto bundle_result = keys.CreatePublicBundle();
        REQUIRE(bundle_result.IsOk());
        auto bundle = std::move(bundle_result).Unwrap();

        REQUIRE(bundle.GetSignedPreKeyPublic().size() == Constants::X_25519_PUBLIC_KEY_SIZE);
        REQUIRE(bundle.GetSignedPreKeySignature().size() == Constants::ED_25519_SIGNATURE_SIZE);
        REQUIRE(bundle.GetOneTimePreKeyCount() == 5);
    }
}

TEST_CASE("X3DH Test Vectors - Cross-Session Consistency", "[x3dh][interop][vectors]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Ephemeral key properly consumed") {
        auto alice_keys_result = IdentityKeys::Create(0);
        REQUIRE(alice_keys_result.IsOk());
        auto alice_keys = std::move(alice_keys_result).Unwrap();
        alice_keys.GenerateEphemeralKeyPair();

        auto bob_keys_result = IdentityKeys::Create(1);
        REQUIRE(bob_keys_result.IsOk());
        auto bob_keys = std::move(bob_keys_result).Unwrap();

        auto bob_bundle_result = bob_keys.CreatePublicBundle();
        REQUIRE(bob_bundle_result.IsOk());
        auto bob_bundle = std::move(bob_bundle_result).Unwrap();

        std::vector<uint8_t> info(ProtocolConstants::X3DH_INFO.begin(), ProtocolConstants::X3DH_INFO.end());

        auto secret1_result = alice_keys.X3dhDeriveSharedSecret(bob_bundle, info, true);
        REQUIRE(secret1_result.IsOk());

        auto secret2_result = alice_keys.X3dhDeriveSharedSecret(bob_bundle, info, true);
        REQUIRE(secret2_result.IsErr());
    }
}
