#include "ecliptix/identity/ecliptix_system_identity_keys.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/crypto/master_key_derivation.hpp"

#include <sodium.h>
#include <algorithm>
#include <unordered_set>

namespace ecliptix::protocol::identity {

using protocol::Constants;
using crypto::SodiumInterop;
using crypto::MasterKeyDerivation;
using crypto::Hkdf;
using models::SignedPreKeyMaterial;
using models::OneTimePreKeyRecord;

// ============================================================================
// Constructor
// ============================================================================

EcliptixSystemIdentityKeys::EcliptixSystemIdentityKeys(IdentityKeysMaterial material)
    : ed25519_secret_key_handle_(std::move(material.ed25519).TakeSecretKeyHandle())
    , ed25519_public_key_(std::move(material.ed25519).TakePublicKey())
    , identity_x25519_secret_key_handle_(std::move(material.identity_x25519).TakeSecretKeyHandle())
    , identity_x25519_public_key_(std::move(material.identity_x25519).TakePublicKey())
    , signed_pre_key_id_(material.signed_pre_key.GetId())
    , signed_pre_key_secret_key_handle_(std::move(material.signed_pre_key).TakeSecretKeyHandle())
    , signed_pre_key_public_(std::move(material.signed_pre_key).TakePublicKey())
    , signed_pre_key_signature_(std::move(material.signed_pre_key).TakeSignature())
    , one_time_pre_keys_(std::move(material.one_time_pre_keys))
    , ephemeral_secret_key_handle_(std::nullopt)
    , ephemeral_x25519_public_key_(std::nullopt) {
}

// ============================================================================
// Public Key Access
// ============================================================================

std::vector<uint8_t> EcliptixSystemIdentityKeys::GetIdentityX25519PublicKeyCopy() const {
    return identity_x25519_public_key_;
}

// ============================================================================
// Key Generation Helpers
// ============================================================================

Result<Ed25519KeyMaterial, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::GenerateEd25519Keys() {
    // Generate Ed25519 keypair
    std::vector<uint8_t> public_key(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> secret_key(crypto_sign_SECRETKEYBYTES);

    if (crypto_sign_keypair(public_key.data(), secret_key.data()) != 0) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(secret_key));
        return Result<Ed25519KeyMaterial, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::KeyGeneration("Failed to generate Ed25519 keypair"));
    }

    // Allocate secure memory for secret key
    auto handle_result = SecureMemoryHandle::Allocate(Constants::ED_25519_SECRET_KEY_SIZE);
    if (handle_result.IsErr()) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(secret_key));
        return Result<Ed25519KeyMaterial, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(handle_result.UnwrapErr().message));
    }

    auto handle = std::move(handle_result).Unwrap();

    // Write secret key to secure memory
    auto write_result = handle.Write(std::span<const uint8_t>(secret_key));
    SodiumInterop::SecureWipe(std::span<uint8_t>(secret_key));

    if (write_result.IsErr()) {
        return Result<Ed25519KeyMaterial, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(write_result.UnwrapErr().message));
    }

    return Result<Ed25519KeyMaterial, EcliptixProtocolFailure>::Ok(
        Ed25519KeyMaterial(std::move(handle), std::move(public_key)));
}

Result<X25519KeyMaterial, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::GenerateX25519IdentityKeys() {
    auto result = SodiumInterop::GenerateX25519KeyPair("identity-x25519");
    if (result.IsErr()) {
        return Result<X25519KeyMaterial, EcliptixProtocolFailure>::Err(result.UnwrapErr());
    }

    auto [handle, public_key] = std::move(result).Unwrap();
    return Result<X25519KeyMaterial, EcliptixProtocolFailure>::Ok(
        X25519KeyMaterial(std::move(handle), std::move(public_key)));
}

Result<X25519KeyMaterial, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::GenerateX25519SignedPreKey(
    uint32_t id) {
    auto result = SodiumInterop::GenerateX25519KeyPair("signed-pre-key");
    if (result.IsErr()) {
        return Result<X25519KeyMaterial, EcliptixProtocolFailure>::Err(result.UnwrapErr());
    }

    auto [handle, public_key] = std::move(result).Unwrap();
    return Result<X25519KeyMaterial, EcliptixProtocolFailure>::Ok(
        X25519KeyMaterial(std::move(handle), std::move(public_key)));
}

Result<std::vector<uint8_t>, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::SignSignedPreKey(
    const SecureMemoryHandle& ed_secret_key_handle,
    std::span<const uint8_t> spk_public) {

    // Read Ed25519 secret key from secure memory
    auto read_result = ed_secret_key_handle.ReadBytes(Constants::ED_25519_SECRET_KEY_SIZE);
    if (read_result.IsErr()) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(read_result.UnwrapErr().message));
    }

    auto secret_key = std::move(read_result).Unwrap();

    // Sign the public key
    std::vector<uint8_t> signature(crypto_sign_BYTES);
    unsigned long long sig_len;

    int result = crypto_sign_detached(
        signature.data(),
        &sig_len,
        spk_public.data(),
        spk_public.size(),
        secret_key.data());

    SodiumInterop::SecureWipe(std::span<uint8_t>(secret_key));

    if (result != 0) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("Failed to sign signed pre-key public key"));
    }

    if (sig_len != Constants::ED_25519_SIGNATURE_SIZE) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("Generated signature has incorrect size"));
    }

    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(std::move(signature));
}

Result<std::vector<OneTimePreKeyLocal>, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::GenerateOneTimePreKeys(
    uint32_t count) {

    if (count == 0) {
        return Result<std::vector<OneTimePreKeyLocal>, EcliptixProtocolFailure>::Ok(
            std::vector<OneTimePreKeyLocal>{});
    }

    std::vector<OneTimePreKeyLocal> opks;
    opks.reserve(count);

    std::unordered_set<uint32_t> used_ids;
    used_ids.reserve(count);

    uint32_t id_counter = 2;

    for (uint32_t i = 0; i < count; ++i) {
        // Generate unique ID
        uint32_t id = id_counter++;
        while (used_ids.count(id) > 0) {
            // Generate random ID if sequential is taken
            auto random_bytes = SodiumInterop::GetRandomBytes(sizeof(uint32_t));
            std::memcpy(&id, random_bytes.data(), sizeof(uint32_t));
        }
        used_ids.insert(id);

        // Generate OPK
        auto opk_result = OneTimePreKeyLocal::Generate(id);
        if (opk_result.IsErr()) {
            return Result<std::vector<OneTimePreKeyLocal>, EcliptixProtocolFailure>::Err(
                opk_result.UnwrapErr());
        }

        opks.push_back(std::move(opk_result).Unwrap());
    }

    return Result<std::vector<OneTimePreKeyLocal>, EcliptixProtocolFailure>::Ok(std::move(opks));
}

// ============================================================================
// Factory Methods
// ============================================================================

Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::Create(
    uint32_t one_time_key_count) {

    // Generate Ed25519 identity keypair
    auto ed_result = GenerateEd25519Keys();
    if (ed_result.IsErr()) {
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            ed_result.UnwrapErr());
    }
    auto ed_keys = std::move(ed_result).Unwrap();

    // Generate X25519 identity keypair
    auto id_x_result = GenerateX25519IdentityKeys();
    if (id_x_result.IsErr()) {
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            id_x_result.UnwrapErr());
    }
    auto id_x_keys = std::move(id_x_result).Unwrap();

    // Generate random signed pre-key ID
    auto random_id = SodiumInterop::GetRandomBytes(sizeof(uint32_t));
    uint32_t spk_id;
    std::memcpy(&spk_id, random_id.data(), sizeof(uint32_t));

    // Generate signed pre-key
    auto spk_result = GenerateX25519SignedPreKey(spk_id);
    if (spk_result.IsErr()) {
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            spk_result.UnwrapErr());
    }
    auto spk_keys = std::move(spk_result).Unwrap();
    auto spk_public = spk_keys.GetPublicKeyCopy();

    // Sign the signed pre-key
    auto signature_result = SignSignedPreKey(ed_keys.GetSecretKeyHandle(), spk_public);
    if (signature_result.IsErr()) {
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            signature_result.UnwrapErr());
    }
    auto spk_signature = std::move(signature_result).Unwrap();

    // Generate one-time pre-keys
    auto opks_result = GenerateOneTimePreKeys(one_time_key_count);
    if (opks_result.IsErr()) {
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            opks_result.UnwrapErr());
    }
    auto opks = std::move(opks_result).Unwrap();

    // Create signed pre-key material
    auto spk_material = SignedPreKeyMaterial(
        spk_id,
        std::move(spk_keys).TakeSecretKeyHandle(),
        std::move(spk_keys).TakePublicKey(),
        std::move(spk_signature));

    // Bundle everything into IdentityKeysMaterial
    IdentityKeysMaterial material(
        std::move(ed_keys),
        std::move(id_x_keys),
        std::move(spk_material),
        std::move(opks));

    return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Ok(
        EcliptixSystemIdentityKeys(std::move(material)));
}

Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::CreateFromMasterKey(
    std::span<const uint8_t> master_key,
    std::string_view membership_id,
    uint32_t one_time_key_count) {

    // Derive Ed25519 seed
    auto ed_seed = MasterKeyDerivation::DeriveEd25519Seed(master_key, membership_id);

    // Generate Ed25519 keypair from seed
    std::vector<uint8_t> ed_public(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> ed_secret(crypto_sign_SECRETKEYBYTES);

    if (crypto_sign_seed_keypair(ed_public.data(), ed_secret.data(), ed_seed.data()) != 0) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(ed_seed));
        SodiumInterop::SecureWipe(std::span<uint8_t>(ed_secret));
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::KeyGeneration("Failed to generate Ed25519 keypair from seed"));
    }

    SodiumInterop::SecureWipe(std::span<uint8_t>(ed_seed));

    // Store Ed25519 secret key in secure memory
    auto ed_handle_result = SecureMemoryHandle::Allocate(Constants::ED_25519_SECRET_KEY_SIZE);
    if (ed_handle_result.IsErr()) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(ed_secret));
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(ed_handle_result.UnwrapErr().message));
    }

    auto ed_handle = std::move(ed_handle_result).Unwrap();
    auto ed_write_result = ed_handle.Write(std::span<const uint8_t>(ed_secret));
    SodiumInterop::SecureWipe(std::span<uint8_t>(ed_secret));

    if (ed_write_result.IsErr()) {
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(ed_write_result.UnwrapErr().message));
    }

    auto ed_material = Ed25519KeyMaterial(std::move(ed_handle), std::move(ed_public));

    // Derive X25519 identity seed
    auto x_seed = MasterKeyDerivation::DeriveX25519Seed(master_key, membership_id);

    // Clamp the seed for X25519 (required by the protocol)
    x_seed[0] &= 248;
    x_seed[31] &= 127;
    x_seed[31] |= 64;

    // Compute X25519 public key from secret
    std::vector<uint8_t> x_public(crypto_scalarmult_BYTES);
    if (crypto_scalarmult_base(x_public.data(), x_seed.data()) != 0) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(x_seed));
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::KeyGeneration("Failed to derive X25519 public key"));
    }

    // Store X25519 secret in secure memory
    auto x_handle_result = SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE);
    if (x_handle_result.IsErr()) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(x_seed));
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(x_handle_result.UnwrapErr().message));
    }

    auto x_handle = std::move(x_handle_result).Unwrap();
    auto x_write_result = x_handle.Write(std::span<const uint8_t>(x_seed));
    SodiumInterop::SecureWipe(std::span<uint8_t>(x_seed));

    if (x_write_result.IsErr()) {
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(x_write_result.UnwrapErr().message));
    }

    auto x_material = X25519KeyMaterial(std::move(x_handle), std::move(x_public));

    // Derive signed pre-key seed
    auto spk_seed = MasterKeyDerivation::DeriveSignedPreKeySeed(master_key, membership_id);

    // Extract SPK ID from first 4 bytes
    uint32_t spk_id;
    std::memcpy(&spk_id, spk_seed.data(), sizeof(uint32_t));

    // Use remaining bytes as private key
    std::vector<uint8_t> spk_secret(Constants::X_25519_PRIVATE_KEY_SIZE);
    std::memcpy(spk_secret.data(), spk_seed.data(), Constants::X_25519_PRIVATE_KEY_SIZE);
    SodiumInterop::SecureWipe(std::span<uint8_t>(spk_seed));

    // Clamp SPK secret
    spk_secret[0] &= 248;
    spk_secret[31] &= 127;
    spk_secret[31] |= 64;

    // Compute SPK public key
    std::vector<uint8_t> spk_public(crypto_scalarmult_BYTES);
    if (crypto_scalarmult_base(spk_public.data(), spk_secret.data()) != 0) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(spk_secret));
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::KeyGeneration("Failed to derive signed pre-key public key"));
    }

    // Store SPK secret in secure memory
    auto spk_handle_result = SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE);
    if (spk_handle_result.IsErr()) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(spk_secret));
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(spk_handle_result.UnwrapErr().message));
    }

    auto spk_handle = std::move(spk_handle_result).Unwrap();
    auto spk_write_result = spk_handle.Write(std::span<const uint8_t>(spk_secret));
    SodiumInterop::SecureWipe(std::span<uint8_t>(spk_secret));

    if (spk_write_result.IsErr()) {
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(spk_write_result.UnwrapErr().message));
    }

    // Sign the signed pre-key with Ed25519 identity key
    auto signature_result = SignSignedPreKey(ed_material.GetSecretKeyHandle(), spk_public);
    if (signature_result.IsErr()) {
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            signature_result.UnwrapErr());
    }
    auto spk_signature = std::move(signature_result).Unwrap();

    auto spk_material = SignedPreKeyMaterial(
        spk_id,
        std::move(spk_handle),
        std::move(spk_public),
        std::move(spk_signature));

    // Generate one-time pre-keys (still random, not derived)
    auto opks_result = GenerateOneTimePreKeys(one_time_key_count);
    if (opks_result.IsErr()) {
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
            opks_result.UnwrapErr());
    }
    auto opks = std::move(opks_result).Unwrap();

    // Bundle everything
    IdentityKeysMaterial material(
        std::move(ed_material),
        std::move(x_material),
        std::move(spk_material),
        std::move(opks));

    return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Ok(
        EcliptixSystemIdentityKeys(std::move(material)));
}

// ============================================================================
// Bundle Operations
// ============================================================================

Result<LocalPublicKeyBundle, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::CreatePublicBundle() const {
    // Create OPK records (public only)
    std::vector<OneTimePreKeyRecord> opk_records;
    opk_records.reserve(one_time_pre_keys_.size());

    for (const auto& opk : one_time_pre_keys_) {
        opk_records.emplace_back(opk.GetPreKeyId(), opk.GetPublicKeyCopy());
    }

    // Create bundle
    LocalPublicKeyBundle bundle(
        ed25519_public_key_,
        identity_x25519_public_key_,
        signed_pre_key_id_,
        signed_pre_key_public_,
        signed_pre_key_signature_,
        std::move(opk_records),
        ephemeral_x25519_public_key_);

    return Result<LocalPublicKeyBundle, EcliptixProtocolFailure>::Ok(std::move(bundle));
}

void EcliptixSystemIdentityKeys::GenerateEphemeralKeyPair() {
    // Clear existing ephemeral key if any
    ephemeral_secret_key_handle_.reset();
    if (ephemeral_x25519_public_key_.has_value()) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(ephemeral_x25519_public_key_.value()));
    }
    ephemeral_x25519_public_key_.reset();

    // Generate new ephemeral keypair
    auto result = SodiumInterop::GenerateX25519KeyPair("ephemeral-x25519");
    if (result.IsOk()) {
        auto [handle, public_key] = std::move(result).Unwrap();
        ephemeral_secret_key_handle_ = std::move(handle);
        ephemeral_x25519_public_key_ = std::move(public_key);
    }
}

// ============================================================================
// Signature Verification
// ============================================================================

Result<bool, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::VerifyRemoteSpkSignature(
    std::span<const uint8_t> remote_identity_ed25519,
    std::span<const uint8_t> remote_spk_public,
    std::span<const uint8_t> remote_spk_signature) {

    // Validate sizes
    if (remote_identity_ed25519.size() != Constants::ED_25519_PUBLIC_KEY_SIZE ||
        remote_spk_public.size() != Constants::X_25519_PUBLIC_KEY_SIZE ||
        remote_spk_signature.size() != Constants::ED_25519_SIGNATURE_SIZE) {
        return Result<bool, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput("Invalid key or signature length for SPK verification"));
    }

    // Verify signature
    int result = crypto_sign_verify_detached(
        remote_spk_signature.data(),
        remote_spk_public.data(),
        remote_spk_public.size(),
        remote_identity_ed25519.data());

    if (result != 0) {
        return Result<bool, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Handshake("Remote SPK signature verification failed"));
    }

    return Result<bool, EcliptixProtocolFailure>::Ok(true);
}

// ============================================================================
// X3DH Validation Helpers
// ============================================================================

Result<Unit, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::ValidateHkdfInfo(
    std::span<const uint8_t> info) {

    if (info.empty()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::DeriveKey("HKDF info cannot be empty"));
    }

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

Result<Unit, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::ValidateRemoteBundle(
    const LocalPublicKeyBundle& remote_bundle) {

    // Validate identity X25519 key
    if (remote_bundle.GetIdentityX25519().size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::PeerPubKey("Invalid remote identity X25519 key"));
    }

    // Validate signed pre-key
    if (remote_bundle.GetSignedPreKeyPublic().size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::PeerPubKey("Invalid remote signed pre-key public key"));
    }

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

Result<Unit, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::EnsureLocalKeysValid() const {
    // Check ephemeral key
    if (!ephemeral_secret_key_handle_.has_value() ||
        ephemeral_secret_key_handle_.value().IsInvalid()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::PrepareLocal("Local ephemeral key missing or invalid"));
    }

    // Check identity key
    if (identity_x25519_secret_key_handle_.IsInvalid()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::PrepareLocal("Local identity key missing or invalid"));
    }

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

Result<Unit, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::ValidateX3dhPrerequisites(
    const LocalPublicKeyBundle& remote_bundle,
    std::span<const uint8_t> info) const {

    TRY(ValidateHkdfInfo(info));
    TRY(ValidateRemoteBundle(remote_bundle));
    TRY(EnsureLocalKeysValid());

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

// ============================================================================
// X3DH Diffie-Hellman Operations
// ============================================================================

Result<size_t, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::PerformX3dhDiffieHellman(
    std::span<const uint8_t> ephemeral_secret,
    std::span<const uint8_t> identity_secret,
    const LocalPublicKeyBundle& remote_bundle,
    bool use_opk,
    std::span<uint8_t> dh_results_output) {

    size_t offset = 0;

    // DH1 = DH(IK_local, SPK_remote)
    std::vector<uint8_t> dh1(Constants::X_25519_KEY_SIZE);
    if (crypto_scalarmult(
            dh1.data(),
            identity_secret.data(),
            remote_bundle.GetSignedPreKeyPublic().data()) != 0) {
        return Result<size_t, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("DH1 computation failed"));
    }
    std::memcpy(dh_results_output.data() + offset, dh1.data(), Constants::X_25519_KEY_SIZE);
    offset += Constants::X_25519_KEY_SIZE;
    SodiumInterop::SecureWipe(std::span<uint8_t>(dh1));

    // DH2 = DH(EK_local, IK_remote)
    std::vector<uint8_t> dh2(Constants::X_25519_KEY_SIZE);
    if (crypto_scalarmult(
            dh2.data(),
            ephemeral_secret.data(),
            remote_bundle.GetIdentityX25519().data()) != 0) {
        return Result<size_t, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("DH2 computation failed"));
    }
    std::memcpy(dh_results_output.data() + offset, dh2.data(), Constants::X_25519_KEY_SIZE);
    offset += Constants::X_25519_KEY_SIZE;
    SodiumInterop::SecureWipe(std::span<uint8_t>(dh2));

    // DH3 = DH(EK_local, SPK_remote)
    std::vector<uint8_t> dh3(Constants::X_25519_KEY_SIZE);
    if (crypto_scalarmult(
            dh3.data(),
            ephemeral_secret.data(),
            remote_bundle.GetSignedPreKeyPublic().data()) != 0) {
        return Result<size_t, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("DH3 computation failed"));
    }
    std::memcpy(dh_results_output.data() + offset, dh3.data(), Constants::X_25519_KEY_SIZE);
    offset += Constants::X_25519_KEY_SIZE;
    SodiumInterop::SecureWipe(std::span<uint8_t>(dh3));

    // DH4 = DH(EK_local, OPK_remote) [optional]
    if (use_opk && remote_bundle.HasOneTimePreKeys()) {
        const auto& opks = remote_bundle.GetOneTimePreKeys();
        if (!opks.empty() && opks[0].GetPublicKeySpan().size() == Constants::X_25519_PUBLIC_KEY_SIZE) {
            std::vector<uint8_t> dh4(Constants::X_25519_KEY_SIZE);
            if (crypto_scalarmult(
                    dh4.data(),
                    ephemeral_secret.data(),
                    opks[0].GetPublicKeySpan().data()) != 0) {
                return Result<size_t, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("DH4 computation failed"));
            }
            std::memcpy(dh_results_output.data() + offset, dh4.data(), Constants::X_25519_KEY_SIZE);
            offset += Constants::X_25519_KEY_SIZE;
            SodiumInterop::SecureWipe(std::span<uint8_t>(dh4));
        }
    }

    return Result<size_t, EcliptixProtocolFailure>::Ok(offset);
}

// ============================================================================
// X3DH Key Agreement
// ============================================================================

Result<SecureMemoryHandle, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::X3dhDeriveSharedSecret(
    const LocalPublicKeyBundle& remote_bundle,
    std::span<const uint8_t> info) {

    // Validate prerequisites
    auto validation_result = ValidateX3dhPrerequisites(remote_bundle, info);
    if (validation_result.IsErr()) {
        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
            validation_result.UnwrapErr());
    }

    // Read ephemeral secret key
    auto eph_read_result = ephemeral_secret_key_handle_.value().ReadBytes(
        Constants::X_25519_PRIVATE_KEY_SIZE);
    if (eph_read_result.IsErr()) {
        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(eph_read_result.UnwrapErr().message));
    }
    auto ephemeral_secret = std::move(eph_read_result).Unwrap();

    // Read identity secret key
    auto id_read_result = identity_x25519_secret_key_handle_.ReadBytes(
        Constants::X_25519_PRIVATE_KEY_SIZE);
    if (id_read_result.IsErr()) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(ephemeral_secret));
        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(id_read_result.UnwrapErr().message));
    }
    auto identity_secret = std::move(id_read_result).Unwrap();

    // Perform X3DH Diffie-Hellman operations
    std::vector<uint8_t> dh_results(Constants::X_25519_KEY_SIZE * 4);
    bool use_opk = remote_bundle.HasOneTimePreKeys();

    auto dh_result = PerformX3dhDiffieHellman(
        ephemeral_secret,
        identity_secret,
        remote_bundle,
        use_opk,
        dh_results);

    SodiumInterop::SecureWipe(std::span<uint8_t>(ephemeral_secret));
    SodiumInterop::SecureWipe(std::span<uint8_t>(identity_secret));

    if (dh_result.IsErr()) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(dh_results));
        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
            dh_result.UnwrapErr());
    }

    size_t dh_offset = std::move(dh_result).Unwrap();

    // Build IKM: 0xFF || DH1 || DH2 || DH3 || [DH4]
    std::vector<uint8_t> ikm(Constants::X_25519_KEY_SIZE + dh_offset);
    std::fill_n(ikm.begin(), Constants::X_25519_KEY_SIZE, 0xFF);
    std::memcpy(ikm.data() + Constants::X_25519_KEY_SIZE, dh_results.data(), dh_offset);
    SodiumInterop::SecureWipe(std::span<uint8_t>(dh_results));

    // Derive shared secret using HKDF-SHA256
    std::vector<uint8_t> shared_secret(Constants::X_25519_KEY_SIZE);
    auto hkdf_result = Hkdf::DeriveKey(ikm, shared_secret, {}, info);
    SodiumInterop::SecureWipe(std::span<uint8_t>(ikm));

    if (hkdf_result.IsErr()) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(shared_secret));
        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
            hkdf_result.UnwrapErr());
    }

    // Store in secure memory
    auto handle_result = SecureMemoryHandle::Allocate(Constants::X_25519_KEY_SIZE);
    if (handle_result.IsErr()) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(shared_secret));
        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(handle_result.UnwrapErr().message));
    }

    auto handle = std::move(handle_result).Unwrap();
    auto write_result = handle.Write(std::span<const uint8_t>(shared_secret));
    SodiumInterop::SecureWipe(std::span<uint8_t>(shared_secret));

    if (write_result.IsErr()) {
        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(write_result.UnwrapErr().message));
    }

    // Clear ephemeral key after use
    ephemeral_secret_key_handle_.reset();
    if (ephemeral_x25519_public_key_.has_value()) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(ephemeral_x25519_public_key_.value()));
    }
    ephemeral_x25519_public_key_.reset();

    return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Ok(std::move(handle));
}

} // namespace ecliptix::protocol::identity
