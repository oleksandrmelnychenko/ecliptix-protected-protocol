#include "ecliptix/identity/ecliptix_system_identity_keys.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/crypto/master_key_derivation.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include <sodium.h>
#include <algorithm>
#include <unordered_set>

namespace ecliptix::protocol::identity {
    using protocol::Constants;
    using protocol::ProtocolConstants;
    using crypto::SodiumInterop;
    using crypto::MasterKeyDerivation;
    using crypto::Hkdf;
    using crypto::KyberInterop;
    using models::SignedPreKeyMaterial;
    using models::OneTimePreKeyRecord;

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
          , kyber_secret_key_handle_(std::move(material.kyber_secret_key))
          , kyber_public_key_(std::move(material.kyber_public_key))
          , pending_kyber_handshake_(std::nullopt)
          , ephemeral_secret_key_handle_(std::nullopt)
          , ephemeral_x25519_public_key_(std::nullopt) {
    }

    std::vector<uint8_t> EcliptixSystemIdentityKeys::GetIdentityX25519PublicKeyCopy() const {
        return identity_x25519_public_key_;
    }

    std::vector<uint8_t> EcliptixSystemIdentityKeys::GetIdentityEd25519PublicKeyCopy() const {
        return ed25519_public_key_;
    }

    std::vector<uint8_t> EcliptixSystemIdentityKeys::GetKyberPublicKeyCopy() const {
        return kyber_public_key_;
    }

    Result<SecureMemoryHandle, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::CloneKyberSecretKey() const {
        auto read_result = kyber_secret_key_handle_.ReadBytes(KyberInterop::KYBER_768_SECRET_KEY_SIZE);
        if (read_result.IsErr()) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(read_result.UnwrapErr()));
        }
        auto secret_bytes = read_result.Unwrap();
        auto copy_alloc = SecureMemoryHandle::Allocate(KyberInterop::KYBER_768_SECRET_KEY_SIZE);
        if (copy_alloc.IsErr()) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(copy_alloc.UnwrapErr()));
        }
        auto copy_handle = std::move(copy_alloc).Unwrap();
        if (auto write_result = copy_handle.Write(secret_bytes); write_result.IsErr()) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(write_result.UnwrapErr()));
        }
        auto _wipe = SodiumInterop::SecureWipe(std::span(secret_bytes));
        (void) _wipe;
        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Ok(std::move(copy_handle));
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    EcliptixSystemIdentityKeys::GetEphemeralX25519PrivateKeyCopy() const {
        if (!ephemeral_secret_key_handle_.has_value()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Ephemeral key has not been generated"));
        }
        auto read_result = ephemeral_secret_key_handle_->ReadBytes(Constants::X_25519_PRIVATE_KEY_SIZE);
        if (read_result.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(read_result.UnwrapErr()));
        }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(read_result.Unwrap());
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    EcliptixSystemIdentityKeys::GetSignedPreKeyPrivateCopy() const {
        auto read_result = signed_pre_key_secret_key_handle_.ReadBytes(Constants::X_25519_PRIVATE_KEY_SIZE);
        if (read_result.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(read_result.UnwrapErr()));
        }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(read_result.Unwrap());
    }

    Result<Ed25519KeyMaterial, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::GenerateEd25519Keys() {
        std::vector<uint8_t> public_key(crypto_sign_PUBLICKEYBYTES);
        std::vector<uint8_t> secret_key(crypto_sign_SECRETKEYBYTES);
        if (crypto_sign_keypair(public_key.data(), secret_key.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(secret_key));
            return Result<Ed25519KeyMaterial, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::KeyGeneration("Failed to generate Ed25519 keypair"));
        }
        auto handle_result = SecureMemoryHandle::Allocate(Constants::ED_25519_SECRET_KEY_SIZE);
        if (handle_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(secret_key));
            return Result<Ed25519KeyMaterial, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(handle_result.UnwrapErr().message));
        }
        auto handle = std::move(handle_result).Unwrap();
        auto write_result = handle.Write(std::span<const uint8_t>(secret_key));
        SodiumInterop::SecureWipe(std::span(secret_key));
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

    Result<X25519KeyMaterial, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::GenerateX25519SignedPreKey() {
        auto result = SodiumInterop::GenerateX25519KeyPair("signed-pre-key");
        if (result.IsErr()) {
            return Result<X25519KeyMaterial, EcliptixProtocolFailure>::Err(result.UnwrapErr());
        }
        auto [handle, public_key] = std::move(result).Unwrap();
        return Result<X25519KeyMaterial, EcliptixProtocolFailure>::Ok(
            X25519KeyMaterial(std::move(handle), std::move(public_key)));
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::SignSignedPreKey(
        const SecureMemoryHandle &ed_secret_key_handle,
        const std::span<const uint8_t> spk_public) {
        auto read_result = ed_secret_key_handle.ReadBytes(Constants::ED_25519_SECRET_KEY_SIZE);
        if (read_result.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(read_result.UnwrapErr().message));
        }
        auto secret_key = std::move(read_result).Unwrap();
        std::vector<uint8_t> signature(crypto_sign_BYTES);
        unsigned long long sig_len;
        const int result = crypto_sign_detached(
            signature.data(),
            &sig_len,
            spk_public.data(),
            spk_public.size(),
            secret_key.data());
        SodiumInterop::SecureWipe(std::span(secret_key));
        if (result != SodiumConstants::SUCCESS) {
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
        const uint32_t count) {
        if (count == ProtocolConstants::ZERO_VALUE) {
            return Result<std::vector<OneTimePreKeyLocal>, EcliptixProtocolFailure>::Ok(
                std::vector<OneTimePreKeyLocal>{});
        }
        std::vector<OneTimePreKeyLocal> opks;
        opks.reserve(count);
        std::unordered_set<uint32_t> used_ids;
        used_ids.reserve(count);
        uint32_t id_counter = 2;
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t id = id_counter++;
            while (used_ids.count(id) > ProtocolConstants::ZERO_VALUE) {
                auto random_bytes = SodiumInterop::GetRandomBytes(sizeof(uint32_t));
                std::memcpy(&id, random_bytes.data(), sizeof(uint32_t));
            }
            used_ids.insert(id);
            auto opk_result = OneTimePreKeyLocal::Generate(id);
            if (opk_result.IsErr()) {
                return Result<std::vector<OneTimePreKeyLocal>, EcliptixProtocolFailure>::Err(
                    opk_result.UnwrapErr());
            }
            opks.push_back(std::move(opk_result).Unwrap());
        }
        return Result<std::vector<OneTimePreKeyLocal>, EcliptixProtocolFailure>::Ok(std::move(opks));
    }

    Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::Create(
        uint32_t one_time_key_count) {
        auto ed_result = GenerateEd25519Keys();
        if (ed_result.IsErr()) {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                ed_result.UnwrapErr());
        }
        auto ed_keys = std::move(ed_result).Unwrap();
        auto id_x_result = GenerateX25519IdentityKeys();
        if (id_x_result.IsErr()) {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                id_x_result.UnwrapErr());
        }
        auto id_x_keys = std::move(id_x_result).Unwrap();
        auto random_id = SodiumInterop::GetRandomBytes(sizeof(uint32_t));
        uint32_t spk_id;
        std::memcpy(&spk_id, random_id.data(), sizeof(uint32_t));
        auto spk_result = GenerateX25519SignedPreKey();
        if (spk_result.IsErr()) {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                spk_result.UnwrapErr());
        }
        auto spk_keys = std::move(spk_result).Unwrap();
        auto spk_public = spk_keys.GetPublicKeyCopy();
        auto signature_result = SignSignedPreKey(ed_keys.GetSecretKeyHandle(), spk_public);
        if (signature_result.IsErr()) {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                signature_result.UnwrapErr());
        }
        auto spk_signature = std::move(signature_result).Unwrap();
        auto opks_result = GenerateOneTimePreKeys(one_time_key_count);
        if (opks_result.IsErr()) {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                opks_result.UnwrapErr());
        }
        auto opks = std::move(opks_result).Unwrap();
        auto kyber_result = KyberInterop::GenerateKyber768KeyPair("identity-kyber");
        if (kyber_result.IsErr()) {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(kyber_result.UnwrapErr()));
        }
        auto [kyber_secret, kyber_public] = std::move(kyber_result).Unwrap();
        auto spk_material = SignedPreKeyMaterial(
            spk_id,
            std::move(spk_keys).TakeSecretKeyHandle(),
            std::move(spk_keys).TakePublicKey(),
            std::move(spk_signature));
        IdentityKeysMaterial material(
            std::move(ed_keys),
            std::move(id_x_keys),
            std::move(spk_material),
            std::move(opks),
            std::move(kyber_secret),
            std::move(kyber_public));
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Ok(
            EcliptixSystemIdentityKeys(std::move(material)));
    }

    Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::CreateFromMasterKey(
        std::span<const uint8_t> master_key,
        std::string_view membership_id,
        uint32_t one_time_key_count) {
        auto ed_seed = MasterKeyDerivation::DeriveEd25519Seed(master_key, membership_id);
        std::vector<uint8_t> ed_public(crypto_sign_PUBLICKEYBYTES);
        std::vector<uint8_t> ed_secret(crypto_sign_SECRETKEYBYTES);
        if (crypto_sign_seed_keypair(ed_public.data(), ed_secret.data(), ed_seed.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(ed_seed));
            SodiumInterop::SecureWipe(std::span(ed_secret));
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::KeyGeneration("Failed to generate Ed25519 keypair from seed"));
        }
        SodiumInterop::SecureWipe(std::span(ed_seed));
        auto ed_handle_result = SecureMemoryHandle::Allocate(Constants::ED_25519_SECRET_KEY_SIZE);
        if (ed_handle_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(ed_secret));
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(ed_handle_result.UnwrapErr().message));
        }
        auto ed_handle = std::move(ed_handle_result).Unwrap();
        auto ed_write_result = ed_handle.Write(std::span<const uint8_t>(ed_secret));
        SodiumInterop::SecureWipe(std::span(ed_secret));
        if (ed_write_result.IsErr()) {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(ed_write_result.UnwrapErr().message));
        }
        auto ed_material = Ed25519KeyMaterial(std::move(ed_handle), std::move(ed_public));
        auto x_seed = MasterKeyDerivation::DeriveX25519Seed(master_key, membership_id);
        x_seed[0] &= 248;
        x_seed[31] &= 127;
        x_seed[31] |= 64;
        std::vector<uint8_t> x_public(crypto_scalarmult_BYTES);
        if (crypto_scalarmult_base(x_public.data(), x_seed.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(x_seed));
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::KeyGeneration("Failed to derive X25519 public key"));
        }
        auto x_handle_result = SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE);
        if (x_handle_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(x_seed));
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(x_handle_result.UnwrapErr().message));
        }
        auto x_handle = std::move(x_handle_result).Unwrap();
        auto x_write_result = x_handle.Write(std::span<const uint8_t>(x_seed));
        SodiumInterop::SecureWipe(std::span(x_seed));
        if (x_write_result.IsErr()) {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(x_write_result.UnwrapErr().message));
        }
        auto x_material = X25519KeyMaterial(std::move(x_handle), std::move(x_public));
        auto spk_seed = MasterKeyDerivation::DeriveSignedPreKeySeed(master_key, membership_id);
        uint32_t spk_id;
        std::memcpy(&spk_id, spk_seed.data(), sizeof(uint32_t));
        std::vector<uint8_t> spk_secret(Constants::X_25519_PRIVATE_KEY_SIZE);
        std::memcpy(spk_secret.data(), spk_seed.data(), Constants::X_25519_PRIVATE_KEY_SIZE);
        SodiumInterop::SecureWipe(std::span(spk_seed));
        spk_secret[0] &= 248;
        spk_secret[31] &= 127;
        spk_secret[31] |= 64;
        std::vector<uint8_t> spk_public(crypto_scalarmult_BYTES);
        if (crypto_scalarmult_base(spk_public.data(), spk_secret.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::KeyGeneration("Failed to derive signed pre-key public key"));
        }
        auto spk_handle_result = SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE);
        if (spk_handle_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(spk_handle_result.UnwrapErr().message));
        }
        auto spk_handle = std::move(spk_handle_result).Unwrap();
        auto spk_write_result = spk_handle.Write(std::span<const uint8_t>(spk_secret));
        SodiumInterop::SecureWipe(std::span(spk_secret));
        if (spk_write_result.IsErr()) {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(spk_write_result.UnwrapErr().message));
        }
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
        auto opks_result = GenerateOneTimePreKeys(one_time_key_count);
        if (opks_result.IsErr()) {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                opks_result.UnwrapErr());
        }
        auto opks = std::move(opks_result).Unwrap();
        auto kyber_result = KyberInterop::GenerateKyber768KeyPair("identity-kyber");
        if (kyber_result.IsErr()) {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(kyber_result.UnwrapErr()));
        }
        auto [kyber_secret, kyber_public] = std::move(kyber_result).Unwrap();
        IdentityKeysMaterial material(
            std::move(ed_material),
            std::move(x_material),
            std::move(spk_material),
            std::move(opks),
            std::move(kyber_secret),
            std::move(kyber_public));
        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>::Ok(
            EcliptixSystemIdentityKeys(std::move(material)));
    }

    Result<LocalPublicKeyBundle, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::CreatePublicBundle() const {
        std::vector<OneTimePreKeyRecord> opk_records;
        opk_records.reserve(one_time_pre_keys_.size());
        for (const auto &opk: one_time_pre_keys_) {
            opk_records.emplace_back(opk.GetPreKeyId(), opk.GetPublicKeyCopy());
        }
        LocalPublicKeyBundle bundle(
            ed25519_public_key_,
            identity_x25519_public_key_,
            signed_pre_key_id_,
            signed_pre_key_public_,
            signed_pre_key_signature_,
            std::move(opk_records),
            ephemeral_x25519_public_key_,
            kyber_public_key_);
        return Result<LocalPublicKeyBundle, EcliptixProtocolFailure>::Ok(std::move(bundle));
    }

    void EcliptixSystemIdentityKeys::GenerateEphemeralKeyPair() {
        // Only generate if we don't already have an ephemeral key
        if (ephemeral_secret_key_handle_.has_value() && ephemeral_x25519_public_key_.has_value()) {
            return;  // Already have ephemeral key, don't regenerate
        }

        ephemeral_secret_key_handle_.reset();
        if (ephemeral_x25519_public_key_.has_value()) {
            SodiumInterop::SecureWipe(std::span(ephemeral_x25519_public_key_.value()));
        }
        ephemeral_x25519_public_key_.reset();
        if (auto result = SodiumInterop::GenerateX25519KeyPair("ephemeral-x25519"); result.IsOk()) {
            auto [handle, public_key] = std::move(result).Unwrap();
            ephemeral_secret_key_handle_ = std::move(handle);
            ephemeral_x25519_public_key_ = std::move(public_key);
        }
    }

    void EcliptixSystemIdentityKeys::ClearEphemeralKeyPair() {
        // SecureMemoryHandle automatically wipes memory in its destructor via sodium_free()
        // Calling reset() on the optional destroys the handle, triggering secure cleanup
        if (ephemeral_secret_key_handle_.has_value()) {
            ephemeral_secret_key_handle_.reset();
        }
        if (ephemeral_x25519_public_key_.has_value()) {
            SodiumInterop::SecureWipe(std::span(ephemeral_x25519_public_key_.value()));
            ephemeral_x25519_public_key_.reset();
        }
    }

    Result<bool, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::VerifyRemoteSpkSignature(
        const std::span<const uint8_t> remote_identity_ed25519,
        const std::span<const uint8_t> remote_spk_public,
        const std::span<const uint8_t> remote_spk_signature) {
        if (remote_identity_ed25519.size() != Constants::ED_25519_PUBLIC_KEY_SIZE ||
            remote_spk_public.size() != Constants::X_25519_PUBLIC_KEY_SIZE ||
            remote_spk_signature.size() != Constants::ED_25519_SIGNATURE_SIZE) {
            return Result<bool, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Invalid key or signature length for SPK verification"));
        }
        const int result = crypto_sign_verify_detached(
            remote_spk_signature.data(),
            remote_spk_public.data(),
            remote_spk_public.size(),
            remote_identity_ed25519.data());
        if (result != SodiumConstants::SUCCESS) {
            return Result<bool, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Handshake("Remote SPK signature verification failed"));
        }
        return Result<bool, EcliptixProtocolFailure>::Ok(true);
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::ValidateHkdfInfo(
        const std::span<const uint8_t> info) {
        if (info.empty()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::DeriveKey("HKDF info cannot be empty"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::ValidateRemoteBundle(
        const LocalPublicKeyBundle &remote_bundle) {
        if (remote_bundle.GetIdentityX25519().size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::PeerPubKey("Invalid remote identity X25519 key"));
        }
        if (remote_bundle.GetSignedPreKeyPublic().size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::PeerPubKey("Invalid remote signed pre-key public key"));
        }
        if (!remote_bundle.HasKyberKey() || !remote_bundle.GetKyberPublicKey().has_value() ||
            remote_bundle.GetKyberPublicKey()->size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::PeerPubKey("Invalid remote Kyber-768 public key"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::EnsureLocalKeysValid() const {
        if (!ephemeral_secret_key_handle_.has_value() ||
            ephemeral_secret_key_handle_.value().IsInvalid()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::PrepareLocal("Local ephemeral key missing or invalid"));
        }
        if (identity_x25519_secret_key_handle_.IsInvalid()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::PrepareLocal("Local identity key missing or invalid"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::ValidateX3dhPrerequisites(
        const LocalPublicKeyBundle &remote_bundle,
        const std::span<const uint8_t> info) const {
        TRY(ValidateHkdfInfo(info));
        TRY(ValidateRemoteBundle(remote_bundle));
        TRY(EnsureLocalKeysValid());
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    const OneTimePreKeyLocal* EcliptixSystemIdentityKeys::FindOneTimePreKeyById(uint32_t opk_id) const {
        for (const auto& opk : one_time_pre_keys_) {
            if (opk.GetPreKeyId() == opk_id) {
                return &opk;
            }
        }
        return nullptr;
    }

    Result<size_t, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::PerformX3dhDiffieHellmanAsInitiator(
        const std::span<const uint8_t> ephemeral_secret,
        const std::span<const uint8_t> identity_secret,
        const LocalPublicKeyBundle &remote_bundle,
        std::optional<uint32_t> opk_id,
        std::span<uint8_t> dh_results_output) {
        // INITIATOR (Client) X3DH:
        // DH1 = identity_secret × peer.SignedPreKeyPublic
        // DH2 = ephemeral_secret × peer.IdentityX25519
        // DH3 = ephemeral_secret × peer.SignedPreKeyPublic
        // DH4 = ephemeral_secret × peer.OneTimePreKey[opk_id] (if specified)

        fprintf(stderr, "[X3DH-INITIATOR] Starting initiator DH calculations\n");
        fprintf(stderr, "[X3DH-INITIATOR] peer_spk prefix: %02x%02x%02x%02x (size=%zu)\n",
            remote_bundle.GetSignedPreKeyPublic()[0], remote_bundle.GetSignedPreKeyPublic()[1],
            remote_bundle.GetSignedPreKeyPublic()[2], remote_bundle.GetSignedPreKeyPublic()[3],
            remote_bundle.GetSignedPreKeyPublic().size());
        fprintf(stderr, "[X3DH-INITIATOR] peer_identity prefix: %02x%02x%02x%02x (size=%zu)\n",
            remote_bundle.GetIdentityX25519()[0], remote_bundle.GetIdentityX25519()[1],
            remote_bundle.GetIdentityX25519()[2], remote_bundle.GetIdentityX25519()[3],
            remote_bundle.GetIdentityX25519().size());

        size_t offset = 0;
        std::vector<uint8_t> dh1(Constants::X_25519_KEY_SIZE);
        if (crypto_scalarmult(
                dh1.data(),
                identity_secret.data(),
                remote_bundle.GetSignedPreKeyPublic().data()) != 0) {
            return Result<size_t, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("DH1 computation failed"));
        }
        fprintf(stderr, "[X3DH-INITIATOR] DH1 = IK × peer.SPK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh1[0], dh1[1], dh1[2], dh1[3], dh1[4], dh1[5], dh1[6], dh1[7]);
        std::memcpy(dh_results_output.data() + offset, dh1.data(), Constants::X_25519_KEY_SIZE);
        offset += Constants::X_25519_KEY_SIZE;
        SodiumInterop::SecureWipe(std::span(dh1));
        std::vector<uint8_t> dh2(Constants::X_25519_KEY_SIZE);
        if (crypto_scalarmult(
                dh2.data(),
                ephemeral_secret.data(),
                remote_bundle.GetIdentityX25519().data()) != 0) {
            return Result<size_t, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("DH2 computation failed"));
        }
        fprintf(stderr, "[X3DH-INITIATOR] DH2 = EK × peer.IK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh2[0], dh2[1], dh2[2], dh2[3], dh2[4], dh2[5], dh2[6], dh2[7]);
        std::memcpy(dh_results_output.data() + offset, dh2.data(), Constants::X_25519_KEY_SIZE);
        offset += Constants::X_25519_KEY_SIZE;
        SodiumInterop::SecureWipe(std::span(dh2));
        std::vector<uint8_t> dh3(Constants::X_25519_KEY_SIZE);
        if (crypto_scalarmult(
                dh3.data(),
                ephemeral_secret.data(),
                remote_bundle.GetSignedPreKeyPublic().data()) != 0) {
            return Result<size_t, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("DH3 computation failed"));
        }
        fprintf(stderr, "[X3DH-INITIATOR] DH3 = EK × peer.SPK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh3[0], dh3[1], dh3[2], dh3[3], dh3[4], dh3[5], dh3[6], dh3[7]);
        std::memcpy(dh_results_output.data() + offset, dh3.data(), Constants::X_25519_KEY_SIZE);
        offset += Constants::X_25519_KEY_SIZE;
        SodiumInterop::SecureWipe(std::span(dh3));
        // DH4 = ephemeral_secret × peer.OneTimePreKey[opk_id]
        if (opk_id.has_value() && remote_bundle.HasOneTimePreKeys()) {
            // Find OPK by ID in peer's bundle
            const OneTimePreKeyRecord* target_opk = nullptr;
            for (const auto& opk : remote_bundle.GetOneTimePreKeys()) {
                if (opk.GetPreKeyId() == opk_id.value()) {
                    target_opk = &opk;
                    break;
                }
            }
            if (target_opk && target_opk->GetPublicKeySpan().size() == Constants::X_25519_PUBLIC_KEY_SIZE) {
                fprintf(stderr, "[X3DH-INITIATOR] Using OPK ID %u, prefix: %02x%02x%02x%02x\n",
                    opk_id.value(),
                    target_opk->GetPublicKeySpan()[0], target_opk->GetPublicKeySpan()[1],
                    target_opk->GetPublicKeySpan()[2], target_opk->GetPublicKeySpan()[3]);
                std::vector<uint8_t> dh4(Constants::X_25519_KEY_SIZE);
                if (crypto_scalarmult(
                        dh4.data(),
                        ephemeral_secret.data(),
                        target_opk->GetPublicKeySpan().data()) != 0) {
                    return Result<size_t, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic("DH4 computation failed"));
                }
                fprintf(stderr, "[X3DH-INITIATOR] DH4 = EK × peer.OPK[%u] = %02x%02x%02x%02x%02x%02x%02x%02x\n",
                    opk_id.value(), dh4[0], dh4[1], dh4[2], dh4[3], dh4[4], dh4[5], dh4[6], dh4[7]);
                std::memcpy(dh_results_output.data() + offset, dh4.data(), Constants::X_25519_KEY_SIZE);
                offset += Constants::X_25519_KEY_SIZE;
                SodiumInterop::SecureWipe(std::span(dh4));
            } else {
                fprintf(stderr, "[X3DH-INITIATOR] ERROR: OPK ID %u not found in peer bundle!\n", opk_id.value());
                return Result<size_t, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput("Requested OPK ID not found in peer bundle"));
            }
        } else {
            fprintf(stderr, "[X3DH-INITIATOR] No OPK specified, skipping DH4\n");
        }
        fprintf(stderr, "[X3DH-INITIATOR] Total DH bytes: %zu\n", offset);
        return Result<size_t, EcliptixProtocolFailure>::Ok(offset);
    }

    Result<size_t, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::PerformX3dhDiffieHellmanAsResponder(
        const LocalPublicKeyBundle &remote_bundle,
        std::optional<uint32_t> used_opk_id,
        std::span<uint8_t> dh_results_output) {
        // RESPONDER (Server) X3DH:
        // DH1 = SPK_secret × peer.IdentityX25519 (my signed pre-key with their identity)
        // DH2 = Identity_secret × peer.EphemeralX25519 (my identity with their ephemeral)
        // DH3 = SPK_secret × peer.EphemeralX25519 (my signed pre-key with their ephemeral)
        // DH4 = OPK_secret × peer.EphemeralX25519 (if initiator used an OPK, look up by ID)

        fprintf(stderr, "[X3DH-RESPONDER] Starting responder DH calculations\n");

        if (!remote_bundle.HasEphemeralKey()) {
            fprintf(stderr, "[X3DH-RESPONDER] ERROR: Remote bundle has no ephemeral key!\n");
            return Result<size_t, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Remote bundle must have ephemeral key for responder X3DH"));
        }

        const auto& peer_ephemeral = remote_bundle.GetEphemeralX25519Public().value();
        const auto& peer_identity = remote_bundle.GetIdentityX25519();

        fprintf(stderr, "[X3DH-RESPONDER] peer_ephemeral prefix: %02x%02x%02x%02x (size=%zu)\n",
            peer_ephemeral[0], peer_ephemeral[1], peer_ephemeral[2], peer_ephemeral[3], peer_ephemeral.size());
        fprintf(stderr, "[X3DH-RESPONDER] peer_identity prefix: %02x%02x%02x%02x (size=%zu)\n",
            peer_identity[0], peer_identity[1], peer_identity[2], peer_identity[3], peer_identity.size());
        fprintf(stderr, "[X3DH-RESPONDER] my_spk_public prefix: %02x%02x%02x%02x\n",
            signed_pre_key_public_[0], signed_pre_key_public_[1], signed_pre_key_public_[2], signed_pre_key_public_[3]);
        fprintf(stderr, "[X3DH-RESPONDER] my_identity_public prefix: %02x%02x%02x%02x\n",
            identity_x25519_public_key_[0], identity_x25519_public_key_[1], identity_x25519_public_key_[2], identity_x25519_public_key_[3]);

        // Read our SPK secret
        auto spk_read_result = signed_pre_key_secret_key_handle_.ReadBytes(
            Constants::X_25519_PRIVATE_KEY_SIZE);
        if (spk_read_result.IsErr()) {
            return Result<size_t, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(spk_read_result.UnwrapErr().message));
        }
        auto spk_secret = std::move(spk_read_result).Unwrap();

        // Read our identity secret
        auto id_read_result = identity_x25519_secret_key_handle_.ReadBytes(
            Constants::X_25519_PRIVATE_KEY_SIZE);
        if (id_read_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            return Result<size_t, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(id_read_result.UnwrapErr().message));
        }
        auto identity_secret = std::move(id_read_result).Unwrap();

        size_t offset = 0;

        // DH1 = SPK_secret × peer.IdentityX25519
        std::vector<uint8_t> dh1(Constants::X_25519_KEY_SIZE);
        if (crypto_scalarmult(dh1.data(), spk_secret.data(), peer_identity.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            SodiumInterop::SecureWipe(std::span(identity_secret));
            return Result<size_t, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("DH1 (responder) computation failed"));
        }
        fprintf(stderr, "[X3DH-RESPONDER] DH1 = SPK × peer.IK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh1[0], dh1[1], dh1[2], dh1[3], dh1[4], dh1[5], dh1[6], dh1[7]);
        std::memcpy(dh_results_output.data() + offset, dh1.data(), Constants::X_25519_KEY_SIZE);
        offset += Constants::X_25519_KEY_SIZE;
        SodiumInterop::SecureWipe(std::span(dh1));

        // DH2 = Identity_secret × peer.EphemeralX25519
        std::vector<uint8_t> dh2(Constants::X_25519_KEY_SIZE);
        if (crypto_scalarmult(dh2.data(), identity_secret.data(), peer_ephemeral.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            SodiumInterop::SecureWipe(std::span(identity_secret));
            return Result<size_t, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("DH2 (responder) computation failed"));
        }
        fprintf(stderr, "[X3DH-RESPONDER] DH2 = IK × peer.EK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh2[0], dh2[1], dh2[2], dh2[3], dh2[4], dh2[5], dh2[6], dh2[7]);
        std::memcpy(dh_results_output.data() + offset, dh2.data(), Constants::X_25519_KEY_SIZE);
        offset += Constants::X_25519_KEY_SIZE;
        SodiumInterop::SecureWipe(std::span(dh2));

        // DH3 = SPK_secret × peer.EphemeralX25519
        std::vector<uint8_t> dh3(Constants::X_25519_KEY_SIZE);
        if (crypto_scalarmult(dh3.data(), spk_secret.data(), peer_ephemeral.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            SodiumInterop::SecureWipe(std::span(identity_secret));
            return Result<size_t, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("DH3 (responder) computation failed"));
        }
        fprintf(stderr, "[X3DH-RESPONDER] DH3 = SPK × peer.EK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh3[0], dh3[1], dh3[2], dh3[3], dh3[4], dh3[5], dh3[6], dh3[7]);
        std::memcpy(dh_results_output.data() + offset, dh3.data(), Constants::X_25519_KEY_SIZE);
        offset += Constants::X_25519_KEY_SIZE;
        SodiumInterop::SecureWipe(std::span(dh3));

        // DH4 = OPK_secret × peer.EphemeralX25519 (if initiator used an OPK)
        // Only compute DH4 if the initiator explicitly communicated an OPK ID
        // In 1-RTT fallback mode, no OPK is used (client doesn't have server's OPKs)
        if (used_opk_id.has_value()) {
            fprintf(stderr, "[X3DH-RESPONDER] Initiator used OPK ID: %u\n", used_opk_id.value());
            const OneTimePreKeyLocal* opk = FindOneTimePreKeyById(used_opk_id.value());
            if (!opk) {
                SodiumInterop::SecureWipe(std::span(spk_secret));
                SodiumInterop::SecureWipe(std::span(identity_secret));
                fprintf(stderr, "[X3DH-RESPONDER] ERROR: OPK ID %u not found!\n", used_opk_id.value());
                return Result<size_t, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput("OPK with requested ID not found"));
            }
            auto opk_read_result = opk->GetPrivateKeyHandle().ReadBytes(
                Constants::X_25519_PRIVATE_KEY_SIZE);
            if (opk_read_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(spk_secret));
                SodiumInterop::SecureWipe(std::span(identity_secret));
                return Result<size_t, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to read OPK private key"));
            }
            auto opk_secret = std::move(opk_read_result).Unwrap();
            std::vector<uint8_t> dh4(Constants::X_25519_KEY_SIZE);
            if (crypto_scalarmult(dh4.data(), opk_secret.data(), peer_ephemeral.data()) != 0) {
                SodiumInterop::SecureWipe(std::span(dh4));
                SodiumInterop::SecureWipe(std::span(opk_secret));
                SodiumInterop::SecureWipe(std::span(spk_secret));
                SodiumInterop::SecureWipe(std::span(identity_secret));
                return Result<size_t, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("DH4 (responder) computation failed"));
            }
            fprintf(stderr, "[X3DH-RESPONDER] DH4 = OPK[ID=%u] × peer.EK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
                used_opk_id.value(), dh4[0], dh4[1], dh4[2], dh4[3], dh4[4], dh4[5], dh4[6], dh4[7]);
            std::memcpy(dh_results_output.data() + offset, dh4.data(), Constants::X_25519_KEY_SIZE);
            offset += Constants::X_25519_KEY_SIZE;
            SodiumInterop::SecureWipe(std::span(dh4));
            SodiumInterop::SecureWipe(std::span(opk_secret));
        } else {
            fprintf(stderr, "[X3DH-RESPONDER] No OPK ID provided by initiator, skipping DH4\n");
        }

        // Clean up secrets
        SodiumInterop::SecureWipe(std::span(spk_secret));
        SodiumInterop::SecureWipe(std::span(identity_secret));

        fprintf(stderr, "[X3DH-RESPONDER] Total DH bytes: %zu\n", offset);
        return Result<size_t, EcliptixProtocolFailure>::Ok(offset);
    }

    Result<SecureMemoryHandle, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::X3dhDeriveSharedSecret(
        const LocalPublicKeyBundle &remote_bundle,
        std::span<const uint8_t> info,
        bool is_initiator) {
        if (auto validation_result = ValidateX3dhPrerequisites(remote_bundle, info); validation_result.IsErr()) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                validation_result.UnwrapErr());
        }
        if (!remote_bundle.HasKyberKey() || !remote_bundle.GetKyberPublicKey().has_value()) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Remote Kyber public key required for hybrid X3DH"));
        }

        std::vector<uint8_t> dh_results(Constants::X_25519_KEY_SIZE * 4);
        size_t dh_offset = 0;

        if (is_initiator) {
            // INITIATOR path: use ephemeral and identity secrets with peer's SPK/IK
            auto eph_read_result = ephemeral_secret_key_handle_.value().ReadBytes(
                Constants::X_25519_PRIVATE_KEY_SIZE);
            if (eph_read_result.IsErr()) {
                return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic(eph_read_result.UnwrapErr().message));
            }
            auto ephemeral_secret = std::move(eph_read_result).Unwrap();
            auto id_read_result = identity_x25519_secret_key_handle_.ReadBytes(
                Constants::X_25519_PRIVATE_KEY_SIZE);
            if (id_read_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(ephemeral_secret));
                return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic(id_read_result.UnwrapErr().message));
            }
            auto identity_secret = std::move(id_read_result).Unwrap();

            // Determine which OPK to use:
            // 1. Server specified used_one_time_pre_key_id (1-RTT mode) - use that
            // 2. Server sent OPKs without specifying (2-RTT mode) - client selects first
            // 3. No OPKs available - skip DH4
            std::optional<uint32_t> opk_to_use = remote_bundle.GetUsedOpkId();
            if (!opk_to_use.has_value() && remote_bundle.HasOneTimePreKeys() &&
                !remote_bundle.GetOneTimePreKeys().empty()) {
                // 2-RTT fallback: client selects first OPK
                opk_to_use = remote_bundle.GetOneTimePreKeys()[0].GetPreKeyId();
            }
            bool use_opk = opk_to_use.has_value();

            if (use_opk) {
                selected_opk_id_ = opk_to_use.value();
                fprintf(stderr, "[X3DH] Initiator using OPK ID: %u (source: %s)\n",
                    opk_to_use.value(),
                    remote_bundle.GetUsedOpkId().has_value() ? "server pre-selected" : "client selected");
            } else {
                selected_opk_id_.reset();
                fprintf(stderr, "[X3DH] Initiator: no OPK available, skipping DH4\n");
            }

            auto dh_result = PerformX3dhDiffieHellmanAsInitiator(
                ephemeral_secret,
                identity_secret,
                remote_bundle,
                opk_to_use,
                dh_results);
            SodiumInterop::SecureWipe(std::span(ephemeral_secret));
            SodiumInterop::SecureWipe(std::span(identity_secret));
            if (dh_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(dh_results));
                return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                    dh_result.UnwrapErr());
            }
            dh_offset = std::move(dh_result).Unwrap();
        } else {
            // RESPONDER path: use SPK and identity secrets with peer's ephemeral/IK
            // In 1-RTT mode, server pre-selects OPK - use that instead of client's bundle
            // In 2-RTT mode, client would tell us which OPK they used via remote_bundle
            std::optional<uint32_t> used_opk_id = selected_opk_id_.has_value()
                ? selected_opk_id_  // Server pre-selected OPK (1-RTT mode)
                : remote_bundle.GetUsedOpkId();  // Client-selected OPK (2-RTT mode)
            fprintf(stderr, "[X3DH] Responder using OPK ID: %s (source: %s)\n",
                used_opk_id.has_value() ? std::to_string(used_opk_id.value()).c_str() : "none",
                selected_opk_id_.has_value() ? "server pre-selected" : "client bundle");

            auto dh_result = PerformX3dhDiffieHellmanAsResponder(remote_bundle, used_opk_id, dh_results);
            if (dh_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(dh_results));
                return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                    dh_result.UnwrapErr());
            }
            dh_offset = std::move(dh_result).Unwrap();
        }
        std::vector<uint8_t> ikm(Constants::X_25519_KEY_SIZE + dh_offset);
        std::fill_n(ikm.begin(), Constants::X_25519_KEY_SIZE, CryptoHashConstants::FILL_BYTE);
        std::memcpy(ikm.data() + Constants::X_25519_KEY_SIZE, dh_results.data(), dh_offset);
        SodiumInterop::SecureWipe(std::span(dh_results));
        std::vector<uint8_t> classical_shared(Constants::X_25519_KEY_SIZE);
        auto hkdf_result = Hkdf::DeriveKey(ikm, classical_shared, {}, info);
        SodiumInterop::SecureWipe(std::span(ikm));
        if (hkdf_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(classical_shared));
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                hkdf_result.UnwrapErr());
        }

        // Check if we already have stored Kyber artifacts (from BeginHandshakeWithPeerKyber)
        std::vector<uint8_t> kyber_ciphertext;
        std::vector<uint8_t> kyber_ss_bytes;
        bool used_stored_artifacts = false;

        if (pending_kyber_handshake_.has_value()) {
            // Case 1: SERVER - Use pre-stored artifacts from BeginHandshakeWithPeerKyber
            kyber_ciphertext = pending_kyber_handshake_->kyber_ciphertext;
            kyber_ss_bytes = pending_kyber_handshake_->kyber_shared_secret;
            used_stored_artifacts = true;
        } else if (remote_bundle.HasKyberCiphertext()) {
            // Case 2: CLIENT - Peer sent ciphertext, DECAPSULATE to get shared secret
            const auto& peer_ciphertext = remote_bundle.GetKyberCiphertext().value();
            auto decap_result = DecapsulateKyberCiphertext(
                std::span<const uint8_t>(peer_ciphertext.data(), peer_ciphertext.size()));
            if (decap_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(classical_shared));
                return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                    decap_result.UnwrapErr());
            }
            auto artifacts = std::move(decap_result).Unwrap();
            kyber_ciphertext = std::move(artifacts.kyber_ciphertext);
            kyber_ss_bytes = std::move(artifacts.kyber_shared_secret);
            // Store artifacts so they can be consumed by complete_handshake_auto
            used_stored_artifacts = false;
        } else {
            // Case 3: Fallback - Encapsulate to peer's Kyber public key
            const auto &remote_kyber_public = remote_bundle.GetKyberPublicKey().value();
            auto encaps_result = KyberInterop::Encapsulate(remote_kyber_public);
            if (encaps_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(classical_shared));
                return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(encaps_result.UnwrapErr()));
            }
            auto [ct, kyber_ss_handle] = std::move(encaps_result).Unwrap();
            kyber_ciphertext = std::move(ct);

            auto kyber_ss_bytes_result = kyber_ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
            if (kyber_ss_bytes_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(classical_shared));
                return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(kyber_ss_bytes_result.UnwrapErr()));
            }
            kyber_ss_bytes = kyber_ss_bytes_result.Unwrap();
        }

        auto hybrid_result = KyberInterop::CombineHybridSecrets(
            classical_shared,
            kyber_ss_bytes,
            std::string(ProtocolConstants::X3DH_INFO));
        auto _wipe_classical = SodiumInterop::SecureWipe(std::span(classical_shared));
        (void) _wipe_classical;
        if (hybrid_result.IsErr()) {
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_ss_bytes));
            (void) _wipe_pq;
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                hybrid_result.UnwrapErr());
        }

        // Only store artifacts if we freshly encapsulated (not if we used stored ones)
        if (!used_stored_artifacts) {
            pending_kyber_handshake_ = HybridHandshakeArtifacts{
                std::move(kyber_ciphertext),
                kyber_ss_bytes
            };
        }
        auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_ss_bytes));
        (void) _wipe_pq;
        auto handle = std::move(hybrid_result).Unwrap();

        // Clear ephemeral key after use - ephemeral keys are single-use per Signal Protocol
        if (is_initiator) {
            ClearEphemeralKeyPair();
        }

        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Ok(std::move(handle));
    }

    Result<EcliptixSystemIdentityKeys::HybridHandshakeArtifacts, EcliptixProtocolFailure>
    EcliptixSystemIdentityKeys::ConsumePendingKyberHandshake() {
        if (!pending_kyber_handshake_.has_value()) {
            return Result<HybridHandshakeArtifacts, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("No pending Kyber handshake data"));
        }
        auto artifacts = std::move(*pending_kyber_handshake_);
        pending_kyber_handshake_.reset();
        return Result<HybridHandshakeArtifacts, EcliptixProtocolFailure>::Ok(std::move(artifacts));
    }

    void EcliptixSystemIdentityKeys::StorePendingKyberHandshake(
        std::vector<uint8_t> kyber_ciphertext,
        std::vector<uint8_t> kyber_shared_secret) {
        pending_kyber_handshake_ = HybridHandshakeArtifacts{
            std::move(kyber_ciphertext),
            std::move(kyber_shared_secret)
        };
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    EcliptixSystemIdentityKeys::GetPendingKyberCiphertext() const {
        if (!pending_kyber_handshake_.has_value()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("No pending Kyber handshake data"));
        }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(
            pending_kyber_handshake_->kyber_ciphertext);
    }

    Result<EcliptixSystemIdentityKeys::HybridHandshakeArtifacts, EcliptixProtocolFailure>
    EcliptixSystemIdentityKeys::DecapsulateKyberCiphertext(std::span<const uint8_t> ciphertext) const {
        auto validate_result = KyberInterop::ValidateCiphertext(ciphertext);
        if (validate_result.IsErr()) {
            return Result<HybridHandshakeArtifacts, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(validate_result.UnwrapErr()));
        }
        auto decap_result = KyberInterop::Decapsulate(ciphertext, kyber_secret_key_handle_);
        if (decap_result.IsErr()) {
            return Result<HybridHandshakeArtifacts, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(decap_result.UnwrapErr()));
        }
        auto kyber_ss_handle = std::move(decap_result).Unwrap();
        auto ss_bytes_result = kyber_ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
        if (ss_bytes_result.IsErr()) {
            return Result<HybridHandshakeArtifacts, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(ss_bytes_result.UnwrapErr()));
        }
        return Result<HybridHandshakeArtifacts, EcliptixProtocolFailure>::Ok(
            HybridHandshakeArtifacts{
                std::vector(ciphertext.begin(), ciphertext.end()),
                ss_bytes_result.Unwrap()
            });
    }
}
