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

    Result<size_t, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::PerformX3dhDiffieHellman(
        const std::span<const uint8_t> ephemeral_secret,
        const std::span<const uint8_t> identity_secret,
        const LocalPublicKeyBundle &remote_bundle,
        const bool use_opk,
        std::span<uint8_t> dh_results_output) {
        size_t offset = 0;
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
        SodiumInterop::SecureWipe(std::span(dh1));
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
        SodiumInterop::SecureWipe(std::span(dh2));
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
        SodiumInterop::SecureWipe(std::span(dh3));
        if (use_opk && remote_bundle.HasOneTimePreKeys()) {
            if (const auto &opks = remote_bundle.GetOneTimePreKeys();
                !opks.empty() && opks[0].GetPublicKeySpan().size() == Constants::X_25519_PUBLIC_KEY_SIZE) {
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
                SodiumInterop::SecureWipe(std::span(dh4));
            }
        }
        return Result<size_t, EcliptixProtocolFailure>::Ok(offset);
    }

    Result<SecureMemoryHandle, EcliptixProtocolFailure> EcliptixSystemIdentityKeys::X3dhDeriveSharedSecret(
        const LocalPublicKeyBundle &remote_bundle,
        std::span<const uint8_t> info) {
        if (auto validation_result = ValidateX3dhPrerequisites(remote_bundle, info); validation_result.IsErr()) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                validation_result.UnwrapErr());
        }
        if (!remote_bundle.HasKyberKey() || !remote_bundle.GetKyberPublicKey().has_value()) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Remote Kyber public key required for hybrid X3DH"));
        }
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
        std::vector<uint8_t> dh_results(Constants::X_25519_KEY_SIZE * 4);
        bool use_opk = remote_bundle.HasOneTimePreKeys();
        auto dh_result = PerformX3dhDiffieHellman(
            ephemeral_secret,
            identity_secret,
            remote_bundle,
            use_opk,
            dh_results);
        SodiumInterop::SecureWipe(std::span(ephemeral_secret));
        SodiumInterop::SecureWipe(std::span(identity_secret));
        if (dh_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(dh_results));
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                dh_result.UnwrapErr());
        }
        size_t dh_offset = std::move(dh_result).Unwrap();
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
        const auto &remote_kyber_public = remote_bundle.GetKyberPublicKey().value();
        auto encaps_result = KyberInterop::Encapsulate(remote_kyber_public);
        if (encaps_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(classical_shared));
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(encaps_result.UnwrapErr()));
        }
        auto [kyber_ciphertext, kyber_ss_handle] = std::move(encaps_result).Unwrap();
        auto kyber_ss_bytes_result = kyber_ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
        if (kyber_ss_bytes_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(classical_shared));
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(kyber_ss_bytes_result.UnwrapErr()));
        }
        auto kyber_ss_bytes = kyber_ss_bytes_result.Unwrap();
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
        pending_kyber_handshake_ = HybridHandshakeArtifacts{
            std::move(kyber_ciphertext),
            kyber_ss_bytes
        };
        auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_ss_bytes));
        (void) _wipe_pq;
        auto handle = std::move(hybrid_result).Unwrap();
        ephemeral_secret_key_handle_.reset();
        if (ephemeral_x25519_public_key_.has_value()) {
            SodiumInterop::SecureWipe(std::span(ephemeral_x25519_public_key_.value()));
        }
        ephemeral_x25519_public_key_.reset();
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
