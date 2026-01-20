#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/protocol/constants.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/crypto/master_key_derivation.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/debug/key_logger.hpp"
#include <sodium.h>
#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace ecliptix::protocol::identity {
    using crypto::SodiumInterop;
    using crypto::MasterKeyDerivation;
    using crypto::Hkdf;
    using crypto::KyberInterop;
    using models::SignedPreKeyPair;
    using models::OneTimePreKeyPublic;

    IdentityKeys::IdentityKeys(IdentityKeyBundle material)
        : identity_ed25519_secret_key_handle_(std::move(material.ed25519).TakeSecretKeyHandle())
          , identity_ed25519_public_(std::move(material.ed25519).TakePublicKey())
          , identity_x25519_secret_key_handle_(std::move(material.identity_x25519).TakeSecretKeyHandle())
          , identity_x25519_public_(std::move(material.identity_x25519).TakePublicKey())
          , signed_pre_key_id_(material.signed_pre_key.GetId())
          , signed_pre_key_secret_key_handle_(std::move(material.signed_pre_key).TakeSecretKeyHandle())
          , signed_pre_key_public_(std::move(material.signed_pre_key).TakePublicKey())
          , signed_pre_key_signature_(std::move(material.signed_pre_key).TakeSignature())
          , one_time_pre_keys_(std::move(material.one_time_pre_keys))
          , kyber_secret_key_handle_(std::move(material.kyber_secret_key))
          , kyber_public_(std::move(material.kyber_public))
          , pending_kyber_handshake_(std::nullopt)
          , ephemeral_secret_key_handle_(std::nullopt)
          , ephemeral_x25519_public_(std::nullopt)
          , selected_one_time_pre_key_id_(std::nullopt)
          , lock_(std::make_unique<std::shared_mutex>()) {
    }

    std::vector<uint8_t> IdentityKeys::GetIdentityX25519PublicCopy() const {
        std::shared_lock lock(*lock_);
        return identity_x25519_public_;
    }

    std::vector<uint8_t> IdentityKeys::GetIdentityEd25519PublicCopy() const {
        std::shared_lock lock(*lock_);
        return identity_ed25519_public_;
    }

    std::vector<uint8_t> IdentityKeys::GetKyberPublicCopy() const {
        std::shared_lock lock(*lock_);
        return kyber_public_;
    }

    Result<std::vector<uint8_t>, ProtocolFailure>
    IdentityKeys::GetIdentityX25519PrivateKeyCopy() const {
        std::shared_lock lock(*lock_);
        auto read_result = identity_x25519_secret_key_handle_.ReadBytes(kX25519PrivateKeyBytes);
        if (read_result.IsErr()) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(read_result.UnwrapErr()));
        }
        return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(read_result.Unwrap());
    }

    Result<SecureMemoryHandle, ProtocolFailure> IdentityKeys::CloneKyberSecretKey() const {
        std::shared_lock lock(*lock_);
        auto read_result = kyber_secret_key_handle_.ReadBytes(KyberInterop::KYBER_768_SECRET_KEY_SIZE);
        if (read_result.IsErr()) {
            return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(read_result.UnwrapErr()));
        }
        auto secret_bytes = read_result.Unwrap();
        auto copy_alloc = SecureMemoryHandle::Allocate(KyberInterop::KYBER_768_SECRET_KEY_SIZE);
        if (copy_alloc.IsErr()) {
            return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(copy_alloc.UnwrapErr()));
        }
        auto copy_handle = std::move(copy_alloc).Unwrap();
        if (auto write_result = copy_handle.Write(secret_bytes); write_result.IsErr()) {
            return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(write_result.UnwrapErr()));
        }
        auto _wipe = SodiumInterop::SecureWipe(std::span(secret_bytes));
        (void) _wipe;
        return Result<SecureMemoryHandle, ProtocolFailure>::Ok(std::move(copy_handle));
    }

    Result<std::vector<uint8_t>, ProtocolFailure>
    IdentityKeys::GetEphemeralX25519PrivateKeyCopy() const {
        std::shared_lock lock(*lock_);
        if (!ephemeral_secret_key_handle_.has_value()) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic("Ephemeral key has not been generated"));
        }
        auto read_result = ephemeral_secret_key_handle_->ReadBytes(kX25519PrivateKeyBytes);
        if (read_result.IsErr()) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(read_result.UnwrapErr()));
        }
        return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(read_result.Unwrap());
    }

    Result<std::vector<uint8_t>, ProtocolFailure>
    IdentityKeys::GetSignedPreKeyPrivateCopy() const {
        std::shared_lock lock(*lock_);
        auto read_result = signed_pre_key_secret_key_handle_.ReadBytes(kX25519PrivateKeyBytes);
        if (read_result.IsErr()) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(read_result.UnwrapErr()));
        }
        return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(read_result.Unwrap());
    }

    std::optional<std::vector<uint8_t>>
    IdentityKeys::GetEphemeralX25519PublicCopy() const {
        std::shared_lock lock(*lock_);
        return ephemeral_x25519_public_;
    }

    std::vector<uint8_t>
    IdentityKeys::GetSignedPreKeyPublicCopy() const {
        std::shared_lock lock(*lock_);
        return signed_pre_key_public_;
    }

    std::optional<uint32_t> IdentityKeys::GetSelectedOneTimePreKeyId() const {
        std::shared_lock lock(*lock_);
        return selected_one_time_pre_key_id_;
    }

    void IdentityKeys::SetSelectedOneTimePreKeyId(uint32_t one_time_pre_key_id) {
        std::unique_lock lock(*lock_);
        selected_one_time_pre_key_id_ = one_time_pre_key_id;
    }

    void IdentityKeys::ClearSelectedOneTimePreKeyId() {
        std::unique_lock lock(*lock_);
        selected_one_time_pre_key_id_.reset();
    }

    Result<Ed25519KeyPair, ProtocolFailure> IdentityKeys::GenerateEd25519Keys() {
        std::vector<uint8_t> public_key(crypto_sign_PUBLICKEYBYTES);
        std::vector<uint8_t> secret_key(crypto_sign_SECRETKEYBYTES);
        if (crypto_sign_keypair(public_key.data(), secret_key.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(secret_key));
            return Result<Ed25519KeyPair, ProtocolFailure>::Err(
                ProtocolFailure::KeyGeneration("Failed to generate Ed25519 keypair"));
        }
        auto handle_result = SecureMemoryHandle::Allocate(kEd25519SecretKeyBytes);
        if (handle_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(secret_key));
            return Result<Ed25519KeyPair, ProtocolFailure>::Err(
                ProtocolFailure::Generic(handle_result.UnwrapErr().message));
        }
        auto handle = std::move(handle_result).Unwrap();
        auto write_result = handle.Write(std::span<const uint8_t>(secret_key));
        SodiumInterop::SecureWipe(std::span(secret_key));
        if (write_result.IsErr()) {
            return Result<Ed25519KeyPair, ProtocolFailure>::Err(
                ProtocolFailure::Generic(write_result.UnwrapErr().message));
        }
        return Result<Ed25519KeyPair, ProtocolFailure>::Ok(
            Ed25519KeyPair(std::move(handle), std::move(public_key)));
    }

    Result<X25519KeyPair, ProtocolFailure> IdentityKeys::GenerateX25519IdentityKeys() {
        auto result = SodiumInterop::GenerateX25519KeyPair(kPurposeIdentityX25519);
        if (result.IsErr()) {
            return Result<X25519KeyPair, ProtocolFailure>::Err(result.UnwrapErr());
        }
        auto [handle, public_key] = std::move(result).Unwrap();
        return Result<X25519KeyPair, ProtocolFailure>::Ok(
            X25519KeyPair(std::move(handle), std::move(public_key)));
    }

    Result<X25519KeyPair, ProtocolFailure> IdentityKeys::GenerateX25519SignedPreKey() {
        auto result = SodiumInterop::GenerateX25519KeyPair(kPurposeSignedPreKey);
        if (result.IsErr()) {
            return Result<X25519KeyPair, ProtocolFailure>::Err(result.UnwrapErr());
        }
        auto [handle, public_key] = std::move(result).Unwrap();
        return Result<X25519KeyPair, ProtocolFailure>::Ok(
            X25519KeyPair(std::move(handle), std::move(public_key)));
    }

    Result<std::vector<uint8_t>, ProtocolFailure> IdentityKeys::SignSignedPreKey(
        const SecureMemoryHandle &ed_secret_key_handle,
        const std::span<const uint8_t> spk_public) {
        auto read_result = ed_secret_key_handle.ReadBytes(kEd25519SecretKeyBytes);
        if (read_result.IsErr()) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(read_result.UnwrapErr().message));
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
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic("Failed to sign signed pre-key public key"));
        }
        if (sig_len != kEd25519SignatureBytes) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic("Generated signature has incorrect size"));
        }
        return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(signature));
    }

    Result<std::vector<OneTimePreKey>, ProtocolFailure> IdentityKeys::GenerateOneTimePreKeys(
        const uint32_t count) {
        if (count == 0) {
            return Result<std::vector<OneTimePreKey>, ProtocolFailure>::Ok(
                std::vector<OneTimePreKey>{});
        }
        std::vector<OneTimePreKey> opks;
        opks.reserve(count);
        std::unordered_set<uint32_t> used_ids;
        used_ids.reserve(count);
        uint32_t id_counter = 2;
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t id = id_counter++;
            while (used_ids.count(id) > 0) {
                auto random_bytes = SodiumInterop::GetRandomBytes(sizeof(uint32_t));
                std::memcpy(&id, random_bytes.data(), sizeof(uint32_t));
            }
            used_ids.insert(id);
            auto opk_result = OneTimePreKey::Generate(id);
            if (opk_result.IsErr()) {
                return Result<std::vector<OneTimePreKey>, ProtocolFailure>::Err(
                    opk_result.UnwrapErr());
            }
            opks.push_back(std::move(opk_result).Unwrap());
        }
        return Result<std::vector<OneTimePreKey>, ProtocolFailure>::Ok(std::move(opks));
    }

    Result<std::vector<OneTimePreKey>, ProtocolFailure> IdentityKeys::GenerateOneTimePreKeysFromMasterKey(
        const std::span<const uint8_t> master_key,
        const std::string_view membership_id,
        const uint32_t count) {
        if (count == 0) {
            return Result<std::vector<OneTimePreKey>, ProtocolFailure>::Ok(
                std::vector<OneTimePreKey>{});
        }
        std::vector<OneTimePreKey> opks;
        opks.reserve(count);

        for (uint32_t i = 0; i < count; ++i) {
            // Derive deterministic OPK ID from master key and index
            auto id_seed = MasterKeyDerivation::DeriveOneTimePreKeySeed(master_key, membership_id, i);
            uint32_t id;
            std::memcpy(&id, id_seed.data(), sizeof(uint32_t));
            // Ensure ID is at least 2 (Signal protocol convention)
            id = (id % 0xFFFFFFFE) + 2;

            // Derive the OPK seed for this index
            auto opk_seed = MasterKeyDerivation::DeriveOneTimePreKeySeed(master_key, membership_id, count + i);

            auto opk_result = OneTimePreKey::CreateFromSeed(id, std::span(opk_seed));
            SodiumInterop::SecureWipe(std::span(opk_seed));
            SodiumInterop::SecureWipe(std::span(id_seed));

            if (opk_result.IsErr()) {
                return Result<std::vector<OneTimePreKey>, ProtocolFailure>::Err(
                    opk_result.UnwrapErr());
            }
            opks.push_back(std::move(opk_result).Unwrap());
        }
        return Result<std::vector<OneTimePreKey>, ProtocolFailure>::Ok(std::move(opks));
    }

    Result<IdentityKeys, ProtocolFailure> IdentityKeys::Create(
        uint32_t one_time_key_count) {
        auto ed_result = GenerateEd25519Keys();
        if (ed_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ed_result.UnwrapErr());
        }
        auto ed_keys = std::move(ed_result).Unwrap();
        auto id_x_result = GenerateX25519IdentityKeys();
        if (id_x_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                id_x_result.UnwrapErr());
        }
        auto id_x_keys = std::move(id_x_result).Unwrap();
        auto random_id = SodiumInterop::GetRandomBytes(sizeof(uint32_t));
        uint32_t spk_id;
        std::memcpy(&spk_id, random_id.data(), sizeof(uint32_t));
        auto spk_result = GenerateX25519SignedPreKey();
        if (spk_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                spk_result.UnwrapErr());
        }
        auto spk_keys = std::move(spk_result).Unwrap();
        auto spk_public = spk_keys.GetPublicKeyCopy();
        auto signature_result = SignSignedPreKey(ed_keys.GetSecretKeyHandle(), spk_public);
        if (signature_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                signature_result.UnwrapErr());
        }
        auto spk_signature = std::move(signature_result).Unwrap();
        auto opks_result = GenerateOneTimePreKeys(one_time_key_count);
        if (opks_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                opks_result.UnwrapErr());
        }
        auto opks = std::move(opks_result).Unwrap();
        auto kyber_result = KyberInterop::GenerateKyber768KeyPair(kPurposeIdentityKyber);
        if (kyber_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(kyber_result.UnwrapErr()));
        }
        auto [kyber_secret, kyber_public] = std::move(kyber_result).Unwrap();
        auto spk_material = SignedPreKeyPair(
            spk_id,
            std::move(spk_keys).TakeSecretKeyHandle(),
            std::move(spk_keys).TakePublicKey(),
            std::move(spk_signature));
        IdentityKeyBundle material(
            std::move(ed_keys),
            std::move(id_x_keys),
            std::move(spk_material),
            std::move(opks),
            std::move(kyber_secret),
            std::move(kyber_public));

        auto identity_keys = IdentityKeys(std::move(material));

#ifdef ECLIPTIX_DEBUG_KEYS

        {
            auto ed_pub = identity_keys.GetIdentityEd25519PublicCopy();
            auto ed_priv_result = identity_keys.identity_ed25519_secret_key_handle_.ReadBytes(kEd25519SecretKeyBytes);
            auto x_pub = identity_keys.GetIdentityX25519PublicCopy();
            auto x_priv_result = identity_keys.identity_x25519_secret_key_handle_.ReadBytes(kX25519PrivateKeyBytes);
            auto spk_pub = identity_keys.GetSignedPreKeyPublicCopy();
            auto spk_priv_result = identity_keys.signed_pre_key_secret_key_handle_.ReadBytes(kX25519PrivateKeyBytes);
            auto kyber_pub = identity_keys.GetKyberPublicCopy();
            auto kyber_priv_result = identity_keys.kyber_secret_key_handle_.ReadBytes(KyberInterop::KYBER_768_SECRET_KEY_SIZE);

            if (ed_priv_result.IsOk() && x_priv_result.IsOk() && spk_priv_result.IsOk() && kyber_priv_result.IsOk()) {
                auto ed_priv = ed_priv_result.Unwrap();
                auto x_priv = x_priv_result.Unwrap();
                auto spk_priv = spk_priv_result.Unwrap();
                auto kyber_priv = kyber_priv_result.Unwrap();

                debug::LogIdentityKeysCreated(
                    debug::Side::Unknown,
                    ed_pub, ed_priv,
                    x_pub, x_priv,
                    identity_keys.signed_pre_key_id_,
                    spk_pub, spk_priv,
                    identity_keys.signed_pre_key_signature_,
                    kyber_pub, kyber_priv);

                for (const auto& opk : identity_keys.one_time_pre_keys_) {
                    auto opk_pub = opk.GetPublicKeyCopy();
                    auto opk_priv_result = opk.GetPrivateKeyHandle().ReadBytes(kX25519PrivateKeyBytes);
                    if (opk_priv_result.IsOk()) {
                        auto opk_priv = opk_priv_result.Unwrap();
                        debug::LogOneTimePreKey(debug::Side::Unknown, opk.GetOneTimePreKeyId(), opk_pub, opk_priv);
                        SodiumInterop::SecureWipe(std::span(opk_priv));
                    }
                }

                SodiumInterop::SecureWipe(std::span(ed_priv));
                SodiumInterop::SecureWipe(std::span(x_priv));
                SodiumInterop::SecureWipe(std::span(spk_priv));
                SodiumInterop::SecureWipe(std::span(kyber_priv));
            }
        }
#endif

        return Result<IdentityKeys, ProtocolFailure>::Ok(std::move(identity_keys));
    }

    Result<IdentityKeys, ProtocolFailure> IdentityKeys::CreateFromMasterKey(
        std::span<const uint8_t> master_key,
        std::string_view membership_id,
        uint32_t one_time_key_count) {
        auto ed_seed = MasterKeyDerivation::DeriveEd25519Seed(master_key, membership_id);
        std::vector<uint8_t> ed_public(crypto_sign_PUBLICKEYBYTES);
        std::vector<uint8_t> ed_secret(crypto_sign_SECRETKEYBYTES);
        if (crypto_sign_seed_keypair(ed_public.data(), ed_secret.data(), ed_seed.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(ed_seed));
            SodiumInterop::SecureWipe(std::span(ed_secret));
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ProtocolFailure::KeyGeneration("Failed to generate Ed25519 keypair from seed"));
        }
        SodiumInterop::SecureWipe(std::span(ed_seed));
        auto ed_handle_result = SecureMemoryHandle::Allocate(kEd25519SecretKeyBytes);
        if (ed_handle_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(ed_secret));
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ProtocolFailure::Generic(ed_handle_result.UnwrapErr().message));
        }
        auto ed_handle = std::move(ed_handle_result).Unwrap();
        auto ed_write_result = ed_handle.Write(std::span<const uint8_t>(ed_secret));
        SodiumInterop::SecureWipe(std::span(ed_secret));
        if (ed_write_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ProtocolFailure::Generic(ed_write_result.UnwrapErr().message));
        }
        auto ed_material = Ed25519KeyPair(std::move(ed_handle), std::move(ed_public));
        auto x_seed = MasterKeyDerivation::DeriveX25519Seed(master_key, membership_id);
        x_seed[0] &= kX25519ClampByte0;
        x_seed[31] &= kX25519ClampByte31Low;
        x_seed[31] |= kX25519ClampByte31High;
        std::vector<uint8_t> x_public(crypto_scalarmult_BYTES);
        if (crypto_scalarmult_base(x_public.data(), x_seed.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(x_seed));
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ProtocolFailure::KeyGeneration("Failed to derive X25519 public key"));
        }
        auto x_handle_result = SecureMemoryHandle::Allocate(kX25519PrivateKeyBytes);
        if (x_handle_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(x_seed));
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ProtocolFailure::Generic(x_handle_result.UnwrapErr().message));
        }
        auto x_handle = std::move(x_handle_result).Unwrap();
        auto x_write_result = x_handle.Write(std::span<const uint8_t>(x_seed));
        SodiumInterop::SecureWipe(std::span(x_seed));
        if (x_write_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ProtocolFailure::Generic(x_write_result.UnwrapErr().message));
        }
        auto x_material = X25519KeyPair(std::move(x_handle), std::move(x_public));
        auto spk_seed = MasterKeyDerivation::DeriveSignedPreKeySeed(master_key, membership_id);
        uint32_t spk_id;
        std::memcpy(&spk_id, spk_seed.data(), sizeof(uint32_t));
        std::vector<uint8_t> spk_secret(kX25519PrivateKeyBytes);
        std::memcpy(spk_secret.data(), spk_seed.data(), kX25519PrivateKeyBytes);
        SodiumInterop::SecureWipe(std::span(spk_seed));
        spk_secret[0] &= kX25519ClampByte0;
        spk_secret[31] &= kX25519ClampByte31Low;
        spk_secret[31] |= kX25519ClampByte31High;
        std::vector<uint8_t> spk_public(crypto_scalarmult_BYTES);
        if (crypto_scalarmult_base(spk_public.data(), spk_secret.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ProtocolFailure::KeyGeneration("Failed to derive signed pre-key public key"));
        }
        auto spk_handle_result = SecureMemoryHandle::Allocate(kX25519PrivateKeyBytes);
        if (spk_handle_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ProtocolFailure::Generic(spk_handle_result.UnwrapErr().message));
        }
        auto spk_handle = std::move(spk_handle_result).Unwrap();
        auto spk_write_result = spk_handle.Write(std::span<const uint8_t>(spk_secret));
        SodiumInterop::SecureWipe(std::span(spk_secret));
        if (spk_write_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ProtocolFailure::Generic(spk_write_result.UnwrapErr().message));
        }
        auto signature_result = SignSignedPreKey(ed_material.GetSecretKeyHandle(), spk_public);
        if (signature_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                signature_result.UnwrapErr());
        }
        auto spk_signature = std::move(signature_result).Unwrap();
        auto spk_material = SignedPreKeyPair(
            spk_id,
            std::move(spk_handle),
            std::move(spk_public),
            std::move(spk_signature));
        // Use deterministic OPK generation from master key for reproducible identities
        auto opks_result = GenerateOneTimePreKeysFromMasterKey(master_key, membership_id, one_time_key_count);
        if (opks_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                opks_result.UnwrapErr());
        }
        auto opks = std::move(opks_result).Unwrap();
        auto kyber_seed = MasterKeyDerivation::DeriveKyberSeed(master_key, membership_id);
        auto kyber_result = KyberInterop::GenerateKyber768KeyPairFromSeed(kyber_seed, kPurposeIdentityKyber);
        SodiumInterop::SecureWipe(std::span(kyber_seed));
        if (kyber_result.IsErr()) {
            return Result<IdentityKeys, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(kyber_result.UnwrapErr()));
        }
        auto [kyber_secret, kyber_public] = std::move(kyber_result).Unwrap();
        IdentityKeyBundle material(
            std::move(ed_material),
            std::move(x_material),
            std::move(spk_material),
            std::move(opks),
            std::move(kyber_secret),
            std::move(kyber_public));

        auto identity_keys = IdentityKeys(std::move(material));

#ifdef ECLIPTIX_DEBUG_KEYS

        {
            auto ed_pub = identity_keys.GetIdentityEd25519PublicCopy();
            auto ed_priv_result = identity_keys.identity_ed25519_secret_key_handle_.ReadBytes(kEd25519SecretKeyBytes);
            auto x_pub = identity_keys.GetIdentityX25519PublicCopy();
            auto x_priv_result = identity_keys.identity_x25519_secret_key_handle_.ReadBytes(kX25519PrivateKeyBytes);
            auto spk_pub = identity_keys.GetSignedPreKeyPublicCopy();
            auto spk_priv_result = identity_keys.signed_pre_key_secret_key_handle_.ReadBytes(kX25519PrivateKeyBytes);
            auto kyber_pub = identity_keys.GetKyberPublicCopy();
            auto kyber_priv_result = identity_keys.kyber_secret_key_handle_.ReadBytes(KyberInterop::KYBER_768_SECRET_KEY_SIZE);

            if (ed_priv_result.IsOk() && x_priv_result.IsOk() && spk_priv_result.IsOk() && kyber_priv_result.IsOk()) {
                auto ed_priv = ed_priv_result.Unwrap();
                auto x_priv = x_priv_result.Unwrap();
                auto spk_priv = spk_priv_result.Unwrap();
                auto kyber_priv = kyber_priv_result.Unwrap();

                debug::LogIdentityKeysCreated(
                    debug::Side::Unknown,
                    ed_pub, ed_priv,
                    x_pub, x_priv,
                    identity_keys.signed_pre_key_id_,
                    spk_pub, spk_priv,
                    identity_keys.signed_pre_key_signature_,
                    kyber_pub, kyber_priv);

                for (const auto& opk : identity_keys.one_time_pre_keys_) {
                    auto opk_pub = opk.GetPublicKeyCopy();
                    auto opk_priv_result = opk.GetPrivateKeyHandle().ReadBytes(kX25519PrivateKeyBytes);
                    if (opk_priv_result.IsOk()) {
                        auto opk_priv = opk_priv_result.Unwrap();
                        debug::LogOneTimePreKey(debug::Side::Unknown, opk.GetOneTimePreKeyId(), opk_pub, opk_priv);
                        SodiumInterop::SecureWipe(std::span(opk_priv));
                    }
                }

                SodiumInterop::SecureWipe(std::span(ed_priv));
                SodiumInterop::SecureWipe(std::span(x_priv));
                SodiumInterop::SecureWipe(std::span(spk_priv));
                SodiumInterop::SecureWipe(std::span(kyber_priv));
            }
        }
#endif

        return Result<IdentityKeys, ProtocolFailure>::Ok(std::move(identity_keys));
    }

    Result<LocalPublicKeyBundle, ProtocolFailure> IdentityKeys::CreatePublicBundle() const {
        std::shared_lock lock(*lock_);
        std::vector<OneTimePreKeyPublic> opk_records;
        opk_records.reserve(one_time_pre_keys_.size());
        for (const auto &opk: one_time_pre_keys_) {
            opk_records.emplace_back(opk.GetOneTimePreKeyId(), opk.GetPublicKeyCopy());
        }
        LocalPublicKeyBundle bundle(
            identity_ed25519_public_,
            identity_x25519_public_,
            signed_pre_key_id_,
            signed_pre_key_public_,
            signed_pre_key_signature_,
            std::move(opk_records),
            ephemeral_x25519_public_,
            kyber_public_);
        return Result<LocalPublicKeyBundle, ProtocolFailure>::Ok(std::move(bundle));
    }

    void IdentityKeys::GenerateEphemeralKeyPair() {
        std::unique_lock lock(*lock_);

        if (ephemeral_secret_key_handle_.has_value() && ephemeral_x25519_public_.has_value()) {
            return;
        }

        ephemeral_secret_key_handle_.reset();
        if (ephemeral_x25519_public_.has_value()) {
            SodiumInterop::SecureWipe(std::span(ephemeral_x25519_public_.value()));
        }
        ephemeral_x25519_public_.reset();
        if (auto result = SodiumInterop::GenerateX25519KeyPair(kPurposeEphemeralX25519); result.IsOk()) {
            auto [handle, public_key] = std::move(result).Unwrap();
            ephemeral_secret_key_handle_ = std::move(handle);
            ephemeral_x25519_public_ = std::move(public_key);

#ifdef ECLIPTIX_DEBUG_KEYS
            auto priv_result = ephemeral_secret_key_handle_->ReadBytes(kX25519PrivateKeyBytes);
            if (priv_result.IsOk()) {
                auto priv = priv_result.Unwrap();
                debug::LogEphemeralKeyGenerated(debug::Side::Unknown, *ephemeral_x25519_public_, priv);
                SodiumInterop::SecureWipe(std::span(priv));
            }
#endif
        }
    }

    void IdentityKeys::ClearEphemeralKeyPair() {
        std::unique_lock lock(*lock_);
        ClearEphemeralKeyPairLocked();
    }

    void IdentityKeys::ClearEphemeralKeyPairLocked() {

        if (ephemeral_secret_key_handle_.has_value()) {
            ephemeral_secret_key_handle_.reset();
        }
        if (ephemeral_x25519_public_.has_value()) {
            SodiumInterop::SecureWipe(std::span(ephemeral_x25519_public_.value()));
            ephemeral_x25519_public_.reset();
        }
    }

    Result<bool, ProtocolFailure> IdentityKeys::VerifyRemoteSpkSignature(
        const std::span<const uint8_t> remote_identity_ed25519,
        const std::span<const uint8_t> remote_spk_public,
        const std::span<const uint8_t> remote_spk_signature) {
        if (remote_identity_ed25519.size() != kEd25519PublicKeyBytes ||
            remote_spk_public.size() != kX25519PublicKeyBytes ||
            remote_spk_signature.size() != kEd25519SignatureBytes) {
            return Result<bool, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid key or signature length for SPK verification"));
        }
        const int result = crypto_sign_verify_detached(
            remote_spk_signature.data(),
            remote_spk_public.data(),
            remote_spk_public.size(),
            remote_identity_ed25519.data());
        if (result != SodiumConstants::SUCCESS) {
            return Result<bool, ProtocolFailure>::Err(
                ProtocolFailure::Handshake("Remote SPK signature verification failed"));
        }
        return Result<bool, ProtocolFailure>::Ok(true);
    }

    Result<Unit, ProtocolFailure> IdentityKeys::ValidateHkdfInfo(
        const std::span<const uint8_t> info) {
        if (info.empty()) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::DeriveKey("HKDF info cannot be empty"));
        }
        return Result<Unit, ProtocolFailure>::Ok(Unit{});
    }

Result<Unit, ProtocolFailure> IdentityKeys::ValidateRemoteBundle(
    const LocalPublicKeyBundle &remote_bundle) {
        if (remote_bundle.GetIdentityEd25519Public().size() != kEd25519PublicKeyBytes) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::PeerPubKey("Invalid remote Ed25519 identity key"));
        }
        if (remote_bundle.GetIdentityX25519Public().size() != kX25519PublicKeyBytes) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::PeerPubKey("Invalid remote identity X25519 key"));
        }
        if (remote_bundle.GetSignedPreKeyPublic().size() != kX25519PublicKeyBytes) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::PeerPubKey("Invalid remote signed pre-key public key"));
        }
        auto verify_result = VerifyRemoteSpkSignature(
            remote_bundle.GetIdentityEd25519Public(),
            remote_bundle.GetSignedPreKeyPublic(),
            remote_bundle.GetSignedPreKeySignature());
        if (verify_result.IsErr()) {
            return Result<Unit, ProtocolFailure>::Err(verify_result.UnwrapErr());
        }
        if (!remote_bundle.HasKyberPublic() || !remote_bundle.GetKyberPublic().has_value() ||
            remote_bundle.GetKyberPublic()->size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::PeerPubKey("Invalid remote Kyber-768 public key"));
        }
        return Result<Unit, ProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, ProtocolFailure> IdentityKeys::EnsureLocalKeysValid() const {
        if (!ephemeral_secret_key_handle_.has_value() ||
            ephemeral_secret_key_handle_.value().IsInvalid()) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::PrepareLocal("Local ephemeral key missing or invalid"));
        }
        if (identity_x25519_secret_key_handle_.IsInvalid()) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::PrepareLocal("Local identity key missing or invalid"));
        }
        return Result<Unit, ProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, ProtocolFailure> IdentityKeys::ValidateX3dhPrerequisites(
        const LocalPublicKeyBundle &remote_bundle,
        const std::span<const uint8_t> info) const {
        TRY(ValidateHkdfInfo(info));
        TRY(ValidateRemoteBundle(remote_bundle));
        TRY(EnsureLocalKeysValid());
        return Result<Unit, ProtocolFailure>::Ok(Unit{});
    }

    const OneTimePreKey* IdentityKeys::FindOneTimePreKeyByIdLocked(const uint32_t one_time_pre_key_id) const {
        for (const auto& opk : one_time_pre_keys_) {
            if (opk.GetOneTimePreKeyId() == one_time_pre_key_id) {
                return &opk;
            }
        }
        return nullptr;
    }

    Result<Unit, ProtocolFailure>
    IdentityKeys::ConsumeOneTimePreKeyByIdLocked(uint32_t one_time_pre_key_id) {
        auto it = std::find_if(one_time_pre_keys_.begin(), one_time_pre_keys_.end(),
                               [one_time_pre_key_id](const OneTimePreKey &opk) {
                                   return opk.GetOneTimePreKeyId() == one_time_pre_key_id;
                               });
        if (it == one_time_pre_keys_.end()) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("OPK with requested ID not found"));
        }
        one_time_pre_keys_.erase(it);
        return Result<Unit, ProtocolFailure>::Ok(Unit{});
    }

    const OneTimePreKey* IdentityKeys::FindOneTimePreKeyById(const uint32_t one_time_pre_key_id) const {
        std::shared_lock lock(*lock_);
        return FindOneTimePreKeyByIdLocked(one_time_pre_key_id);
    }

    Result<Unit, ProtocolFailure> IdentityKeys::ConsumeOneTimePreKeyById(uint32_t one_time_pre_key_id) {
        std::unique_lock lock(*lock_);
        return ConsumeOneTimePreKeyByIdLocked(one_time_pre_key_id);
    }

    Result<size_t, ProtocolFailure> IdentityKeys::PerformX3dhDiffieHellmanAsInitiator(
        const std::span<const uint8_t> ephemeral_secret,
        const std::span<const uint8_t> identity_secret,
        const LocalPublicKeyBundle &remote_bundle,
        const std::optional<uint32_t> one_time_pre_key_id,
        std::span<uint8_t> dh_results_output) {

        fprintf(stderr, "[X3DH-INITIATOR] Starting initiator DH calculations\n");
        fprintf(stderr, "[X3DH-INITIATOR] peer_spk prefix: %02x%02x%02x%02x (size=%zu)\n",
            remote_bundle.GetSignedPreKeyPublic()[0], remote_bundle.GetSignedPreKeyPublic()[1],
            remote_bundle.GetSignedPreKeyPublic()[2], remote_bundle.GetSignedPreKeyPublic()[3],
            remote_bundle.GetSignedPreKeyPublic().size());
        fprintf(stderr, "[X3DH-INITIATOR] peer_identity prefix: %02x%02x%02x%02x (size=%zu)\n",
            remote_bundle.GetIdentityX25519Public()[0], remote_bundle.GetIdentityX25519Public()[1],
            remote_bundle.GetIdentityX25519Public()[2], remote_bundle.GetIdentityX25519Public()[3],
            remote_bundle.GetIdentityX25519Public().size());

        size_t offset = 0;
        std::vector<uint8_t> dh1(kX25519SharedSecretBytes);
        if (crypto_scalarmult(
                dh1.data(),
                identity_secret.data(),
                remote_bundle.GetSignedPreKeyPublic().data()) != 0) {
            return Result<size_t, ProtocolFailure>::Err(
                ProtocolFailure::Generic("DH1 computation failed"));
        }
        fprintf(stderr, "[X3DH-INITIATOR] DH1 = IK × peer.SPK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh1[0], dh1[1], dh1[2], dh1[3], dh1[4], dh1[5], dh1[6], dh1[7]);
        std::memcpy(dh_results_output.data() + offset, dh1.data(), kX25519SharedSecretBytes);
        offset += kX25519SharedSecretBytes;
        SodiumInterop::SecureWipe(std::span(dh1));
        std::vector<uint8_t> dh2(kX25519SharedSecretBytes);
        if (crypto_scalarmult(
                dh2.data(),
                ephemeral_secret.data(),
                remote_bundle.GetIdentityX25519Public().data()) != 0) {
            return Result<size_t, ProtocolFailure>::Err(
                ProtocolFailure::Generic("DH2 computation failed"));
        }
        fprintf(stderr, "[X3DH-INITIATOR] DH2 = EK × peer.IK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh2[0], dh2[1], dh2[2], dh2[3], dh2[4], dh2[5], dh2[6], dh2[7]);
        std::memcpy(dh_results_output.data() + offset, dh2.data(), kX25519SharedSecretBytes);
        offset += kX25519SharedSecretBytes;
        SodiumInterop::SecureWipe(std::span(dh2));
        std::vector<uint8_t> dh3(kX25519SharedSecretBytes);
        if (crypto_scalarmult(
                dh3.data(),
                ephemeral_secret.data(),
                remote_bundle.GetSignedPreKeyPublic().data()) != 0) {
            return Result<size_t, ProtocolFailure>::Err(
                ProtocolFailure::Generic("DH3 computation failed"));
        }
        fprintf(stderr, "[X3DH-INITIATOR] DH3 = EK × peer.SPK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh3[0], dh3[1], dh3[2], dh3[3], dh3[4], dh3[5], dh3[6], dh3[7]);
        std::memcpy(dh_results_output.data() + offset, dh3.data(), kX25519SharedSecretBytes);
        offset += kX25519SharedSecretBytes;
        SodiumInterop::SecureWipe(std::span(dh3));

        if (one_time_pre_key_id.has_value() && remote_bundle.HasOneTimePreKeys()) {

            const OneTimePreKeyPublic* target_opk = nullptr;
            for (const auto& opk : remote_bundle.GetOneTimePreKeys()) {
                if (opk.GetOneTimePreKeyId() == one_time_pre_key_id.value()) {
                    target_opk = &opk;
                    break;
                }
            }
            if (target_opk && target_opk->GetPublicKeySpan().size() == kX25519PublicKeyBytes) {
                fprintf(stderr, "[X3DH-INITIATOR] Using OPK ID %u, prefix: %02x%02x%02x%02x\n",
                    one_time_pre_key_id.value(),
                    target_opk->GetPublicKeySpan()[0], target_opk->GetPublicKeySpan()[1],
                    target_opk->GetPublicKeySpan()[2], target_opk->GetPublicKeySpan()[3]);
                std::vector<uint8_t> dh4(kX25519SharedSecretBytes);
                if (crypto_scalarmult(
                        dh4.data(),
                        ephemeral_secret.data(),
                        target_opk->GetPublicKeySpan().data()) != 0) {
                    return Result<size_t, ProtocolFailure>::Err(
                        ProtocolFailure::Generic("DH4 computation failed"));
                }
                fprintf(stderr, "[X3DH-INITIATOR] DH4 = EK × peer.OPK[%u] = %02x%02x%02x%02x%02x%02x%02x%02x\n",
                    one_time_pre_key_id.value(), dh4[0], dh4[1], dh4[2], dh4[3], dh4[4], dh4[5], dh4[6], dh4[7]);
                std::memcpy(dh_results_output.data() + offset, dh4.data(), kX25519SharedSecretBytes);
                offset += kX25519SharedSecretBytes;
                SodiumInterop::SecureWipe(std::span(dh4));
            } else {
                fprintf(stderr, "[X3DH-INITIATOR] ERROR: OPK ID %u not found in peer bundle!\n", one_time_pre_key_id.value());
                return Result<size_t, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Requested OPK ID not found in peer bundle"));
            }
        } else {
            fprintf(stderr, "[X3DH-INITIATOR] No OPK specified, skipping DH4\n");
        }
        fprintf(stderr, "[X3DH-INITIATOR] Total DH bytes: %zu\n", offset);
        return Result<size_t, ProtocolFailure>::Ok(offset);
    }

    Result<size_t, ProtocolFailure> IdentityKeys::PerformX3dhDiffieHellmanAsResponder(
        const LocalPublicKeyBundle &remote_bundle,
        std::optional<uint32_t> used_one_time_pre_key_id,
        std::span<uint8_t> dh_results_output) {

        fprintf(stderr, "[X3DH-RESPONDER] Starting responder DH calculations\n");

        if (!remote_bundle.HasEphemeralX25519Public()) {
            fprintf(stderr, "[X3DH-RESPONDER] ERROR: Remote bundle has no ephemeral key!\n");
            return Result<size_t, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Remote bundle must have ephemeral key for responder X3DH"));
        }

        const auto& peer_ephemeral = remote_bundle.GetEphemeralX25519Public().value();
        const auto& peer_identity = remote_bundle.GetIdentityX25519Public();

        fprintf(stderr, "[X3DH-RESPONDER] peer_ephemeral prefix: %02x%02x%02x%02x (size=%zu)\n",
            peer_ephemeral[0], peer_ephemeral[1], peer_ephemeral[2], peer_ephemeral[3], peer_ephemeral.size());
        fprintf(stderr, "[X3DH-RESPONDER] peer_identity prefix: %02x%02x%02x%02x (size=%zu)\n",
            peer_identity[0], peer_identity[1], peer_identity[2], peer_identity[3], peer_identity.size());
        fprintf(stderr, "[X3DH-RESPONDER] my_spk_public prefix: %02x%02x%02x%02x\n",
            signed_pre_key_public_[0], signed_pre_key_public_[1], signed_pre_key_public_[2], signed_pre_key_public_[3]);
        fprintf(stderr, "[X3DH-RESPONDER] my_identity_public prefix: %02x%02x%02x%02x\n",
            identity_x25519_public_[0], identity_x25519_public_[1], identity_x25519_public_[2], identity_x25519_public_[3]);

        auto spk_read_result = signed_pre_key_secret_key_handle_.ReadBytes(
            kX25519PrivateKeyBytes);
        if (spk_read_result.IsErr()) {
            return Result<size_t, ProtocolFailure>::Err(
                ProtocolFailure::Generic(spk_read_result.UnwrapErr().message));
        }
        auto spk_secret = std::move(spk_read_result).Unwrap();

        auto id_read_result = identity_x25519_secret_key_handle_.ReadBytes(
            kX25519PrivateKeyBytes);
        if (id_read_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            return Result<size_t, ProtocolFailure>::Err(
                ProtocolFailure::Generic(id_read_result.UnwrapErr().message));
        }
        auto identity_secret = std::move(id_read_result).Unwrap();

        size_t offset = 0;

        std::vector<uint8_t> dh1(kX25519SharedSecretBytes);
        if (crypto_scalarmult(dh1.data(), spk_secret.data(), peer_identity.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            SodiumInterop::SecureWipe(std::span(identity_secret));
            return Result<size_t, ProtocolFailure>::Err(
                ProtocolFailure::Generic("DH1 (responder) computation failed"));
        }
        fprintf(stderr, "[X3DH-RESPONDER] DH1 = SPK × peer.IK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh1[0], dh1[1], dh1[2], dh1[3], dh1[4], dh1[5], dh1[6], dh1[7]);
        std::memcpy(dh_results_output.data() + offset, dh1.data(), kX25519SharedSecretBytes);
        offset += kX25519SharedSecretBytes;
        SodiumInterop::SecureWipe(std::span(dh1));

        std::vector<uint8_t> dh2(kX25519SharedSecretBytes);
        if (crypto_scalarmult(dh2.data(), identity_secret.data(), peer_ephemeral.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            SodiumInterop::SecureWipe(std::span(identity_secret));
            return Result<size_t, ProtocolFailure>::Err(
                ProtocolFailure::Generic("DH2 (responder) computation failed"));
        }
        fprintf(stderr, "[X3DH-RESPONDER] DH2 = IK × peer.EK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh2[0], dh2[1], dh2[2], dh2[3], dh2[4], dh2[5], dh2[6], dh2[7]);
        std::memcpy(dh_results_output.data() + offset, dh2.data(), kX25519SharedSecretBytes);
        offset += kX25519SharedSecretBytes;
        SodiumInterop::SecureWipe(std::span(dh2));

        std::vector<uint8_t> dh3(kX25519SharedSecretBytes);
        if (crypto_scalarmult(dh3.data(), spk_secret.data(), peer_ephemeral.data()) != 0) {
            SodiumInterop::SecureWipe(std::span(spk_secret));
            SodiumInterop::SecureWipe(std::span(identity_secret));
            return Result<size_t, ProtocolFailure>::Err(
                ProtocolFailure::Generic("DH3 (responder) computation failed"));
        }
        fprintf(stderr, "[X3DH-RESPONDER] DH3 = SPK × peer.EK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
            dh3[0], dh3[1], dh3[2], dh3[3], dh3[4], dh3[5], dh3[6], dh3[7]);
        std::memcpy(dh_results_output.data() + offset, dh3.data(), kX25519SharedSecretBytes);
        offset += kX25519SharedSecretBytes;
        SodiumInterop::SecureWipe(std::span(dh3));

        if (used_one_time_pre_key_id.has_value()) {
            fprintf(stderr, "[X3DH-RESPONDER] Initiator used OPK ID: %u\n", used_one_time_pre_key_id.value());
            const OneTimePreKey* opk = FindOneTimePreKeyByIdLocked(used_one_time_pre_key_id.value());
            if (!opk) {
                SodiumInterop::SecureWipe(std::span(spk_secret));
                SodiumInterop::SecureWipe(std::span(identity_secret));
                fprintf(stderr, "[X3DH-RESPONDER] ERROR: OPK ID %u not found!\n", used_one_time_pre_key_id.value());
                return Result<size_t, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("OPK with requested ID not found"));
            }
            auto opk_read_result = opk->GetPrivateKeyHandle().ReadBytes(
                kX25519PrivateKeyBytes);
            if (opk_read_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(spk_secret));
                SodiumInterop::SecureWipe(std::span(identity_secret));
                return Result<size_t, ProtocolFailure>::Err(
                    ProtocolFailure::Generic("Failed to read OPK private key"));
            }
            auto opk_secret = std::move(opk_read_result).Unwrap();
            std::vector<uint8_t> dh4(kX25519SharedSecretBytes);
            if (crypto_scalarmult(dh4.data(), opk_secret.data(), peer_ephemeral.data()) != 0) {
                SodiumInterop::SecureWipe(std::span(dh4));
                SodiumInterop::SecureWipe(std::span(opk_secret));
                SodiumInterop::SecureWipe(std::span(spk_secret));
                SodiumInterop::SecureWipe(std::span(identity_secret));
                return Result<size_t, ProtocolFailure>::Err(
                    ProtocolFailure::Generic("DH4 (responder) computation failed"));
            }
            fprintf(stderr, "[X3DH-RESPONDER] DH4 = OPK[ID=%u] × peer.EK = %02x%02x%02x%02x%02x%02x%02x%02x\n",
                used_one_time_pre_key_id.value(), dh4[0], dh4[1], dh4[2], dh4[3], dh4[4], dh4[5], dh4[6], dh4[7]);
            std::memcpy(dh_results_output.data() + offset, dh4.data(), kX25519SharedSecretBytes);
            offset += kX25519SharedSecretBytes;
            SodiumInterop::SecureWipe(std::span(dh4));
            SodiumInterop::SecureWipe(std::span(opk_secret));
        } else {
            fprintf(stderr, "[X3DH-RESPONDER] No OPK ID provided by initiator, skipping DH4\n");
        }

        SodiumInterop::SecureWipe(std::span(spk_secret));
        SodiumInterop::SecureWipe(std::span(identity_secret));

        fprintf(stderr, "[X3DH-RESPONDER] Total DH bytes: %zu\n", offset);
        return Result<size_t, ProtocolFailure>::Ok(offset);
    }

    Result<SecureMemoryHandle, ProtocolFailure> IdentityKeys::X3dhDeriveSharedSecret(
        const LocalPublicKeyBundle &remote_bundle,
        std::span<const uint8_t> info,
        bool is_initiator) {
        std::unique_lock lock(*lock_);
        if (auto validation_result = ValidateX3dhPrerequisites(remote_bundle, info); validation_result.IsErr()) {
            return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                validation_result.UnwrapErr());
        }
        if (!remote_bundle.HasKyberPublic() || !remote_bundle.GetKyberPublic().has_value()) {
            return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Remote Kyber public key required for hybrid X3DH"));
        }

        std::vector<uint8_t> dh_results(kX25519SharedSecretBytes * 4);
        size_t dh_offset = 0;
        std::optional<uint32_t> used_one_time_pre_key_id;

        if (is_initiator) {

            auto eph_read_result = ephemeral_secret_key_handle_.value().ReadBytes(
                kX25519PrivateKeyBytes);
            if (eph_read_result.IsErr()) {
                return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                    ProtocolFailure::Generic(eph_read_result.UnwrapErr().message));
            }
            auto ephemeral_secret = std::move(eph_read_result).Unwrap();
            auto id_read_result = identity_x25519_secret_key_handle_.ReadBytes(
                kX25519PrivateKeyBytes);
            if (id_read_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(ephemeral_secret));
                return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                    ProtocolFailure::Generic(id_read_result.UnwrapErr().message));
            }
            auto identity_secret = std::move(id_read_result).Unwrap();

            std::optional<uint32_t> opk_to_use = remote_bundle.GetUsedOneTimePreKeyId();
            const char *opk_source = nullptr;
            if (opk_to_use.has_value()) {
                opk_source = "server pre-selected";
            } else if (selected_one_time_pre_key_id_.has_value()) {
                opk_to_use = selected_one_time_pre_key_id_;
                opk_source = "client selected";
            }
            bool use_opk = opk_to_use.has_value();

            if (use_opk) {
                selected_one_time_pre_key_id_ = opk_to_use.value();
                used_one_time_pre_key_id = opk_to_use;
                fprintf(stderr, "[X3DH] Initiator using OPK ID: %u (source: %s)\n",
                    opk_to_use.value(),
                    opk_source ? opk_source : "unknown");
            } else {
                selected_one_time_pre_key_id_.reset();
                fprintf(stderr, "[X3DH] Initiator: no explicit OPK selected, skipping DH4\n");
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
                return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                    dh_result.UnwrapErr());
            }
            dh_offset = std::move(dh_result).Unwrap();
        } else {

            used_one_time_pre_key_id = selected_one_time_pre_key_id_.has_value()
                ? selected_one_time_pre_key_id_
                : remote_bundle.GetUsedOneTimePreKeyId();
            fprintf(stderr, "[X3DH] Responder using OPK ID: %s (source: %s)\n",
                used_one_time_pre_key_id.has_value() ? std::to_string(used_one_time_pre_key_id.value()).c_str() : "none",
                selected_one_time_pre_key_id_.has_value() ? "server pre-selected" : "client bundle");

            auto dh_result = PerformX3dhDiffieHellmanAsResponder(remote_bundle, used_one_time_pre_key_id, dh_results);
            if (dh_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(dh_results));
                return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                    dh_result.UnwrapErr());
            }
            dh_offset = std::move(dh_result).Unwrap();
        }
        std::vector<uint8_t> ikm(kX25519SharedSecretBytes + dh_offset);
        std::fill_n(ikm.begin(), kX25519SharedSecretBytes, CryptoHashConstants::FILL_BYTE);
        std::memcpy(ikm.data() + kX25519SharedSecretBytes, dh_results.data(), dh_offset);
        SodiumInterop::SecureWipe(std::span(dh_results));
        std::vector<uint8_t> classical_shared(kX25519SharedSecretBytes);
        auto hkdf_result = Hkdf::DeriveKey(ikm, classical_shared, {}, info);

        SodiumInterop::SecureWipe(std::span(ikm));
        if (hkdf_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span(classical_shared));
            return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                hkdf_result.UnwrapErr());
        }

        std::vector<uint8_t> kyber_ciphertext;
        std::vector<uint8_t> kyber_ss_bytes;
        bool used_stored_artifacts = false;

        const bool has_peer_ciphertext = remote_bundle.HasKyberCiphertext();
        const bool use_pending = pending_kyber_handshake_.has_value() &&
            (is_initiator || !has_peer_ciphertext);

        if (use_pending) {
            kyber_ciphertext = pending_kyber_handshake_->kyber_ciphertext;
            kyber_ss_bytes = pending_kyber_handshake_->kyber_shared_secret;
            used_stored_artifacts = true;
        } else if (has_peer_ciphertext) {

            const auto& peer_ciphertext = remote_bundle.GetKyberCiphertext().value();
            auto decap_result = DecapsulateKyberCiphertextLocked(
                std::span<const uint8_t>(peer_ciphertext.data(), peer_ciphertext.size()));
            if (decap_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(classical_shared));
                return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                    decap_result.UnwrapErr());
            }
            auto artifacts = std::move(decap_result).Unwrap();
            kyber_ciphertext = std::move(artifacts.kyber_ciphertext);
            kyber_ss_bytes = std::move(artifacts.kyber_shared_secret);

            used_stored_artifacts = false;
        } else {

            const auto &remote_kyber_public = remote_bundle.GetKyberPublic().value();
            auto encaps_result = KyberInterop::Encapsulate(remote_kyber_public);
            if (encaps_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(classical_shared));
                return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(encaps_result.UnwrapErr()));
            }
            auto [ct, kyber_ss_handle] = std::move(encaps_result).Unwrap();
            kyber_ciphertext = std::move(ct);

            auto kyber_ss_bytes_result = kyber_ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
            if (kyber_ss_bytes_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(classical_shared));
                return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(kyber_ss_bytes_result.UnwrapErr()));
            }
            kyber_ss_bytes = kyber_ss_bytes_result.Unwrap();
        }

        auto hybrid_result = KyberInterop::CombineHybridSecrets(
            classical_shared,
            kyber_ss_bytes,
            std::string(kX3dhInfo));
        auto _wipe_classical = SodiumInterop::SecureWipe(std::span(classical_shared));
        (void) _wipe_classical;
        if (hybrid_result.IsErr()) {
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_ss_bytes));
            (void) _wipe_pq;
            return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                hybrid_result.UnwrapErr());
        }

        if (!used_stored_artifacts) {
            pending_kyber_handshake_ = HybridHandshakeArtifacts{
                std::move(kyber_ciphertext),
                kyber_ss_bytes
            };
        }
        auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_ss_bytes));
        (void) _wipe_pq;
        auto handle = std::move(hybrid_result).Unwrap();

        if (is_initiator) {
            ClearEphemeralKeyPairLocked();
        }

        Result<Unit, ProtocolFailure> consume_result = Result<Unit, ProtocolFailure>::Ok(Unit{});
        if (!is_initiator && used_one_time_pre_key_id.has_value()) {
            consume_result = ConsumeOneTimePreKeyByIdLocked(used_one_time_pre_key_id.value());
        }
        selected_one_time_pre_key_id_.reset();
        if (consume_result.IsErr()) {
            return Result<SecureMemoryHandle, ProtocolFailure>::Err(consume_result.UnwrapErr());
        }

        return Result<SecureMemoryHandle, ProtocolFailure>::Ok(std::move(handle));
    }

    Result<IdentityKeys::HybridHandshakeArtifacts, ProtocolFailure>
    IdentityKeys::ConsumePendingKyberHandshake() {
        std::unique_lock lock(*lock_);
        if (!pending_kyber_handshake_.has_value()) {
            return Result<HybridHandshakeArtifacts, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("No pending Kyber handshake data"));
        }
        auto artifacts = std::move(*pending_kyber_handshake_);
        pending_kyber_handshake_.reset();
        return Result<HybridHandshakeArtifacts, ProtocolFailure>::Ok(std::move(artifacts));
    }

    void IdentityKeys::StorePendingKyberHandshake(
        std::vector<uint8_t> kyber_ciphertext,
        std::vector<uint8_t> kyber_shared_secret) {
        std::unique_lock lock(*lock_);
        pending_kyber_handshake_ = HybridHandshakeArtifacts{
            std::move(kyber_ciphertext),
            std::move(kyber_shared_secret)
        };
    }

    Result<std::vector<uint8_t>, ProtocolFailure>
    IdentityKeys::GetPendingKyberCiphertext() const {
        std::shared_lock lock(*lock_);
        if (!pending_kyber_handshake_.has_value()) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("No pending Kyber handshake data"));
        }
        return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(
            pending_kyber_handshake_->kyber_ciphertext);
    }

    Result<IdentityKeys::HybridHandshakeArtifacts, ProtocolFailure>
    IdentityKeys::DecapsulateKyberCiphertext(const std::span<const uint8_t> ciphertext) const {
        std::shared_lock lock(*lock_);
        return DecapsulateKyberCiphertextLocked(ciphertext);
    }

    Result<IdentityKeys::HybridHandshakeArtifacts, ProtocolFailure>
    IdentityKeys::DecapsulateKyberCiphertextLocked(std::span<const uint8_t> ciphertext) const {
        auto validate_result = KyberInterop::ValidateCiphertext(ciphertext);
        if (validate_result.IsErr()) {
            return Result<HybridHandshakeArtifacts, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(validate_result.UnwrapErr()));
        }
        auto decap_result = KyberInterop::Decapsulate(ciphertext, kyber_secret_key_handle_);
        if (decap_result.IsErr()) {
            return Result<HybridHandshakeArtifacts, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(decap_result.UnwrapErr()));
        }
        auto kyber_ss_handle = std::move(decap_result).Unwrap();
        auto ss_bytes_result = kyber_ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
        if (ss_bytes_result.IsErr()) {
            return Result<HybridHandshakeArtifacts, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(ss_bytes_result.UnwrapErr()));
        }
        return Result<HybridHandshakeArtifacts, ProtocolFailure>::Ok(
            HybridHandshakeArtifacts{
                std::vector(ciphertext.begin(), ciphertext.end()),
                ss_bytes_result.Unwrap()
            });
    }
}
