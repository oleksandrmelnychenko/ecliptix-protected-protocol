#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/models/bundles/local_public_key_bundle.hpp"
#include "ecliptix/models/identity_key_bundle.hpp"
#include <vector>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <shared_mutex>
#include <memory>
namespace ecliptix::protocol::identity {
using protocol::Result;
using protocol::Unit;
using protocol::ProtocolFailure;
using crypto::SecureMemoryHandle;
using models::LocalPublicKeyBundle;
using models::IdentityKeyBundle;
using models::Ed25519KeyPair;
using models::X25519KeyPair;
using models::OneTimePreKey;
class IdentityKeys {
public:
    struct HybridHandshakeArtifacts {
        std::vector<uint8_t> kyber_ciphertext;
        std::vector<uint8_t> kyber_shared_secret;
    };
    [[nodiscard]] static Result<IdentityKeys, ProtocolFailure> Create(
        uint32_t one_time_key_count);
    [[nodiscard]] static Result<IdentityKeys, ProtocolFailure> CreateFromMasterKey(
        std::span<const uint8_t> master_key,
        std::string_view membership_id,
        uint32_t one_time_key_count);
    [[nodiscard]] std::vector<uint8_t> GetIdentityX25519PublicCopy() const;
    [[nodiscard]] std::vector<uint8_t> GetIdentityEd25519PublicCopy() const;
    [[nodiscard]] std::vector<uint8_t> GetKyberPublicCopy() const;
    [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure> GetIdentityX25519PrivateKeyCopy() const;
    [[nodiscard]] Result<SecureMemoryHandle, ProtocolFailure> CloneKyberSecretKey() const;
    [[nodiscard]] std::optional<std::vector<uint8_t>> GetEphemeralX25519PublicCopy() const;
    [[nodiscard]] std::vector<uint8_t> GetSignedPreKeyPublicCopy() const;
    [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure> GetEphemeralX25519PrivateKeyCopy() const;
    [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure> GetSignedPreKeyPrivateCopy() const;
    [[nodiscard]] Result<LocalPublicKeyBundle, ProtocolFailure> CreatePublicBundle() const;
    void GenerateEphemeralKeyPair();
    [[nodiscard]] Result<SecureMemoryHandle, ProtocolFailure> X3dhDeriveSharedSecret(
        const LocalPublicKeyBundle& remote_bundle,
        std::span<const uint8_t> info,
        bool is_initiator);
    [[nodiscard]] Result<HybridHandshakeArtifacts, ProtocolFailure> ConsumePendingKyberHandshake();
    void StorePendingKyberHandshake(
        std::vector<uint8_t> kyber_ciphertext,
        std::vector<uint8_t> kyber_shared_secret);
    [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure> GetPendingKyberCiphertext() const;
    [[nodiscard]] Result<HybridHandshakeArtifacts, ProtocolFailure> DecapsulateKyberCiphertext(
        std::span<const uint8_t> ciphertext) const;
    [[nodiscard]] static Result<bool, ProtocolFailure> VerifyRemoteSpkSignature(
        std::span<const uint8_t> remote_identity_ed25519,
        std::span<const uint8_t> remote_spk_public,
        std::span<const uint8_t> remote_spk_signature);
    [[nodiscard]] const OneTimePreKey* FindOneTimePreKeyById(uint32_t one_time_pre_key_id) const;
    [[nodiscard]] Result<Unit, ProtocolFailure> ConsumeOneTimePreKeyById(uint32_t one_time_pre_key_id);
    [[nodiscard]] std::optional<uint32_t> GetSelectedOneTimePreKeyId() const;
    void SetSelectedOneTimePreKeyId(uint32_t one_time_pre_key_id);
    void ClearSelectedOneTimePreKeyId();
    void ClearEphemeralKeyPair();
    IdentityKeys(IdentityKeys&&) noexcept = default;
    IdentityKeys& operator=(IdentityKeys&&) noexcept = default;
    IdentityKeys(const IdentityKeys&) = delete;
    IdentityKeys& operator=(const IdentityKeys&) = delete;
    ~IdentityKeys() = default;
private:
    explicit IdentityKeys(IdentityKeyBundle material);
    [[nodiscard]] static Result<Ed25519KeyPair, ProtocolFailure> GenerateEd25519Keys();
    [[nodiscard]] static Result<X25519KeyPair, ProtocolFailure> GenerateX25519IdentityKeys();
    [[nodiscard]] static Result<X25519KeyPair, ProtocolFailure> GenerateX25519SignedPreKey(
    );
    [[nodiscard]] static Result<std::vector<uint8_t>, ProtocolFailure> SignSignedPreKey(
        const SecureMemoryHandle& ed_secret_key_handle,
        std::span<const uint8_t> spk_public);
    [[nodiscard]] static Result<std::vector<OneTimePreKey>, ProtocolFailure> GenerateOneTimePreKeys(
        uint32_t count);
    [[nodiscard]] Result<Unit, ProtocolFailure> ValidateX3dhPrerequisites(
        const LocalPublicKeyBundle& remote_bundle,
        std::span<const uint8_t> info) const;
    [[nodiscard]] static Result<Unit, ProtocolFailure> ValidateHkdfInfo(
        std::span<const uint8_t> info);
    [[nodiscard]] static Result<Unit, ProtocolFailure> ValidateRemoteBundle(
        const LocalPublicKeyBundle& remote_bundle);
    [[nodiscard]] Result<Unit, ProtocolFailure> EnsureLocalKeysValid() const;
    [[nodiscard]] static Result<size_t, ProtocolFailure> PerformX3dhDiffieHellmanAsInitiator(
        std::span<const uint8_t> ephemeral_secret,
        std::span<const uint8_t> identity_secret,
        const LocalPublicKeyBundle& remote_bundle,
        std::optional<uint32_t> one_time_pre_key_id,
        std::span<uint8_t> dh_results_output);
    [[nodiscard]] Result<size_t, ProtocolFailure> PerformX3dhDiffieHellmanAsResponder(
        const LocalPublicKeyBundle& remote_bundle,
        std::optional<uint32_t> used_one_time_pre_key_id,
        std::span<uint8_t> dh_results_output);
    [[nodiscard]] const OneTimePreKey* FindOneTimePreKeyByIdLocked(uint32_t one_time_pre_key_id) const;
    [[nodiscard]] Result<Unit, ProtocolFailure> ConsumeOneTimePreKeyByIdLocked(uint32_t one_time_pre_key_id);
    [[nodiscard]] Result<HybridHandshakeArtifacts, ProtocolFailure> DecapsulateKyberCiphertextLocked(
        std::span<const uint8_t> ciphertext) const;
    void ClearEphemeralKeyPairLocked();
    SecureMemoryHandle identity_ed25519_secret_key_handle_;
    std::vector<uint8_t> identity_ed25519_public_;
    SecureMemoryHandle identity_x25519_secret_key_handle_;
    std::vector<uint8_t> identity_x25519_public_;
    uint32_t signed_pre_key_id_;
    SecureMemoryHandle signed_pre_key_secret_key_handle_;
    std::vector<uint8_t> signed_pre_key_public_;
    std::vector<uint8_t> signed_pre_key_signature_;
    std::vector<OneTimePreKey> one_time_pre_keys_;
    SecureMemoryHandle kyber_secret_key_handle_;
    std::vector<uint8_t> kyber_public_;
    std::optional<HybridHandshakeArtifacts> pending_kyber_handshake_;
    std::optional<SecureMemoryHandle> ephemeral_secret_key_handle_;
    std::optional<std::vector<uint8_t>> ephemeral_x25519_public_;
    std::optional<uint32_t> selected_one_time_pre_key_id_;
    mutable std::unique_ptr<std::shared_mutex> lock_;
};
} 
