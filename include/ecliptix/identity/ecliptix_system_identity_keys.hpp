#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/models/bundles/local_public_key_bundle.hpp"
#include "ecliptix/models/identity_keys_material.hpp"
#include <vector>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
namespace ecliptix::protocol::identity {
using protocol::Result;
using protocol::Unit;
using protocol::EcliptixProtocolFailure;
using crypto::SecureMemoryHandle;
using models::LocalPublicKeyBundle;
using models::IdentityKeysMaterial;
using models::Ed25519KeyMaterial;
using models::X25519KeyMaterial;
using models::OneTimePreKeyLocal;
class EcliptixSystemIdentityKeys {
public:
    [[nodiscard]] static Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> Create(
        uint32_t one_time_key_count);
    [[nodiscard]] static Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> CreateFromMasterKey(
        std::span<const uint8_t> master_key,
        std::string_view membership_id,
        uint32_t one_time_key_count);
    [[nodiscard]] std::vector<uint8_t> GetIdentityX25519PublicKeyCopy() const;
    [[nodiscard]] Result<LocalPublicKeyBundle, EcliptixProtocolFailure> CreatePublicBundle() const;
    void GenerateEphemeralKeyPair();
    [[nodiscard]] Result<SecureMemoryHandle, EcliptixProtocolFailure> X3dhDeriveSharedSecret(
        const LocalPublicKeyBundle& remote_bundle,
        std::span<const uint8_t> info);
    [[nodiscard]] static Result<bool, EcliptixProtocolFailure> VerifyRemoteSpkSignature(
        std::span<const uint8_t> remote_identity_ed25519,
        std::span<const uint8_t> remote_spk_public,
        std::span<const uint8_t> remote_spk_signature);
    EcliptixSystemIdentityKeys(EcliptixSystemIdentityKeys&&) noexcept = default;
    EcliptixSystemIdentityKeys& operator=(EcliptixSystemIdentityKeys&&) noexcept = default;
    EcliptixSystemIdentityKeys(const EcliptixSystemIdentityKeys&) = delete;
    EcliptixSystemIdentityKeys& operator=(const EcliptixSystemIdentityKeys&) = delete;
    ~EcliptixSystemIdentityKeys() = default;
private:
    explicit EcliptixSystemIdentityKeys(IdentityKeysMaterial material);
    [[nodiscard]] static Result<Ed25519KeyMaterial, EcliptixProtocolFailure> GenerateEd25519Keys();
    [[nodiscard]] static Result<X25519KeyMaterial, EcliptixProtocolFailure> GenerateX25519IdentityKeys();
    [[nodiscard]] static Result<X25519KeyMaterial, EcliptixProtocolFailure> GenerateX25519SignedPreKey(
        uint32_t id);
    [[nodiscard]] static Result<std::vector<uint8_t>, EcliptixProtocolFailure> SignSignedPreKey(
        const SecureMemoryHandle& ed_secret_key_handle,
        std::span<const uint8_t> spk_public);
    [[nodiscard]] static Result<std::vector<OneTimePreKeyLocal>, EcliptixProtocolFailure> GenerateOneTimePreKeys(
        uint32_t count);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> ValidateX3dhPrerequisites(
        const LocalPublicKeyBundle& remote_bundle,
        std::span<const uint8_t> info) const;
    [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> ValidateHkdfInfo(
        std::span<const uint8_t> info);
    [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> ValidateRemoteBundle(
        const LocalPublicKeyBundle& remote_bundle);
    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> EnsureLocalKeysValid() const;
    [[nodiscard]] static Result<size_t, EcliptixProtocolFailure> PerformX3dhDiffieHellman(
        std::span<const uint8_t> ephemeral_secret,
        std::span<const uint8_t> identity_secret,
        const LocalPublicKeyBundle& remote_bundle,
        bool use_opk,
        std::span<uint8_t> dh_results_output);
    SecureMemoryHandle ed25519_secret_key_handle_;
    std::vector<uint8_t> ed25519_public_key_;
    SecureMemoryHandle identity_x25519_secret_key_handle_;
    std::vector<uint8_t> identity_x25519_public_key_;
    uint32_t signed_pre_key_id_;
    SecureMemoryHandle signed_pre_key_secret_key_handle_;
    std::vector<uint8_t> signed_pre_key_public_;
    std::vector<uint8_t> signed_pre_key_signature_;
    std::vector<OneTimePreKeyLocal> one_time_pre_keys_;
    std::optional<SecureMemoryHandle> ephemeral_secret_key_handle_;
    std::optional<std::vector<uint8_t>> ephemeral_x25519_public_key_;
};
} 
