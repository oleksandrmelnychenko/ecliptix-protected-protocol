#pragma once
#include "ecliptix/models/keys/one_time_pre_key_record.hpp"
#include <vector>
#include <cstdint>
#include <optional>
namespace ecliptix::protocol::models {
class LocalPublicKeyBundle {
public:
    LocalPublicKeyBundle(
        std::vector<uint8_t> ed25519_public,
        std::vector<uint8_t> identity_x25519_public,
        uint32_t signed_pre_key_id,
        std::vector<uint8_t> signed_pre_key_public,
        std::vector<uint8_t> signed_pre_key_signature,
        std::vector<OneTimePreKeyRecord> one_time_pre_keys,
        std::optional<std::vector<uint8_t>> ephemeral_x25519_public = std::nullopt,
        std::optional<std::vector<uint8_t>> kyber_public_key = std::nullopt);
    LocalPublicKeyBundle(const LocalPublicKeyBundle&) = default;
    LocalPublicKeyBundle(LocalPublicKeyBundle&&) noexcept = default;
    LocalPublicKeyBundle& operator=(const LocalPublicKeyBundle&) = default;
    LocalPublicKeyBundle& operator=(LocalPublicKeyBundle&&) noexcept = default;
    ~LocalPublicKeyBundle() = default;
    [[nodiscard]] const std::vector<uint8_t>& GetEd25519Public() const noexcept {
        return ed25519_public_;
    }
    [[nodiscard]] const std::vector<uint8_t>& GetIdentityX25519() const noexcept {
        return identity_x25519_;
    }
    [[nodiscard]] std::vector<uint8_t> GetIdentityX25519Copy() const {
        return identity_x25519_;
    }
    [[nodiscard]] uint32_t GetSignedPreKeyId() const noexcept {
        return signed_pre_key_id_;
    }
    [[nodiscard]] const std::vector<uint8_t>& GetSignedPreKeyPublic() const noexcept {
        return signed_pre_key_public_;
    }
    [[nodiscard]] std::vector<uint8_t> GetSignedPreKeyPublicCopy() const {
        return signed_pre_key_public_;
    }
    [[nodiscard]] const std::vector<uint8_t>& GetSignedPreKeySignature() const noexcept {
        return signed_pre_key_signature_;
    }
    [[nodiscard]] const std::vector<OneTimePreKeyRecord>& GetOneTimePreKeys() const noexcept {
        return one_time_pre_keys_;
    }
    [[nodiscard]] size_t GetOneTimePreKeyCount() const noexcept {
        return one_time_pre_keys_.size();
    }
    [[nodiscard]] bool HasOneTimePreKeys() const noexcept {
        return !one_time_pre_keys_.empty();
    }
    [[nodiscard]] const std::optional<std::vector<uint8_t>>& GetEphemeralX25519Public() const noexcept {
        return ephemeral_x25519_public_;
    }
    [[nodiscard]] bool HasEphemeralKey() const noexcept {
        return ephemeral_x25519_public_.has_value();
    }
    [[nodiscard]] const std::optional<std::vector<uint8_t>>& GetKyberPublicKey() const noexcept {
        return kyber_public_key_;
    }
    [[nodiscard]] bool HasKyberKey() const noexcept {
        return kyber_public_key_.has_value();
    }
private:
    std::vector<uint8_t> ed25519_public_;
    std::vector<uint8_t> identity_x25519_;
    uint32_t signed_pre_key_id_;
    std::vector<uint8_t> signed_pre_key_public_;
    std::vector<uint8_t> signed_pre_key_signature_;
    std::vector<OneTimePreKeyRecord> one_time_pre_keys_;
    std::optional<std::vector<uint8_t>> ephemeral_x25519_public_;
    std::optional<std::vector<uint8_t>> kyber_public_key_;
};
} 
