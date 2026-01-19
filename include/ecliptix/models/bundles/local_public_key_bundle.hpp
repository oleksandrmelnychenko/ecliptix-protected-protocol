#pragma once
#include "ecliptix/models/keys/one_time_pre_key_public.hpp"
#include <vector>
#include <cstdint>
#include <optional>
namespace ecliptix::protocol::models {
class LocalPublicKeyBundle {
public:
    LocalPublicKeyBundle(
        std::vector<uint8_t> identity_ed25519_public,
        std::vector<uint8_t> identity_x25519_public,
        uint32_t signed_pre_key_id,
        std::vector<uint8_t> signed_pre_key_public,
        std::vector<uint8_t> signed_pre_key_signature,
        std::vector<OneTimePreKeyPublic> one_time_pre_keys,
        std::optional<std::vector<uint8_t>> ephemeral_x25519_public = std::nullopt,
        std::optional<std::vector<uint8_t>> kyber_public = std::nullopt,
        std::optional<std::vector<uint8_t>> kyber_ciphertext = std::nullopt,
        std::optional<uint32_t> used_one_time_pre_key_id = std::nullopt);
    LocalPublicKeyBundle(const LocalPublicKeyBundle&) = default;
    LocalPublicKeyBundle(LocalPublicKeyBundle&&) noexcept = default;
    LocalPublicKeyBundle& operator=(const LocalPublicKeyBundle&) = default;
    LocalPublicKeyBundle& operator=(LocalPublicKeyBundle&&) noexcept = default;
    ~LocalPublicKeyBundle() = default;
    [[nodiscard]] const std::vector<uint8_t>& GetIdentityEd25519Public() const noexcept {
        return identity_ed25519_public_;
    }
    [[nodiscard]] const std::vector<uint8_t>& GetIdentityX25519Public() const noexcept {
        return identity_x25519_public_;
    }
    [[nodiscard]] std::vector<uint8_t> GetIdentityX25519PublicCopy() const {
        return identity_x25519_public_;
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
    [[nodiscard]] const std::vector<OneTimePreKeyPublic>& GetOneTimePreKeys() const noexcept {
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
    [[nodiscard]] bool HasEphemeralX25519Public() const noexcept {
        return ephemeral_x25519_public_.has_value();
    }
    [[nodiscard]] const std::optional<std::vector<uint8_t>>& GetKyberPublic() const noexcept {
        return kyber_public_;
    }
    [[nodiscard]] bool HasKyberPublic() const noexcept {
        return kyber_public_.has_value();
    }
    [[nodiscard]] const std::optional<std::vector<uint8_t>>& GetKyberCiphertext() const noexcept {
        return kyber_ciphertext_;
    }
    [[nodiscard]] bool HasKyberCiphertext() const noexcept {
        return kyber_ciphertext_.has_value() && !kyber_ciphertext_->empty();
    }
    [[nodiscard]] std::optional<uint32_t> GetUsedOneTimePreKeyId() const noexcept {
        return used_one_time_pre_key_id_;
    }
    [[nodiscard]] bool HasUsedOneTimePreKeyId() const noexcept {
        return used_one_time_pre_key_id_.has_value();
    }
    void SetUsedOneTimePreKeyId(uint32_t one_time_pre_key_id) {
        used_one_time_pre_key_id_ = one_time_pre_key_id;
    }
private:
    std::vector<uint8_t> identity_ed25519_public_;
    std::vector<uint8_t> identity_x25519_public_;
    uint32_t signed_pre_key_id_;
    std::vector<uint8_t> signed_pre_key_public_;
    std::vector<uint8_t> signed_pre_key_signature_;
    std::vector<OneTimePreKeyPublic> one_time_pre_keys_;
    std::optional<std::vector<uint8_t>> ephemeral_x25519_public_;
    std::optional<std::vector<uint8_t>> kyber_public_;
    std::optional<std::vector<uint8_t>> kyber_ciphertext_;
    std::optional<uint32_t> used_one_time_pre_key_id_;
};
} 
