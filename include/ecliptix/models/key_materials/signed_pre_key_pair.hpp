#pragma once
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include <vector>
#include <cstdint>
namespace ecliptix::protocol::models {
class SignedPreKeyPair {
public:
    SignedPreKeyPair(
        uint32_t id,
        crypto::SecureMemoryHandle secret_key_handle,
        std::vector<uint8_t> public_key,
        std::vector<uint8_t> signature);
    SignedPreKeyPair(SignedPreKeyPair&&) noexcept = default;
    SignedPreKeyPair& operator=(SignedPreKeyPair&&) noexcept = default;
    SignedPreKeyPair(const SignedPreKeyPair&) = delete;
    SignedPreKeyPair& operator=(const SignedPreKeyPair&) = delete;
    [[nodiscard]] uint32_t GetId() const noexcept {
        return id_;
    }
    [[nodiscard]] const crypto::SecureMemoryHandle& GetSecretKeyHandle() const noexcept {
        return secret_key_handle_;
    }
    [[nodiscard]] crypto::SecureMemoryHandle& GetSecretKeyHandle() noexcept {
        return secret_key_handle_;
    }
    [[nodiscard]] std::vector<uint8_t> GetPublicKeyCopy() const {
        return public_key_;
    }
    [[nodiscard]] const std::vector<uint8_t>& GetPublicKey() const noexcept {
        return public_key_;
    }
    [[nodiscard]] std::vector<uint8_t> GetSignatureCopy() const {
        return signature_;
    }
    [[nodiscard]] const std::vector<uint8_t>& GetSignature() const noexcept {
        return signature_;
    }
    [[nodiscard]] crypto::SecureMemoryHandle TakeSecretKeyHandle() && {
        return std::move(secret_key_handle_);
    }
    [[nodiscard]] std::vector<uint8_t> TakePublicKey() && {
        return std::move(public_key_);
    }
    [[nodiscard]] std::vector<uint8_t> TakeSignature() && {
        return std::move(signature_);
    }
private:
    uint32_t id_;
    crypto::SecureMemoryHandle secret_key_handle_;
    std::vector<uint8_t> public_key_;
    std::vector<uint8_t> signature_;
};
}
