#pragma once
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include <vector>
#include <cstdint>
namespace ecliptix::protocol::models {
class X25519KeyMaterial {
public:
    X25519KeyMaterial(
        crypto::SecureMemoryHandle secret_key_handle,
        std::vector<uint8_t> public_key);
    X25519KeyMaterial(X25519KeyMaterial&&) noexcept = default;
    X25519KeyMaterial& operator=(X25519KeyMaterial&&) noexcept = default;
    X25519KeyMaterial(const X25519KeyMaterial&) = delete;
    X25519KeyMaterial& operator=(const X25519KeyMaterial&) = delete;
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
    [[nodiscard]] crypto::SecureMemoryHandle TakeSecretKeyHandle() && {
        return std::move(secret_key_handle_);
    }
    [[nodiscard]] std::vector<uint8_t> TakePublicKey() && {
        return std::move(public_key_);
    }
private:
    crypto::SecureMemoryHandle secret_key_handle_;
    std::vector<uint8_t> public_key_;
};
} 
