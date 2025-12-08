#pragma once
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include <vector>
#include <cstdint>
namespace ecliptix::protocol::models {
class Ed25519KeyMaterial {
public:
    Ed25519KeyMaterial(
        crypto::SecureMemoryHandle secret_key_handle,
        std::vector<uint8_t> public_key);
    Ed25519KeyMaterial(Ed25519KeyMaterial&&) noexcept = default;
    Ed25519KeyMaterial& operator=(Ed25519KeyMaterial&&) noexcept = default;
    Ed25519KeyMaterial(const Ed25519KeyMaterial&) = delete;
    Ed25519KeyMaterial& operator=(const Ed25519KeyMaterial&) = delete;
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
