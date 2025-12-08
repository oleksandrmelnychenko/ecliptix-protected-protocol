#pragma once
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/core/constants.hpp"
#include <vector>
#include <cstdint>
#include <span>
namespace ecliptix::protocol::models {
class OneTimePreKeyLocal {
public:
    static Result<OneTimePreKeyLocal, EcliptixProtocolFailure> Generate(uint32_t pre_key_id);
    static OneTimePreKeyLocal CreateFromParts(
        uint32_t pre_key_id,
        crypto::SecureMemoryHandle private_key_handle,
        std::vector<uint8_t> public_key);
    OneTimePreKeyLocal(OneTimePreKeyLocal&&) noexcept = default;
    OneTimePreKeyLocal& operator=(OneTimePreKeyLocal&&) noexcept = default;
    OneTimePreKeyLocal(const OneTimePreKeyLocal&) = delete;
    OneTimePreKeyLocal& operator=(const OneTimePreKeyLocal&) = delete;
    ~OneTimePreKeyLocal() = default;
    [[nodiscard]] uint32_t GetPreKeyId() const noexcept {
        return pre_key_id_;
    }
    [[nodiscard]] const crypto::SecureMemoryHandle& GetPrivateKeyHandle() const noexcept {
        return private_key_handle_;
    }
    [[nodiscard]] crypto::SecureMemoryHandle& GetPrivateKeyHandle() noexcept {
        return private_key_handle_;
    }
    [[nodiscard]] std::vector<uint8_t> GetPublicKeyCopy() const {
        return public_key_;
    }
    [[nodiscard]] const std::vector<uint8_t>& GetPublicKey() const noexcept {
        return public_key_;
    }
    [[nodiscard]] std::span<const uint8_t> GetPublicKeySpan() const noexcept {
        return std::span<const uint8_t>(public_key_);
    }
private:
    OneTimePreKeyLocal(
        uint32_t pre_key_id,
        crypto::SecureMemoryHandle private_key_handle,
        std::vector<uint8_t> public_key);
    uint32_t pre_key_id_;
    crypto::SecureMemoryHandle private_key_handle_;
    std::vector<uint8_t> public_key_;
};
} 
