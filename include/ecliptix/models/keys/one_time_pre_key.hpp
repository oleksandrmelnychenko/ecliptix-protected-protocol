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
class OneTimePreKey {
public:
    static Result<OneTimePreKey, ProtocolFailure> Generate(uint32_t one_time_pre_key_id);
    static OneTimePreKey CreateFromParts(
        uint32_t one_time_pre_key_id,
        crypto::SecureMemoryHandle private_key_handle,
        std::vector<uint8_t> public_key);
    OneTimePreKey(OneTimePreKey&&) noexcept = default;
    OneTimePreKey& operator=(OneTimePreKey&&) noexcept = default;
    OneTimePreKey(const OneTimePreKey&) = delete;
    OneTimePreKey& operator=(const OneTimePreKey&) = delete;
    ~OneTimePreKey() = default;
    [[nodiscard]] uint32_t GetOneTimePreKeyId() const noexcept {
        return one_time_pre_key_id_;
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
    OneTimePreKey(
        uint32_t one_time_pre_key_id,
        crypto::SecureMemoryHandle private_key_handle,
        std::vector<uint8_t> public_key);
    uint32_t one_time_pre_key_id_;
    crypto::SecureMemoryHandle private_key_handle_;
    std::vector<uint8_t> public_key_;
};
} 
