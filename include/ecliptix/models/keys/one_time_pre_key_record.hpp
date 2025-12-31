#pragma once
#include <vector>
#include <cstdint>
#include <optional>
#include <span>
namespace ecliptix::protocol::models {
class OneTimePreKeyRecord {
public:
    OneTimePreKeyRecord(uint32_t pre_key_id, std::vector<uint8_t> public_key, std::optional<std::vector<uint8_t>> kyber_public_key = std::nullopt);
    OneTimePreKeyRecord(const OneTimePreKeyRecord&) = default;
    OneTimePreKeyRecord(OneTimePreKeyRecord&&) noexcept = default;
    OneTimePreKeyRecord& operator=(const OneTimePreKeyRecord&) = default;
    OneTimePreKeyRecord& operator=(OneTimePreKeyRecord&&) noexcept = default;
    ~OneTimePreKeyRecord() = default;
    [[nodiscard]] uint32_t GetPreKeyId() const noexcept {
        return pre_key_id_;
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
    [[nodiscard]] const std::optional<std::vector<uint8_t>>& GetKyberPublicKey() const noexcept {
        return kyber_public_key_;
    }
private:
    uint32_t pre_key_id_;
    std::vector<uint8_t> public_key_;
    std::optional<std::vector<uint8_t>> kyber_public_key_;
};
} 
