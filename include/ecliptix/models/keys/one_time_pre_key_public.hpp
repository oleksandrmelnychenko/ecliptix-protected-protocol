#pragma once
#include <vector>
#include <cstdint>
#include <optional>
#include <span>
namespace ecliptix::protocol::models {
class OneTimePreKeyPublic {
public:
    OneTimePreKeyPublic(uint32_t one_time_pre_key_id, std::vector<uint8_t> public_key,
        std::optional<std::vector<uint8_t>> kyber_public = std::nullopt);
    OneTimePreKeyPublic(const OneTimePreKeyPublic&) = default;
    OneTimePreKeyPublic(OneTimePreKeyPublic&&) noexcept = default;
    OneTimePreKeyPublic& operator=(const OneTimePreKeyPublic&) = default;
    OneTimePreKeyPublic& operator=(OneTimePreKeyPublic&&) noexcept = default;
    ~OneTimePreKeyPublic() = default;
    [[nodiscard]] uint32_t GetOneTimePreKeyId() const noexcept {
        return one_time_pre_key_id_;
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
    [[nodiscard]] const std::optional<std::vector<uint8_t>>& GetKyberPublic() const noexcept {
        return kyber_public_;
    }
private:
    uint32_t one_time_pre_key_id_;
    std::vector<uint8_t> public_key_;
    std::optional<std::vector<uint8_t>> kyber_public_;
};
}
