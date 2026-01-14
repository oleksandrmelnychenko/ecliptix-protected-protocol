#pragma once

#include <cstdint>

namespace ecliptix::protocol::configuration {

enum class SecurityLevel : uint8_t {
    Classical = 0,
    PostQuantum = 1,
    Puncturable = 2,
    ZeroKnowledge = 3
};

class ProtocolConfig {
public:
    [[nodiscard]] static constexpr ProtocolConfig ClassicalOnly() noexcept {
        return ProtocolConfig(SecurityLevel::Classical);
    }

    [[nodiscard]] static constexpr ProtocolConfig PostQuantumOnly() noexcept {
        return ProtocolConfig(SecurityLevel::PostQuantum);
    }

    [[nodiscard]] static constexpr ProtocolConfig PuncturableOnly() noexcept {
        return ProtocolConfig(SecurityLevel::Puncturable);
    }

    [[nodiscard]] static constexpr ProtocolConfig MaximumSecurity() noexcept {
        return ProtocolConfig(SecurityLevel::ZeroKnowledge);
    }

    [[nodiscard]] static constexpr ProtocolConfig Default() noexcept {
        return ClassicalOnly();
    }

    [[nodiscard]] constexpr bool IsPqEnabled() const noexcept {
        return level_ >= SecurityLevel::PostQuantum;
    }

    [[nodiscard]] constexpr bool IsPuncturableEnabled() const noexcept {
        return level_ >= SecurityLevel::Puncturable;
    }

    [[nodiscard]] constexpr bool IsZkEnabled() const noexcept {
        return level_ >= SecurityLevel::ZeroKnowledge;
    }

    [[nodiscard]] constexpr SecurityLevel GetSecurityLevel() const noexcept {
        return level_;
    }

    [[nodiscard]] constexpr uint32_t EstimateHandshakeOverheadUs() const noexcept {
        switch (level_) {
            case SecurityLevel::Classical:
                return 0;
            case SecurityLevel::PostQuantum:
                return 140;
            case SecurityLevel::Puncturable:
            case SecurityLevel::ZeroKnowledge:
                return 200;
        }
        return 0;
    }

    [[nodiscard]] constexpr uint32_t EstimateMessageOverheadUs() const noexcept {
        switch (level_) {
            case SecurityLevel::Classical:
                return 0;
            case SecurityLevel::PostQuantum:
                return 10;
            case SecurityLevel::Puncturable:
                return 70;
            case SecurityLevel::ZeroKnowledge:
                return 150'070;
        }
        return 0;
    }

    [[nodiscard]] constexpr uint32_t EstimateMemoryOverheadBytes() const noexcept {
        switch (level_) {
            case SecurityLevel::Classical:
                return 0;
            case SecurityLevel::PostQuantum:
                return 2400;
            case SecurityLevel::Puncturable:
                return 6400;
            case SecurityLevel::ZeroKnowledge:
                return 10'400;
        }
        return 0;
    }

    [[nodiscard]] constexpr bool operator==(const ProtocolConfig& other) const noexcept {
        return level_ == other.level_;
    }

    [[nodiscard]] constexpr bool operator!=(const ProtocolConfig& other) const noexcept {
        return level_ != other.level_;
    }

    [[nodiscard]] constexpr bool operator>(const ProtocolConfig& other) const noexcept {
        return level_ > other.level_;
    }

    [[nodiscard]] constexpr bool operator<(const ProtocolConfig& other) const noexcept {
        return level_ < other.level_;
    }

private:
    explicit constexpr ProtocolConfig(const SecurityLevel level) noexcept
        : level_(level) {}

    SecurityLevel level_;
};

}
