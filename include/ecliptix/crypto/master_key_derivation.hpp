#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <vector>
#include <string>
#include <string_view>
#include <span>
#include <cstdint>
namespace ecliptix::protocol::crypto {
class MasterKeyDerivation {
public:
    static std::vector<uint8_t> DeriveEd25519Seed(
        std::span<const uint8_t> master_key,
        std::string_view membership_id);
    static std::vector<uint8_t> DeriveX25519Seed(
        std::span<const uint8_t> master_key,
        std::string_view membership_id);
    static std::vector<uint8_t> DeriveSignedPreKeySeed(
        std::span<const uint8_t> master_key,
        std::string_view membership_id);
    static std::vector<uint8_t> DeriveKyberSeed(
        std::span<const uint8_t> master_key,
        std::string_view membership_id);
    static std::vector<uint8_t> DeriveOneTimePreKeySeed(
        std::span<const uint8_t> master_key,
        std::string_view membership_id,
        uint32_t opk_index);
    static constexpr std::string_view ED_25519_CONTEXT = "Ecliptix-Ed25519";
    static constexpr std::string_view X_25519_CONTEXT = "Ecliptix-X25519";
    static constexpr std::string_view SIGNED_PRE_KEY_CONTEXT = "Ecliptix-SignedPreKey";
    static constexpr std::string_view KYBER_CONTEXT = "Ecliptix-Kyber768";
    static constexpr std::string_view KYBER_CONTEXT_PART2_SUFFIX = "-part2";
    static constexpr std::string_view OPK_CONTEXT = "Ecliptix-OneTimePreKey";
private:
    static constexpr int KEY_SIZE = 32;
    static std::vector<uint8_t> HashWithGenericHash(
        std::span<const uint8_t> key,
        std::span<const uint8_t> data,
        size_t output_size);
    static std::vector<uint8_t> BuildContextData(
        std::string_view context,
        std::string_view membership_id);
    MasterKeyDerivation() = delete;
};
}
