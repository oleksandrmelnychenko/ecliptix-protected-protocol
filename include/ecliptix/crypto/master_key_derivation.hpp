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
    static constexpr std::string_view ED_25519_CONTEXT = "ecliptix-ed25519-v1";
    static constexpr std::string_view X_25519_CONTEXT = "ecliptix-x25519-v1";
    static constexpr std::string_view SIGNED_PRE_KEY_CONTEXT = "ecliptix-spk-v1";
private:
    static constexpr int KEY_SIZE = 32;
    static constexpr int CURRENT_VERSION = 1;
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
