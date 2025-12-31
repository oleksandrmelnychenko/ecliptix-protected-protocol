#include "ecliptix/crypto/master_key_derivation.hpp"
#include <sodium.h>
#include <cstring>

namespace ecliptix::protocol::crypto {
    std::vector<uint8_t> MasterKeyDerivation::DeriveEd25519Seed(
        const std::span<const uint8_t> master_key,
        const std::string_view membership_id) {
        auto context_data = BuildContextData(ED_25519_CONTEXT, membership_id);
        return HashWithGenericHash(master_key, context_data, KEY_SIZE);
    }

    std::vector<uint8_t> MasterKeyDerivation::DeriveX25519Seed(
        const std::span<const uint8_t> master_key,
        const std::string_view membership_id) {
        auto context_data = BuildContextData(X_25519_CONTEXT, membership_id);
        return HashWithGenericHash(master_key, context_data, KEY_SIZE);
    }

    std::vector<uint8_t> MasterKeyDerivation::DeriveSignedPreKeySeed(
        const std::span<const uint8_t> master_key,
        const std::string_view membership_id) {
        auto context_data = BuildContextData(SIGNED_PRE_KEY_CONTEXT, membership_id);
        return HashWithGenericHash(master_key, context_data, KEY_SIZE);
    }

    std::vector<uint8_t> MasterKeyDerivation::HashWithGenericHash(
        const std::span<const uint8_t> key,
        const std::span<const uint8_t> data,
        const size_t output_size) {
        std::vector<uint8_t> output(output_size);
        crypto_generichash(
            output.data(),
            output_size,
            data.data(),
            data.size(),
            key.data(),
            key.size()
        );
        return output;
    }

    std::vector<uint8_t> MasterKeyDerivation::BuildContextData(
        const std::string_view context,
        const std::string_view membership_id) {
        const size_t total_size = sizeof(int32_t) + context.size() + membership_id.size();
        std::vector<uint8_t> result(total_size);
        size_t offset = 0;
        constexpr int32_t version = CURRENT_VERSION;
        std::memcpy(result.data() + offset, &version, sizeof(version));
        offset += sizeof(version);
        std::memcpy(result.data() + offset, context.data(), context.size());
        offset += context.size();
        std::memcpy(result.data() + offset, membership_id.data(), membership_id.size());
        return result;
    }
}
