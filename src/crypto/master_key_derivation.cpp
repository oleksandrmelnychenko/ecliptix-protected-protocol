#include "ecliptix/crypto/master_key_derivation.hpp"

#include <sodium.h>
#include <cstring>
#include <algorithm>

namespace ecliptix::protocol::crypto {

std::vector<uint8_t> MasterKeyDerivation::DeriveEd25519Seed(
    std::span<const uint8_t> master_key,
    std::string_view membership_id) {

    auto context_data = BuildContextData(ED_25519_CONTEXT, membership_id);
    return HashWithGenericHash(master_key, context_data, KEY_SIZE);
}

std::vector<uint8_t> MasterKeyDerivation::DeriveX25519Seed(
    std::span<const uint8_t> master_key,
    std::string_view membership_id) {

    auto context_data = BuildContextData(X_25519_CONTEXT, membership_id);
    return HashWithGenericHash(master_key, context_data, KEY_SIZE);
}

std::vector<uint8_t> MasterKeyDerivation::DeriveSignedPreKeySeed(
    std::span<const uint8_t> master_key,
    std::string_view membership_id) {

    auto context_data = BuildContextData(SIGNED_PRE_KEY_CONTEXT, membership_id);
    return HashWithGenericHash(master_key, context_data, KEY_SIZE);
}

std::vector<uint8_t> MasterKeyDerivation::HashWithGenericHash(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data,
    size_t output_size) {

    std::vector<uint8_t> output(output_size);

    // Use libsodium's crypto_generichash (BLAKE2b)
    // This is keyed hashing, providing domain separation
    crypto_generichash(
        output.data(),           // output
        output_size,             // output length
        data.data(),            // input data
        data.size(),            // input length
        key.data(),             // key
        key.size()              // key length
    );

    return output;
}

std::vector<uint8_t> MasterKeyDerivation::BuildContextData(
    std::string_view context,
    std::string_view membership_id) {

    // Calculate total size: version (4 bytes) + context + membership_id
    size_t total_size = sizeof(int32_t) + context.size() + membership_id.size();
    std::vector<uint8_t> result(total_size);

    size_t offset = 0;

    // Write version (little-endian)
    int32_t version = CURRENT_VERSION;
    std::memcpy(result.data() + offset, &version, sizeof(version));
    offset += sizeof(version);

    // Write context string
    std::memcpy(result.data() + offset, context.data(), context.size());
    offset += context.size();

    // Write membership ID
    std::memcpy(result.data() + offset, membership_id.data(), membership_id.size());

    return result;
}

} // namespace ecliptix::protocol::crypto
