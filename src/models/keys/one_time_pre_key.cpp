#include "ecliptix/models/keys/one_time_pre_key.hpp"
#include <sodium.h>
#include <cstring>

namespace ecliptix::protocol::models {
    Result<OneTimePreKey, ProtocolFailure> OneTimePreKey::Generate(const uint32_t one_time_pre_key_id) {
        auto key_result = crypto::SodiumInterop::GenerateX25519KeyPair("OneTimePreKey");
        if (key_result.IsErr()) {
            return Result<OneTimePreKey, ProtocolFailure>::Err(
                std::move(key_result).UnwrapErr());
        }
        auto [private_key_handle, public_key] = std::move(key_result).Unwrap();
        return Result<OneTimePreKey, ProtocolFailure>::Ok(
            OneTimePreKey(one_time_pre_key_id, std::move(private_key_handle), std::move(public_key)));
    }

    Result<OneTimePreKey, ProtocolFailure> OneTimePreKey::CreateFromSeed(
        const uint32_t one_time_pre_key_id,
        const std::span<const uint8_t> seed) {
        if (seed.size() != crypto_scalarmult_SCALARBYTES) {
            return Result<OneTimePreKey, ProtocolFailure>::Err(
                ProtocolFailure::KeyGeneration("Invalid seed size for OPK derivation"));
        }

        // Create private key from seed (apply X25519 clamping)
        std::vector<uint8_t> private_key(crypto_scalarmult_SCALARBYTES);
        std::memcpy(private_key.data(), seed.data(), crypto_scalarmult_SCALARBYTES);

        // Apply X25519 clamping
        private_key[0] &= 248;
        private_key[31] &= 127;
        private_key[31] |= 64;

        // Derive public key from private key
        std::vector<uint8_t> public_key(crypto_scalarmult_BYTES);
        if (crypto_scalarmult_base(public_key.data(), private_key.data()) != 0) {
            crypto::SodiumInterop::SecureWipe(std::span(private_key));
            return Result<OneTimePreKey, ProtocolFailure>::Err(
                ProtocolFailure::KeyGeneration("Failed to derive OPK public key from seed"));
        }

        // Create secure memory handle for private key
        auto handle_result = crypto::SecureMemoryHandle::Allocate(crypto_scalarmult_SCALARBYTES);
        if (handle_result.IsErr()) {
            crypto::SodiumInterop::SecureWipe(std::span(private_key));
            return Result<OneTimePreKey, ProtocolFailure>::Err(
                ProtocolFailure::KeyGeneration("Failed to allocate secure memory for OPK"));
        }

        auto handle = std::move(handle_result).Unwrap();
        auto write_result = handle.Write(std::span<const uint8_t>(private_key));
        crypto::SodiumInterop::SecureWipe(std::span(private_key));

        if (write_result.IsErr()) {
            return Result<OneTimePreKey, ProtocolFailure>::Err(
                ProtocolFailure::KeyGeneration("Failed to write OPK private key to secure memory"));
        }

        return Result<OneTimePreKey, ProtocolFailure>::Ok(
            OneTimePreKey(one_time_pre_key_id, std::move(handle), std::move(public_key)));
    }

    OneTimePreKey OneTimePreKey::CreateFromParts(
        const uint32_t one_time_pre_key_id,
        crypto::SecureMemoryHandle private_key_handle,
        std::vector<uint8_t> public_key) {
        return {one_time_pre_key_id, std::move(private_key_handle), std::move(public_key)};
    }

    OneTimePreKey::OneTimePreKey(
        const uint32_t one_time_pre_key_id,
        crypto::SecureMemoryHandle private_key_handle,
        std::vector<uint8_t> public_key)
        : one_time_pre_key_id_(one_time_pre_key_id)
          , private_key_handle_(std::move(private_key_handle))
          , public_key_(std::move(public_key)) {
    }
}
