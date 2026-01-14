#include "ecliptix/models/keys/one_time_pre_key.hpp"

namespace ecliptix::protocol::models {
    Result<OneTimePreKey, ProtocolFailure> OneTimePreKey::Generate(const uint32_t pre_key_id) {
        auto key_result = crypto::SodiumInterop::GenerateX25519KeyPair("OneTimePreKey");
        if (key_result.IsErr()) {
            return Result<OneTimePreKey, ProtocolFailure>::Err(
                std::move(key_result).UnwrapErr());
        }
        auto [private_key_handle, public_key] = std::move(key_result).Unwrap();
        return Result<OneTimePreKey, ProtocolFailure>::Ok(
            OneTimePreKey(pre_key_id, std::move(private_key_handle), std::move(public_key)));
    }

    OneTimePreKey OneTimePreKey::CreateFromParts(
        const uint32_t pre_key_id,
        crypto::SecureMemoryHandle private_key_handle,
        std::vector<uint8_t> public_key) {
        return {pre_key_id, std::move(private_key_handle), std::move(public_key)};
    }

    OneTimePreKey::OneTimePreKey(
        const uint32_t pre_key_id,
        crypto::SecureMemoryHandle private_key_handle,
        std::vector<uint8_t> public_key)
        : pre_key_id_(pre_key_id)
          , private_key_handle_(std::move(private_key_handle))
          , public_key_(std::move(public_key)) {
    }
}
