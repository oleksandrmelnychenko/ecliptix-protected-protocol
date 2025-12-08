#include "ecliptix/models/keys/one_time_pre_key_local.hpp"
namespace ecliptix::protocol::models {
Result<OneTimePreKeyLocal, EcliptixProtocolFailure> OneTimePreKeyLocal::Generate(uint32_t pre_key_id) {
    auto key_result = crypto::SodiumInterop::GenerateX25519KeyPair("OneTimePreKey");
    if (key_result.IsErr()) {
        return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>::Err(
            std::move(key_result).UnwrapErr());
    }
    auto [private_key_handle, public_key] = std::move(key_result).Unwrap();
    return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>::Ok(
        OneTimePreKeyLocal(pre_key_id, std::move(private_key_handle), std::move(public_key)));
}
OneTimePreKeyLocal OneTimePreKeyLocal::CreateFromParts(
    uint32_t pre_key_id,
    crypto::SecureMemoryHandle private_key_handle,
    std::vector<uint8_t> public_key) {
    return OneTimePreKeyLocal(pre_key_id, std::move(private_key_handle), std::move(public_key));
}
OneTimePreKeyLocal::OneTimePreKeyLocal(
    uint32_t pre_key_id,
    crypto::SecureMemoryHandle private_key_handle,
    std::vector<uint8_t> public_key)
    : pre_key_id_(pre_key_id)
    , private_key_handle_(std::move(private_key_handle))
    , public_key_(std::move(public_key)) {
}
} 
