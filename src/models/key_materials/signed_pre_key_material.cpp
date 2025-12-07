#include "ecliptix/models/key_materials/signed_pre_key_material.hpp"

namespace ecliptix::protocol::models {

SignedPreKeyMaterial::SignedPreKeyMaterial(
    uint32_t id,
    crypto::SecureMemoryHandle secret_key_handle,
    std::vector<uint8_t> public_key,
    std::vector<uint8_t> signature)
    : id_(id)
    , secret_key_handle_(std::move(secret_key_handle))
    , public_key_(std::move(public_key))
    , signature_(std::move(signature)) {
}

} // namespace ecliptix::protocol::models
