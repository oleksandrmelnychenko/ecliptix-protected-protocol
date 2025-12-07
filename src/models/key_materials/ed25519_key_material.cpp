#include "ecliptix/models/key_materials/ed25519_key_material.hpp"

namespace ecliptix::protocol::models {

Ed25519KeyMaterial::Ed25519KeyMaterial(
    crypto::SecureMemoryHandle secret_key_handle,
    std::vector<uint8_t> public_key)
    : secret_key_handle_(std::move(secret_key_handle))
    , public_key_(std::move(public_key)) {
}

} // namespace ecliptix::protocol::models
