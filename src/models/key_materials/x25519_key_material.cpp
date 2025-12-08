#include "ecliptix/models/key_materials/x25519_key_material.hpp"
namespace ecliptix::protocol::models {
X25519KeyMaterial::X25519KeyMaterial(
    crypto::SecureMemoryHandle secret_key_handle,
    std::vector<uint8_t> public_key)
    : secret_key_handle_(std::move(secret_key_handle))
    , public_key_(std::move(public_key)) {
}
} 
