#include "ecliptix/models/key_materials/ed25519_key_pair.hpp"

namespace ecliptix::protocol::models {
    Ed25519KeyPair::Ed25519KeyPair(
        crypto::SecureMemoryHandle secret_key_handle,
        std::vector<uint8_t> public_key)
        : secret_key_handle_(std::move(secret_key_handle))
          , public_key_(std::move(public_key)) {
    }
}
