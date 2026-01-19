#pragma once
#include "ecliptix/models/key_materials/ed25519_key_pair.hpp"
#include "ecliptix/models/key_materials/x25519_key_pair.hpp"
#include "ecliptix/models/key_materials/signed_pre_key_pair.hpp"
#include "ecliptix/models/keys/one_time_pre_key.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include <vector>
namespace ecliptix::protocol::models {
struct IdentityKeyBundle {
    Ed25519KeyPair ed25519;
    X25519KeyPair identity_x25519;
    SignedPreKeyPair signed_pre_key;
    std::vector<OneTimePreKey> one_time_pre_keys;
    crypto::SecureMemoryHandle kyber_secret_key;
    std::vector<uint8_t> kyber_public;
    IdentityKeyBundle(
        Ed25519KeyPair ed25519_key,
        X25519KeyPair identity_x25519_key,
        SignedPreKeyPair signed_pre_key_material,
        std::vector<OneTimePreKey> one_time_keys,
        crypto::SecureMemoryHandle kyber_secret,
        std::vector<uint8_t> kyber_public)
        : ed25519(std::move(ed25519_key))
        , identity_x25519(std::move(identity_x25519_key))
        , signed_pre_key(std::move(signed_pre_key_material))
        , one_time_pre_keys(std::move(one_time_keys))
        , kyber_secret_key(std::move(kyber_secret))
        , kyber_public(std::move(kyber_public)) {
    }
    IdentityKeyBundle(IdentityKeyBundle&&) noexcept = default;
    IdentityKeyBundle& operator=(IdentityKeyBundle&&) noexcept = default;
    IdentityKeyBundle(const IdentityKeyBundle&) = delete;
    IdentityKeyBundle& operator=(const IdentityKeyBundle&) = delete;
};
}
