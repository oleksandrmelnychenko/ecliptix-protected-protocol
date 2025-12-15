#pragma once
#include "ecliptix/models/key_materials/ed25519_key_material.hpp"
#include "ecliptix/models/key_materials/x25519_key_material.hpp"
#include "ecliptix/models/key_materials/signed_pre_key_material.hpp"
#include "ecliptix/models/keys/one_time_pre_key_local.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include <vector>
namespace ecliptix::protocol::models {
struct IdentityKeysMaterial {
    Ed25519KeyMaterial ed25519;
    X25519KeyMaterial identity_x25519;
    SignedPreKeyMaterial signed_pre_key;
    std::vector<OneTimePreKeyLocal> one_time_pre_keys;
    crypto::SecureMemoryHandle kyber_secret_key;
    std::vector<uint8_t> kyber_public_key;
    IdentityKeysMaterial(
        Ed25519KeyMaterial ed25519_key,
        X25519KeyMaterial identity_x25519_key,
        SignedPreKeyMaterial signed_pre_key_material,
        std::vector<OneTimePreKeyLocal> one_time_keys,
        crypto::SecureMemoryHandle kyber_secret,
        std::vector<uint8_t> kyber_public)
        : ed25519(std::move(ed25519_key))
        , identity_x25519(std::move(identity_x25519_key))
        , signed_pre_key(std::move(signed_pre_key_material))
        , one_time_pre_keys(std::move(one_time_keys))
        , kyber_secret_key(std::move(kyber_secret))
        , kyber_public_key(std::move(kyber_public)) {
    }
    IdentityKeysMaterial(IdentityKeysMaterial&&) noexcept = default;
    IdentityKeysMaterial& operator=(IdentityKeysMaterial&&) noexcept = default;
    IdentityKeysMaterial(const IdentityKeysMaterial&) = delete;
    IdentityKeysMaterial& operator=(const IdentityKeysMaterial&) = delete;
};
} 
