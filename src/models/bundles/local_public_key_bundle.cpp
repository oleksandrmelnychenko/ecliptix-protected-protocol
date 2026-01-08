#include "ecliptix/models/bundles/local_public_key_bundle.hpp"

namespace ecliptix::protocol::models {
    LocalPublicKeyBundle::LocalPublicKeyBundle(
        std::vector<uint8_t> ed25519_public,
        std::vector<uint8_t> identity_x25519_public,
        const uint32_t signed_pre_key_id,
        std::vector<uint8_t> signed_pre_key_public,
        std::vector<uint8_t> signed_pre_key_signature,
        std::vector<OneTimePreKeyRecord> one_time_pre_keys,
        std::optional<std::vector<uint8_t> > ephemeral_x25519_public,
        std::optional<std::vector<uint8_t> > kyber_public_key,
        std::optional<std::vector<uint8_t> > kyber_ciphertext,
        const std::optional<uint32_t> used_opk_id)
        : ed25519_public_(std::move(ed25519_public))
          , identity_x25519_(std::move(identity_x25519_public))
          , signed_pre_key_id_(signed_pre_key_id)
          , signed_pre_key_public_(std::move(signed_pre_key_public))
          , signed_pre_key_signature_(std::move(signed_pre_key_signature))
          , one_time_pre_keys_(std::move(one_time_pre_keys))
          , ephemeral_x25519_public_(std::move(ephemeral_x25519_public))
          , kyber_public_key_(std::move(kyber_public_key))
          , kyber_ciphertext_(std::move(kyber_ciphertext))
          , used_opk_id_(used_opk_id) {
    }
}
