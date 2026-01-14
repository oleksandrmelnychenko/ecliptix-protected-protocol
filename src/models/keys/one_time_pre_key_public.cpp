#include "ecliptix/models/keys/one_time_pre_key_public.hpp"

namespace ecliptix::protocol::models {
    OneTimePreKeyPublic::OneTimePreKeyPublic(const uint32_t pre_key_id, std::vector<uint8_t> public_key,
                                             std::optional<std::vector<uint8_t> > kyber_public_key)
        : pre_key_id_(pre_key_id)
          , public_key_(std::move(public_key))
          , kyber_public_key_(std::move(kyber_public_key)) {
    }
}
