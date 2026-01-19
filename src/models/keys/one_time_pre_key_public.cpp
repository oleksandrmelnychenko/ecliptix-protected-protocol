#include "ecliptix/models/keys/one_time_pre_key_public.hpp"

namespace ecliptix::protocol::models {
    OneTimePreKeyPublic::OneTimePreKeyPublic(const uint32_t one_time_pre_key_id, std::vector<uint8_t> public_key,
                                             std::optional<std::vector<uint8_t> > kyber_public)
        : one_time_pre_key_id_(one_time_pre_key_id)
          , public_key_(std::move(public_key))
          , kyber_public_(std::move(kyber_public)) {
    }
}
