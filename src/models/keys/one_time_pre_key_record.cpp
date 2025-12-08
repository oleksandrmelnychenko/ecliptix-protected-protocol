#include "ecliptix/models/keys/one_time_pre_key_record.hpp"
namespace ecliptix::protocol::models {
OneTimePreKeyRecord::OneTimePreKeyRecord(uint32_t pre_key_id, std::vector<uint8_t> public_key)
    : pre_key_id_(pre_key_id)
    , public_key_(std::move(public_key)) {
}
} 
