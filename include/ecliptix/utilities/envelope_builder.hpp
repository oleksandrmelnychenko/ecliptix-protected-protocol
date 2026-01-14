#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <vector>
#include <cstdint>
#include <string>
#include <span>
namespace ecliptix::proto::common {
    class EnvelopeMetadata;
    enum EnvelopeType : int;
}
namespace ecliptix::protocol::utilities {
using protocol::Result;
using protocol::ProtocolFailure;
class EnvelopeBuilder {
public:
    [[nodiscard]] static proto::common::EnvelopeMetadata
    CreateEnvelopeMetadata(
        uint32_t request_id,
        const std::vector<uint8_t>& nonce,
        uint32_t ratchet_index,
        const std::vector<uint8_t>& channel_key_id = {},
        proto::common::EnvelopeType envelope_type =
            static_cast<proto::common::EnvelopeType>(0),
        const std::string& correlation_id = "");
    [[nodiscard]] static Result<std::vector<uint8_t>, ProtocolFailure>
    EncryptMetadata(
        const proto::common::EnvelopeMetadata& metadata,
        std::span<const uint8_t> header_encryption_key,
        std::span<const uint8_t> header_nonce,
        std::span<const uint8_t> associated_data);
    [[nodiscard]] static Result<proto::common::EnvelopeMetadata, ProtocolFailure>
    DecryptMetadata(
        std::span<const uint8_t> encrypted_metadata,
        std::span<const uint8_t> header_encryption_key,
        std::span<const uint8_t> header_nonce,
        std::span<const uint8_t> associated_data);
private:
    [[nodiscard]] static std::vector<uint8_t> GenerateChannelKeyId();
    EnvelopeBuilder() = delete;
};
} 
