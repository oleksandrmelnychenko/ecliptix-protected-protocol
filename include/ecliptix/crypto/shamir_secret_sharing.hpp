#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace ecliptix::protocol::crypto {
class ShamirSecretSharing {
public:
    static constexpr uint8_t MIN_SHARES = 2;
    static constexpr uint8_t MAX_SHARES = 255;
    static constexpr size_t MAX_SECRET_LENGTH = 1024 * 1024;
    static constexpr size_t HEADER_SIZE = 12;
    static constexpr size_t AUTH_TAG_SIZE = 32;
    static constexpr uint8_t FLAG_HAS_AUTH = 0x01;
    static constexpr std::array<uint8_t, 4> MAGIC = {'E', 'S', 'S', '1'};

    static Result<std::vector<std::vector<uint8_t>>, EcliptixProtocolFailure> Split(
        std::span<const uint8_t> secret,
        uint8_t threshold,
        uint8_t share_count,
        std::span<const uint8_t> auth_key = {});

    static Result<std::vector<uint8_t>, EcliptixProtocolFailure> Reconstruct(
        std::span<const std::vector<uint8_t>> shares,
        std::span<const uint8_t> auth_key = {});

    static Result<std::vector<uint8_t>, EcliptixProtocolFailure> ReconstructSerialized(
        std::span<const uint8_t> shares_blob,
        size_t share_length,
        size_t share_count,
        std::span<const uint8_t> auth_key = {});
};
}
