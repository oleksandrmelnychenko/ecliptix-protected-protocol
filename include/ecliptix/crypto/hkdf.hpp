#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <span>
#include <vector>
#include <cstdint>
#include <optional>
namespace ecliptix::protocol::crypto {
class Hkdf {
public:
    static Result<Unit, ProtocolFailure> DeriveKey(
        std::span<const uint8_t> ikm,
        std::span<uint8_t> output,
        std::span<const uint8_t> salt = {},
        std::span<const uint8_t> info = {});
    static Result<std::vector<uint8_t>, ProtocolFailure> DeriveKeyBytes(
        std::span<const uint8_t> ikm,
        size_t output_size,
        std::span<const uint8_t> salt = {},
        std::span<const uint8_t> info = {});
    static Result<std::vector<uint8_t>, ProtocolFailure> Extract(
        std::span<const uint8_t> ikm,
        std::span<const uint8_t> salt = {});
    static Result<Unit, ProtocolFailure> Expand(
        std::span<const uint8_t> prk,
        std::span<uint8_t> output,
        std::span<const uint8_t> info = {});
    static constexpr size_t HASH_LEN = 32;
    static constexpr size_t MAX_OUTPUT_LEN = 255 * HASH_LEN;
private:
    Hkdf() = delete;
};
} 
