#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <vector>
#include <cstdint>
#include <span>
namespace ecliptix::protocol::crypto {
using protocol::Result;
using protocol::EcliptixProtocolFailure;

class AesGcm {
public:
    [[nodiscard]] static Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    Encrypt(
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> associated_data = {});
    [[nodiscard]] static Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    Decrypt(
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> ciphertext_with_tag,
        std::span<const uint8_t> associated_data = {});
private:
    AesGcm() = delete;
};
}
