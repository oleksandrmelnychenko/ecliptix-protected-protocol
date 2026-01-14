#include "ecliptix/crypto/shamir_secret_sharing.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include <sodium.h>
#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace ecliptix::protocol::crypto {
namespace {
constexpr uint8_t kPoly = 0x1B;
constexpr size_t kAuthKeySize = crypto_auth_hmacsha256_KEYBYTES;

uint32_t ReadU32BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

void WriteU32BE(uint8_t* out, const uint32_t value) {
    out[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    out[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[3] = static_cast<uint8_t>(value & 0xFF);
}

uint8_t Gf256Mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        const uint8_t mask = static_cast<uint8_t>(-(static_cast<int>(b & 1u)));
        p ^= a & mask;
        const uint8_t hi = static_cast<uint8_t>(a & 0x80);
        a <<= 1;
        const uint8_t reduction = static_cast<uint8_t>(-(static_cast<int>(hi >> 7))) & kPoly;
        a ^= reduction;
        b >>= 1;
    }
    return p;
}

uint8_t Gf256Inv(uint8_t a) {
    if (a == 0) {
        return 0;
    }
    const uint8_t a2 = Gf256Mul(a, a);
    const uint8_t a4 = Gf256Mul(a2, a2);
    const uint8_t a8 = Gf256Mul(a4, a4);
    const uint8_t a16 = Gf256Mul(a8, a8);
    const uint8_t a32 = Gf256Mul(a16, a16);
    const uint8_t a64 = Gf256Mul(a32, a32);
    const uint8_t a128 = Gf256Mul(a64, a64);

    uint8_t result = Gf256Mul(a128, a64);
    result = Gf256Mul(result, a32);
    result = Gf256Mul(result, a16);
    result = Gf256Mul(result, a8);
    result = Gf256Mul(result, a4);
    result = Gf256Mul(result, a2);
    return result;
}

uint8_t EvaluatePolynomial(std::span<const uint8_t> coeffs, const uint8_t x) {
    uint8_t result = 0;
    uint8_t x_power = 1;
    for (const uint8_t coeff : coeffs) {
        result ^= Gf256Mul(coeff, x_power);
        x_power = Gf256Mul(x_power, x);
    }
    return result;
}

struct ParsedShare {
    uint8_t threshold;
    uint8_t share_count;
    uint8_t index;
    bool has_auth;
    uint32_t secret_length;
    std::span<const uint8_t> share_data;
    std::span<const uint8_t> auth_tag;
    std::span<const uint8_t> auth_input;
};

Result<Unit, ProtocolFailure> ValidateAuthKey(std::span<const uint8_t> auth_key) {
    if (auth_key.empty()) {
        return Result<Unit, ProtocolFailure>::Ok(unit);
    }
    if (auth_key.size() != kAuthKeySize) {
        return Result<Unit, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput(
                "Auth key must be 32 bytes for HMAC-SHA256"));
    }
    return Result<Unit, ProtocolFailure>::Ok(unit);
}

Result<ParsedShare, ProtocolFailure> ParseShare(
    std::span<const uint8_t> share,
    std::span<const uint8_t> auth_key) {
    if (share.size() < ShamirSecretSharing::HEADER_SIZE) {
        return Result<ParsedShare, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Share is too small for header"));
    }

    if (!std::equal(
            ShamirSecretSharing::MAGIC.begin(),
            ShamirSecretSharing::MAGIC.end(),
            share.begin())) {
        return Result<ParsedShare, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Share magic mismatch"));
    }

    ParsedShare parsed{
        .threshold = share[4],
        .share_count = share[5],
        .index = share[6],
        .has_auth = (share[7] & ShamirSecretSharing::FLAG_HAS_AUTH) != 0,
        .secret_length = ReadU32BE(share.data() + 8),
        .share_data = {},
        .auth_tag = {},
        .auth_input = {}
    };

    if (parsed.threshold < ShamirSecretSharing::MIN_SHARES) {
        return Result<ParsedShare, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Share threshold is invalid"));
    }

    if (parsed.share_count < ShamirSecretSharing::MIN_SHARES ||
        parsed.share_count > ShamirSecretSharing::MAX_SHARES) {
        return Result<ParsedShare, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Share count is invalid"));
    }

    if (parsed.index == 0 || parsed.index > parsed.share_count) {
        return Result<ParsedShare, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Share index is invalid"));
    }

    if (parsed.secret_length == 0 || parsed.secret_length > ShamirSecretSharing::MAX_SECRET_LENGTH) {
        return Result<ParsedShare, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Secret length is invalid"));
    }

    const size_t expected_length = ShamirSecretSharing::HEADER_SIZE +
                                   parsed.secret_length +
                                   (parsed.has_auth ? ShamirSecretSharing::AUTH_TAG_SIZE : 0);
    if (share.size() != expected_length) {
        return Result<ParsedShare, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Share length does not match header"));
    }

    if (parsed.has_auth && auth_key.empty()) {
        return Result<ParsedShare, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Auth key required for authenticated shares"));
    }

    if (!parsed.has_auth && !auth_key.empty()) {
        return Result<ParsedShare, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Auth key provided for unauthenticated shares"));
    }

    parsed.share_data = share.subspan(ShamirSecretSharing::HEADER_SIZE, parsed.secret_length);
    parsed.auth_input = share.subspan(0, ShamirSecretSharing::HEADER_SIZE + parsed.secret_length);

    if (parsed.has_auth) {
        parsed.auth_tag = share.subspan(
            ShamirSecretSharing::HEADER_SIZE + parsed.secret_length,
            ShamirSecretSharing::AUTH_TAG_SIZE);

        std::array<uint8_t, ShamirSecretSharing::AUTH_TAG_SIZE> expected{};
        crypto_auth_hmacsha256(
            expected.data(),
            parsed.auth_input.data(),
            parsed.auth_input.size(),
            auth_key.data());

        auto cmp_result = SodiumInterop::ConstantTimeEquals(
            expected,
            parsed.auth_tag);
        if (cmp_result.IsErr() || !cmp_result.Unwrap()) {
            return Result<ParsedShare, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Share authentication failed"));
        }
    }

    return Result<ParsedShare, ProtocolFailure>::Ok(parsed);
}

Result<std::vector<uint8_t>, ProtocolFailure> ReconstructFromShares(
    const std::vector<std::span<const uint8_t>>& shares,
    std::span<const uint8_t> auth_key) {
    if (shares.size() < ShamirSecretSharing::MIN_SHARES) {
        return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Insufficient shares for reconstruction"));
    }

    auto auth_key_result = ValidateAuthKey(auth_key);
    if (auth_key_result.IsErr()) {
        return Result<std::vector<uint8_t>, ProtocolFailure>::Err(auth_key_result.UnwrapErr());
    }

    std::vector<ParsedShare> parsed_shares;
    parsed_shares.reserve(shares.size());

    for (const auto& share : shares) {
        auto parsed_result = ParseShare(share, auth_key);
        if (parsed_result.IsErr()) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                parsed_result.UnwrapErr());
        }
        parsed_shares.push_back(parsed_result.Unwrap());
    }

    const uint8_t threshold = parsed_shares.front().threshold;
    if (shares.size() < threshold) {
        return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Not enough shares for threshold"));
    }

    const uint32_t secret_length = parsed_shares.front().secret_length;
    const uint8_t share_count = parsed_shares.front().share_count;
    const bool has_auth = parsed_shares.front().has_auth;

    std::array<bool, 256> seen_indices{};
    for (const auto& share : parsed_shares) {
        if (share.threshold != threshold ||
            share.share_count != share_count ||
            share.secret_length != secret_length ||
            share.has_auth != has_auth) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Share metadata mismatch"));
        }
        if (seen_indices[share.index]) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Duplicate share index"));
        }
        seen_indices[share.index] = true;
    }

    std::vector<uint8_t> x_values;
    x_values.reserve(parsed_shares.size());
    for (const auto& share : parsed_shares) {
        x_values.push_back(share.index);
    }

    std::vector<uint8_t> lagrange_coeffs(parsed_shares.size(), 0);
    for (size_t i = 0; i < parsed_shares.size(); ++i) {
        uint8_t numerator = 1;
        uint8_t denominator = 1;
        for (size_t j = 0; j < parsed_shares.size(); ++j) {
            if (i == j) {
                continue;
            }
            numerator = Gf256Mul(numerator, x_values[j]);
            denominator = Gf256Mul(denominator, static_cast<uint8_t>(x_values[j] ^ x_values[i]));
        }
        if (denominator == 0) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Share indices are invalid"));
        }
        lagrange_coeffs[i] = Gf256Mul(numerator, Gf256Inv(denominator));
    }

    std::vector<uint8_t> secret(secret_length);
    for (uint32_t byte_index = 0; byte_index < secret_length; ++byte_index) {
        uint8_t value = 0;
        for (size_t i = 0; i < parsed_shares.size(); ++i) {
            const uint8_t y = parsed_shares[i].share_data[byte_index];
            value ^= Gf256Mul(lagrange_coeffs[i], y);
        }
        secret[byte_index] = value;
    }

    return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(secret));
}
} 

Result<std::vector<std::vector<uint8_t>>, ProtocolFailure> ShamirSecretSharing::Split(
    std::span<const uint8_t> secret,
    const uint8_t threshold,
    const uint8_t share_count,
    std::span<const uint8_t> auth_key) {
    if (secret.empty()) {
        return Result<std::vector<std::vector<uint8_t>>, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Secret must not be empty"));
    }

    if (secret.size() > MAX_SECRET_LENGTH) {
        return Result<std::vector<std::vector<uint8_t>>, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Secret exceeds maximum length"));
    }

    if (threshold < MIN_SHARES || threshold > share_count) {
        return Result<std::vector<std::vector<uint8_t>>, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Threshold is invalid"));
    }

    if (share_count < MIN_SHARES || share_count > MAX_SHARES) {
        return Result<std::vector<std::vector<uint8_t>>, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Share count is invalid"));
    }

    auto auth_key_result = ValidateAuthKey(auth_key);
    if (auth_key_result.IsErr()) {
        return Result<std::vector<std::vector<uint8_t>>, ProtocolFailure>::Err(
            auth_key_result.UnwrapErr());
    }

    if (SodiumInterop::Initialize().IsErr()) {
        return Result<std::vector<std::vector<uint8_t>>, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Failed to initialize libsodium"));
    }

    const bool has_auth = !auth_key.empty();
    const size_t share_length = HEADER_SIZE + secret.size() + (has_auth ? AUTH_TAG_SIZE : 0);
    std::vector<std::vector<uint8_t>> shares;
    shares.resize(share_count);

    for (size_t i = 0; i < share_count; ++i) {
        shares[i].assign(share_length, 0);
        auto& share = shares[i];
        std::copy(MAGIC.begin(), MAGIC.end(), share.begin());
        share[4] = threshold;
        share[5] = static_cast<uint8_t>(share_count);
        share[6] = static_cast<uint8_t>(i + 1);
        share[7] = has_auth ? FLAG_HAS_AUTH : 0;
        WriteU32BE(share.data() + 8, static_cast<uint32_t>(secret.size()));
    }

    std::vector<uint8_t> coeffs(threshold);
    for (size_t byte_index = 0; byte_index < secret.size(); ++byte_index) {
        coeffs[0] = secret[byte_index];
        randombytes_buf(coeffs.data() + 1, coeffs.size() - 1);

        for (size_t share_index = 0; share_index < share_count; ++share_index) {
            const uint8_t x = static_cast<uint8_t>(share_index + 1);
            const uint8_t y = EvaluatePolynomial(coeffs, x);
            shares[share_index][HEADER_SIZE + byte_index] = y;
        }
    }

    if (has_auth) {
        for (auto& share : shares) {
            const size_t tag_offset = HEADER_SIZE + secret.size();
            crypto_auth_hmacsha256(
                share.data() + tag_offset,
                share.data(),
                tag_offset,
                auth_key.data());
        }
    }

    return Result<std::vector<std::vector<uint8_t>>, ProtocolFailure>::Ok(std::move(shares));
}

Result<std::vector<uint8_t>, ProtocolFailure> ShamirSecretSharing::Reconstruct(
    std::span<const std::vector<uint8_t>> shares,
    std::span<const uint8_t> auth_key) {
    if (shares.empty()) {
        return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("No shares provided"));
    }

    if (SodiumInterop::Initialize().IsErr()) {
        return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Failed to initialize libsodium"));
    }

    std::vector<std::span<const uint8_t>> share_spans;
    share_spans.reserve(shares.size());
    for (const auto& share : shares) {
        share_spans.emplace_back(share.data(), share.size());
    }

    return ReconstructFromShares(share_spans, auth_key);
}

Result<std::vector<uint8_t>, ProtocolFailure> ShamirSecretSharing::ReconstructSerialized(
    std::span<const uint8_t> shares_blob,
    const size_t share_length,
    const size_t share_count,
    std::span<const uint8_t> auth_key) {
    if (share_length == 0 || share_count == 0) {
        return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Share length or count is invalid"));
    }

    if (shares_blob.size() != share_length * share_count) {
        return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
            ProtocolFailure::InvalidInput("Share buffer length mismatch"));
    }

    if (SodiumInterop::Initialize().IsErr()) {
        return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Failed to initialize libsodium"));
    }

    std::vector<std::span<const uint8_t>> share_spans;
    share_spans.reserve(share_count);
    for (size_t i = 0; i < share_count; ++i) {
        share_spans.emplace_back(
            shares_blob.data() + (i * share_length),
            share_length);
    }

    return ReconstructFromShares(share_spans, auth_key);
}
} 
