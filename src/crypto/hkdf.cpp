#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/core/constants.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <cstring>

namespace ecliptix::protocol::crypto {

Result<Unit, EcliptixProtocolFailure> Hkdf::DeriveKey(
    std::span<const uint8_t> ikm,
    std::span<uint8_t> output,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info) {

    if (output.size() > MAX_OUTPUT_LEN) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                "HKDF output size exceeds maximum allowed: " +
                std::to_string(output.size()) + " > " + std::to_string(MAX_OUTPUT_LEN)));
    }

    if (ikm.empty()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput("HKDF input key material cannot be empty"));
    }

    try {
        EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
        if (!kdf) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::DeriveKey("Failed to fetch HKDF algorithm"));
        }

        EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);

        if (!kctx) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::DeriveKey("Failed to create HKDF context"));
        }

        // Build parameters
        OSSL_PARAM params[5];
        int param_idx = 0;

        // Hash algorithm: SHA-256
        params[param_idx++] = OSSL_PARAM_construct_utf8_string(
            "digest", const_cast<char*>("SHA256"), 0);

        // Input key material
        params[param_idx++] = OSSL_PARAM_construct_octet_string(
            "key", const_cast<uint8_t*>(ikm.data()), ikm.size());

        // Salt (optional)
        if (!salt.empty()) {
            params[param_idx++] = OSSL_PARAM_construct_octet_string(
                "salt", const_cast<uint8_t*>(salt.data()), salt.size());
        }

        // Info (optional)
        if (!info.empty()) {
            params[param_idx++] = OSSL_PARAM_construct_octet_string(
                "info", const_cast<uint8_t*>(info.data()), info.size());
        }

        // End marker
        params[param_idx] = OSSL_PARAM_construct_end();

        // Derive the key
        int result = EVP_KDF_derive(kctx, output.data(), output.size(), params);
        EVP_KDF_CTX_free(kctx);

        if (result != 1) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::DeriveKey("HKDF key derivation failed"));
        }

        return Result<Unit, EcliptixProtocolFailure>::Ok(unit);

    } catch (const std::exception& ex) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::DeriveKey(
                "HKDF derivation exception: " + std::string(ex.what())));
    }
}

Result<std::vector<uint8_t>, EcliptixProtocolFailure> Hkdf::DeriveKeyBytes(
    std::span<const uint8_t> ikm,
    size_t output_size,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info) {

    std::vector<uint8_t> output(output_size);
    auto result = DeriveKey(ikm, output, salt, info);

    if (result.IsErr()) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            std::move(result).UnwrapErr());
    }

    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(std::move(output));
}

Result<std::vector<uint8_t>, EcliptixProtocolFailure> Hkdf::Extract(
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> salt) {

    // HKDF-Extract always produces HASH_LEN bytes
    std::vector<uint8_t> prk(HASH_LEN);

    // Use empty info for extract-only
    auto result = DeriveKey(ikm, prk, salt, {});
    if (result.IsErr()) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            std::move(result).UnwrapErr());
    }

    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(std::move(prk));
}

Result<Unit, EcliptixProtocolFailure> Hkdf::Expand(
    std::span<const uint8_t> prk,
    std::span<uint8_t> output,
    std::span<const uint8_t> info) {

    if (prk.size() != HASH_LEN) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                "PRK must be exactly " + std::to_string(HASH_LEN) + " bytes"));
    }

    // Use PRK as input, no salt for expand phase
    return DeriveKey(prk, output, {}, info);
}

} // namespace ecliptix::protocol::crypto
