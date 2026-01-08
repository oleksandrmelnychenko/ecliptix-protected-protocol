#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/core/constants.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <cstring>

namespace ecliptix::protocol::crypto {
    using OpenSSL = OpenSSLConstants;

    namespace {
        Result<Unit, EcliptixProtocolFailure> DeriveKeyWithMode(
            std::span<const uint8_t> ikm,
            std::span<uint8_t> output,
            std::span<const uint8_t> salt,
            std::span<const uint8_t> info,
            const int mode) {
            if (output.size() > Hkdf::MAX_OUTPUT_LEN) {
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput(
                        "HKDF output size exceeds maximum allowed: " +
                        std::to_string(output.size()) + " > " + std::to_string(Hkdf::MAX_OUTPUT_LEN)));
            }
            if (ikm.empty()) {
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput("HKDF input key material cannot be empty"));
            }
            try {
                EVP_KDF *const kdf = EVP_KDF_fetch(nullptr, std::string(OpenSSL::ALGORITHM_HKDF).c_str(), nullptr);
                if (!kdf) {
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::DeriveKey("Failed to fetch HKDF algorithm"));
                }
                EVP_KDF_CTX *const kctx = EVP_KDF_CTX_new(kdf);
                EVP_KDF_free(kdf);
                if (!kctx) {
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::DeriveKey("Failed to create HKDF context"));
                }
                OSSL_PARAM params[6];
                int param_idx = ProtocolConstants::ZERO_VALUE;
                char digest_name[7];
                std::memcpy(digest_name, OpenSSL::ALGORITHM_SHA256.data(), 6);
                digest_name[6] = '\0';
                char param_digest[7];
                std::memcpy(param_digest, OpenSSL::PARAM_DIGEST.data(), OpenSSL::PARAM_DIGEST.size());
                param_digest[OpenSSL::PARAM_DIGEST.size()] = '\0';
                char param_key[4];
                std::memcpy(param_key, OpenSSL::PARAM_KEY.data(), OpenSSL::PARAM_KEY.size());
                param_key[OpenSSL::PARAM_KEY.size()] = '\0';
                char param_mode[5];
                std::memcpy(param_mode, OpenSSL::PARAM_MODE.data(), OpenSSL::PARAM_MODE.size());
                param_mode[OpenSSL::PARAM_MODE.size()] = '\0';
                params[param_idx++] = OSSL_PARAM_construct_utf8_string(
                    param_digest, digest_name, ProtocolConstants::ZERO_VALUE);
                std::vector ikm_copy(ikm.begin(), ikm.end());
                params[param_idx++] = OSSL_PARAM_construct_octet_string(
                    param_key, ikm_copy.data(), ikm_copy.size());
                std::vector<uint8_t> salt_copy;
                char param_salt[5];
                if (!salt.empty()) {
                    salt_copy.assign(salt.begin(), salt.end());
                    std::memcpy(param_salt, OpenSSL::PARAM_SALT.data(), OpenSSL::PARAM_SALT.size());
                    param_salt[OpenSSL::PARAM_SALT.size()] = '\0';
                    params[param_idx++] = OSSL_PARAM_construct_octet_string(
                        param_salt, salt_copy.data(), salt_copy.size());
                }
                std::vector<uint8_t> info_copy;
                char param_info[5];
                if (!info.empty()) {
                    info_copy.assign(info.begin(), info.end());
                    std::memcpy(param_info, OpenSSL::PARAM_INFO.data(), OpenSSL::PARAM_INFO.size());
                    param_info[OpenSSL::PARAM_INFO.size()] = '\0';
                    params[param_idx++] = OSSL_PARAM_construct_octet_string(
                        param_info, info_copy.data(), info_copy.size());
                }
                int mode_value = mode;
                params[param_idx++] = OSSL_PARAM_construct_int(param_mode, &mode_value);
                params[param_idx] = OSSL_PARAM_construct_end();
                const int result = EVP_KDF_derive(kctx, output.data(), output.size(), params);
                EVP_KDF_CTX_free(kctx);
                if (result != OpenSSL::SUCCESS) {
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::DeriveKey("HKDF key derivation failed"));
                }
                return Result<Unit, EcliptixProtocolFailure>::Ok(unit);
            } catch (const std::exception &ex) {
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::DeriveKey(
                        "HKDF derivation exception: " + std::string(ex.what())));
            }
        }
    }

    Result<Unit, EcliptixProtocolFailure> Hkdf::DeriveKey(
        const std::span<const uint8_t> ikm,
        const std::span<uint8_t> output,
        const std::span<const uint8_t> salt,
        const std::span<const uint8_t> info) {
        return DeriveKeyWithMode(
            ikm,
            output,
            salt,
            info,
            EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND);
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure> Hkdf::DeriveKeyBytes(
        const std::span<const uint8_t> ikm,
        const size_t output_size,
        const std::span<const uint8_t> salt,
        const std::span<const uint8_t> info) {
        std::vector<uint8_t> output(output_size);
        if (auto result = DeriveKey(ikm, output, salt, info); result.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                std::move(result).UnwrapErr());
        }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(std::move(output));
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure> Hkdf::Extract(
        const std::span<const uint8_t> ikm,
        const std::span<const uint8_t> salt) {
        std::vector<uint8_t> prk(HASH_LEN);
        if (auto result = DeriveKeyWithMode(ikm, prk, salt, {}, EVP_KDF_HKDF_MODE_EXTRACT_ONLY);
            result.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                std::move(result).UnwrapErr());
        }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(std::move(prk));
    }

    Result<Unit, EcliptixProtocolFailure> Hkdf::Expand(
        const std::span<const uint8_t> prk,
        const std::span<uint8_t> output,
        const std::span<const uint8_t> info) {
        if (prk.size() != HASH_LEN) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    "PRK must be exactly " + std::to_string(HASH_LEN) + " bytes"));
        }
        return DeriveKeyWithMode(prk, output, {}, info, EVP_KDF_HKDF_MODE_EXPAND_ONLY);
    }
}
