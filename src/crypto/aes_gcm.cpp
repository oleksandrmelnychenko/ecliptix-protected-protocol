#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <memory>
namespace ecliptix::protocol::crypto {
using Constants = Constants;
using OpenSSL = OpenSSLConstants;
namespace {
    struct EVP_CIPHER_CTX_Deleter {
        void operator()(EVP_CIPHER_CTX* ctx) const {
            if (ctx) {
                EVP_CIPHER_CTX_free(ctx);
            }
        }
    };
    using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;
    std::string GetOpenSSLError() {
        const unsigned long err = ERR_get_error();
        if (err == OpenSSL::NO_ERROR) {
            return std::string(OpenSSL::UNKNOWN_ERROR_MESSAGE);
        }
        char buffer[Constants::OPENSSL_ERROR_BUFFER_SIZE];
        ERR_error_string_n(err, buffer, sizeof(buffer));
        return std::string(buffer);
    }
}
Result<std::vector<uint8_t>, EcliptixProtocolFailure>
AesGcm::Encrypt(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> associated_data) {
    if (key.size() != Constants::AES_KEY_SIZE) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                std::format("AES-256-GCM key must be {} bytes, got {}",
                    Constants::AES_KEY_SIZE, key.size())));
    }
    if (nonce.size() != Constants::AES_GCM_NONCE_SIZE) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                std::format("AES-GCM nonce must be {} bytes, got {}",
                    Constants::AES_GCM_NONCE_SIZE, nonce.size())));
    }
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Failed to create cipher context: {}", GetOpenSSLError())));
    }
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != OpenSSL::SUCCESS) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Failed to initialize AES-256-GCM: {}", GetOpenSSLError())));
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(nonce.size()), nullptr) != OpenSSL::SUCCESS) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Failed to set nonce length: {}", GetOpenSSLError())));
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != OpenSSL::SUCCESS) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Failed to set key and nonce: {}", GetOpenSSLError())));
    }
    if (!associated_data.empty()) {
        int outlen = ProtocolConstants::ZERO_VALUE;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &outlen,
                             associated_data.data(),
                             static_cast<int>(associated_data.size())) != OpenSSL::SUCCESS) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    std::format("Failed to add associated data: {}", GetOpenSSLError())));
        }
    }
    std::vector<uint8_t> output(plaintext.size() + Constants::AES_GCM_TAG_SIZE);
    int ciphertext_len = ProtocolConstants::ZERO_VALUE;
    if (EVP_EncryptUpdate(ctx.get(), output.data(), &ciphertext_len,
                         plaintext.data(),
                         static_cast<int>(plaintext.size())) != OpenSSL::SUCCESS) {
        { auto __wipe = SodiumInterop::SecureWipe(std::span<uint8_t>(output)); (void)__wipe; }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Encryption failed: {}", GetOpenSSLError())));
    }
    int final_len = ProtocolConstants::ZERO_VALUE;
    if (EVP_EncryptFinal_ex(ctx.get(), output.data() + ciphertext_len, &final_len) != OpenSSL::SUCCESS) {
        { auto __wipe = SodiumInterop::SecureWipe(std::span<uint8_t>(output)); (void)__wipe; }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Encryption finalization failed: {}", GetOpenSSLError())));
    }
    ciphertext_len += final_len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                           Constants::AES_GCM_TAG_SIZE,
                           output.data() + ciphertext_len) != OpenSSL::SUCCESS) {
        { auto __wipe = SodiumInterop::SecureWipe(std::span<uint8_t>(output)); (void)__wipe; }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Failed to get authentication tag: {}", GetOpenSSLError())));
    }
    output.resize(ciphertext_len + Constants::AES_GCM_TAG_SIZE);
    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(std::move(output));
}
Result<std::vector<uint8_t>, EcliptixProtocolFailure>
AesGcm::Decrypt(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> ciphertext_with_tag,
    std::span<const uint8_t> associated_data) {
    if (key.size() != Constants::AES_KEY_SIZE) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                std::format("AES-256-GCM key must be {} bytes, got {}",
                    Constants::AES_KEY_SIZE, key.size())));
    }
    if (nonce.size() != Constants::AES_GCM_NONCE_SIZE) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                std::format("AES-GCM nonce must be {} bytes, got {}",
                    Constants::AES_GCM_NONCE_SIZE, nonce.size())));
    }
    if (ciphertext_with_tag.size() < Constants::AES_GCM_TAG_SIZE) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                std::format("Ciphertext too small: {} bytes (minimum {} for tag)",
                    ciphertext_with_tag.size(), Constants::AES_GCM_TAG_SIZE)));
    }
    size_t ciphertext_len = ciphertext_with_tag.size() - Constants::AES_GCM_TAG_SIZE;
    std::span<const uint8_t> ciphertext = ciphertext_with_tag.subspan(0, ciphertext_len);
    std::span<const uint8_t> tag = ciphertext_with_tag.subspan(ciphertext_len);
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Failed to create cipher context: {}", GetOpenSSLError())));
    }
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != OpenSSL::SUCCESS) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Failed to initialize AES-256-GCM: {}", GetOpenSSLError())));
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(nonce.size()), nullptr) != OpenSSL::SUCCESS) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Failed to set nonce length: {}", GetOpenSSLError())));
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != OpenSSL::SUCCESS) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Failed to set key and nonce: {}", GetOpenSSLError())));
    }
    if (!associated_data.empty()) {
        int outlen = ProtocolConstants::ZERO_VALUE;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &outlen,
                             associated_data.data(),
                             static_cast<int>(associated_data.size())) != OpenSSL::SUCCESS) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    std::format("Failed to add associated data: {}", GetOpenSSLError())));
        }
    }
    std::vector<uint8_t> output(ciphertext_len);
    int plaintext_len = ProtocolConstants::ZERO_VALUE;
    if (EVP_DecryptUpdate(ctx.get(), output.data(), &plaintext_len,
                         ciphertext.data(),
                         static_cast<int>(ciphertext.size())) != OpenSSL::SUCCESS) {
        { auto __wipe = SodiumInterop::SecureWipe(std::span<uint8_t>(output)); (void)__wipe; }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Decryption failed: {}", GetOpenSSLError())));
    }
    std::vector<uint8_t> tag_copy(tag.begin(), tag.end());
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                           Constants::AES_GCM_TAG_SIZE,
                           tag_copy.data()) != OpenSSL::SUCCESS) {
        { auto __wipe = SodiumInterop::SecureWipe(std::span<uint8_t>(output)); (void)__wipe; }
        { auto __wipe2 = SodiumInterop::SecureWipe(std::span<uint8_t>(tag_copy)); (void)__wipe2; }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                std::format("Failed to set authentication tag: {}", GetOpenSSLError())));
    }
    { auto __wipe = SodiumInterop::SecureWipe(std::span<uint8_t>(tag_copy)); (void)__wipe; }
    int final_len = ProtocolConstants::ZERO_VALUE;
    const int ret = EVP_DecryptFinal_ex(ctx.get(), output.data() + plaintext_len, &final_len);
    if (ret != OpenSSL::SUCCESS) {
        { auto __wipe = SodiumInterop::SecureWipe(std::span<uint8_t>(output)); (void)__wipe; }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                "Authentication tag verification failed - data may have been tampered with"));
    }
    plaintext_len += final_len;
    output.resize(plaintext_len);
    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(std::move(output));
}
} 
