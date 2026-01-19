#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/core/format.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>

static_assert(ecliptix::protocol::kAesGcmNonceBytes == 12,
              "GCM nonce must be 12 bytes per NIST SP 800-38D Section 8");
static_assert(ecliptix::protocol::kAesKeyBytes == 32,
              "AES-256-GCM requires 32-byte (256-bit) keys");
static_assert(ecliptix::protocol::kAesGcmTagBytes == 16,
              "GCM authentication tag must be 16 bytes (128 bits)");

namespace ecliptix::protocol::crypto {
    using OpenSSL = OpenSSLConstants;

    namespace {
        struct EVP_CIPHER_CTX_Deleter {
            void operator()(EVP_CIPHER_CTX *ctx) const {
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
            return {buffer};
        }
    }

    Result<std::vector<uint8_t>, ProtocolFailure>
    AesGcm::Encrypt(
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> associated_data) {
        if (key.size() != kAesKeyBytes) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput(
                    ecliptix::compat::format("AES-256-GCM key must be {} bytes, got {}",
                                kAesKeyBytes, key.size())));
        }
        if (nonce.size() != kAesGcmNonceBytes) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput(
                    ecliptix::compat::format("AES-GCM nonce must be {} bytes, got {}",
                                kAesGcmNonceBytes, nonce.size())));
        }
        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Failed to create cipher context: {}", GetOpenSSLError())));
        }
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != OpenSSL::SUCCESS) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Failed to initialize AES-256-GCM: {}", GetOpenSSLError())));
        }
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(nonce.size()), nullptr) != OpenSSL::SUCCESS) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Failed to set nonce length: {}", GetOpenSSLError())));
        }
        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != OpenSSL::SUCCESS) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Failed to set key and nonce: {}", GetOpenSSLError())));
        }
        if (!associated_data.empty()) {
            int outlen = 0;
            if (EVP_EncryptUpdate(ctx.get(), nullptr, &outlen,
                                  associated_data.data(),
                                  static_cast<int>(associated_data.size())) != OpenSSL::SUCCESS) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    ProtocolFailure::Generic(
                        ecliptix::compat::format("Failed to add associated data: {}", GetOpenSSLError())));
            }
        }
        std::vector<uint8_t> output(plaintext.size() + kAesGcmTagBytes);
        int ciphertext_len = 0;
        if (EVP_EncryptUpdate(ctx.get(), output.data(), &ciphertext_len,
                              plaintext.data(),
                              static_cast<int>(plaintext.size())) != OpenSSL::SUCCESS) {
            {
                auto _wipe = SodiumInterop::SecureWipe(std::span(output));
                (void) _wipe;
            }
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Encryption failed: {}", GetOpenSSLError())));
        }
        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx.get(), output.data() + ciphertext_len, &final_len) != OpenSSL::SUCCESS) {
            {
                auto _wipe = SodiumInterop::SecureWipe(std::span(output));
                (void) _wipe;
            }
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Encryption finalization failed: {}", GetOpenSSLError())));
        }
        ciphertext_len += final_len;
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                                kAesGcmTagBytes,
                                output.data() + ciphertext_len) != OpenSSL::SUCCESS) {
            {
                auto _wipe = SodiumInterop::SecureWipe(std::span(output));
                (void) _wipe;
            }
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Failed to get authentication tag: {}", GetOpenSSLError())));
        }
        output.resize(ciphertext_len + kAesGcmTagBytes);
        return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(output));
    }

    Result<std::vector<uint8_t>, ProtocolFailure>
    AesGcm::Decrypt(
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> ciphertext_with_tag,
        std::span<const uint8_t> associated_data) {
        if (key.size() != kAesKeyBytes) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput(
                    ecliptix::compat::format("AES-256-GCM key must be {} bytes, got {}",
                                kAesKeyBytes, key.size())));
        }
        if (nonce.size() != kAesGcmNonceBytes) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput(
                    ecliptix::compat::format("AES-GCM nonce must be {} bytes, got {}",
                                kAesGcmNonceBytes, nonce.size())));
        }
        if (ciphertext_with_tag.size() < kAesGcmTagBytes) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput(
                    ecliptix::compat::format("Ciphertext too small: {} bytes (minimum {} for tag)",
                                ciphertext_with_tag.size(), kAesGcmTagBytes)));
        }
        size_t ciphertext_len = ciphertext_with_tag.size() - kAesGcmTagBytes;
        std::span<const uint8_t> ciphertext = ciphertext_with_tag.subspan(0, ciphertext_len);
        std::span<const uint8_t> tag = ciphertext_with_tag.subspan(ciphertext_len);
        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Failed to create cipher context: {}", GetOpenSSLError())));
        }
        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != OpenSSL::SUCCESS) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Failed to initialize AES-256-GCM: {}", GetOpenSSLError())));
        }
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(nonce.size()), nullptr) != OpenSSL::SUCCESS) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Failed to set nonce length: {}", GetOpenSSLError())));
        }
        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != OpenSSL::SUCCESS) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Failed to set key and nonce: {}", GetOpenSSLError())));
        }
        if (!associated_data.empty()) {
            int outlen = 0;
            if (EVP_DecryptUpdate(ctx.get(), nullptr, &outlen,
                                  associated_data.data(),
                                  static_cast<int>(associated_data.size())) != OpenSSL::SUCCESS) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    ProtocolFailure::Generic(
                        ecliptix::compat::format("Failed to add associated data: {}", GetOpenSSLError())));
            }
        }
        std::vector<uint8_t> output(ciphertext_len);
        int plaintext_len = 0;
        if (EVP_DecryptUpdate(ctx.get(), output.data(), &plaintext_len,
                              ciphertext.data(),
                              static_cast<int>(ciphertext.size())) != OpenSSL::SUCCESS) {
            {
                auto _wipe = SodiumInterop::SecureWipe(std::span(output));
                (void) _wipe;
            }
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Decryption failed: {}", GetOpenSSLError())));
        }
        std::vector tag_copy(tag.begin(), tag.end());
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                                kAesGcmTagBytes,
                                tag_copy.data()) != OpenSSL::SUCCESS) {
            {
                auto _wipe = SodiumInterop::SecureWipe(std::span(output));
                (void) _wipe;
            } {
                auto _wipe2 = SodiumInterop::SecureWipe(std::span(tag_copy));
                (void) _wipe2;
            }
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    ecliptix::compat::format("Failed to set authentication tag: {}", GetOpenSSLError())));
        } {
            auto _wipe = SodiumInterop::SecureWipe(std::span(tag_copy));
            (void) _wipe;
        }
        int final_len = 0;
        if (const int ret = EVP_DecryptFinal_ex(ctx.get(), output.data() + plaintext_len, &final_len);
            ret != OpenSSL::SUCCESS) {
            {
                auto _wipe = SodiumInterop::SecureWipe(std::span(output));
                (void) _wipe;
            }
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    "Authentication tag verification failed - data may have been tampered with"));
        }
        plaintext_len += final_len;
        output.resize(plaintext_len);
        return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(output));
    }
}
