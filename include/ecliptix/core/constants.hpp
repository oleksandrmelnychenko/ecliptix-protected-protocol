#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>
#include "ecliptix/protocol/constants.hpp"
namespace ecliptix::protocol {
struct Constants {
    static constexpr size_t CURVE_25519_FIELD_ELEMENT_SIZE = 32;
    static constexpr size_t WORD_SIZE = 4;
    static constexpr size_t FIELD_256_WORD_COUNT = 8;
    static constexpr uint32_t FIELD_ELEMENT_MASK = 0x7FFFFFFF;
    static constexpr size_t SMALL_BUFFER_THRESHOLD = 1024;
    static constexpr size_t OPENSSL_ERROR_BUFFER_SIZE = 256;
};
struct OpenSSLConstants {
    static constexpr int SUCCESS = 1;
    static constexpr unsigned long NO_ERROR = 0;
    static constexpr std::string_view ALGORITHM_HKDF = "HKDF";
    static constexpr std::string_view ALGORITHM_SHA256 = "SHA256";
    static constexpr std::string_view PARAM_DIGEST = "digest";
    static constexpr std::string_view PARAM_KEY = "key";
    static constexpr std::string_view PARAM_SALT = "salt";
    static constexpr std::string_view PARAM_INFO = "info";
    static constexpr std::string_view PARAM_MODE = "mode";
    static constexpr std::string_view UNKNOWN_ERROR_MESSAGE = "Unknown OpenSSL error";
};
struct SodiumConstants {
    static constexpr int SUCCESS = 0;
    static constexpr int FAILURE = -1;
    static constexpr uint8_t SECURE_WIPE_PATTERN = 0;
};
struct CryptoHashConstants {
    static constexpr size_t FNV_PRIME = 0x100000001b3;
    static constexpr uint8_t FILL_BYTE = 0xFF;
};
struct ComparisonConstants {
    static constexpr int EQUAL = 0;
    static constexpr double WINDOW_FILL_RATIO_HIGH = 0.75;
    static constexpr double WINDOW_FILL_RATIO_LOW = 0.25;
    static constexpr uint32_t MINIMUM_REQUEST_ID = 1;
    static constexpr uint8_t BIT_SHIFT_BYTE = 8;
    static constexpr uint8_t BYTE_MASK = 0xFF;
};
struct ErrorMessages {
    static constexpr std::string_view SODIUM_INIT_FAILED = "Failed to initialize libsodium";
    static constexpr std::string_view NOT_INITIALIZED = "Libsodium not initialized";
    static constexpr std::string_view BUFFER_NULL = "Buffer is null";
    static constexpr std::string_view BUFFER_TOO_SMALL = "Buffer too small";
    static constexpr std::string_view BUFFER_TOO_LARGE = "Buffer too large";
    static constexpr std::string_view BUFFER_DISPOSED = "Buffer is disposed";
    static constexpr std::string_view HANDLE_DISPOSED = "Handle disposed";
    static constexpr std::string_view CONSTANT_TIME_COMPARISON_FAILED = "Constant-time comparison failed";
    static constexpr std::string_view FAILED_TO_ALLOCATE_SECURE_MEMORY = "Failed to allocate secure memory";
    static constexpr std::string_view FAILED_TO_READ_SECURE_MEMORY = "Failed to read secure memory";
    static constexpr std::string_view DATA_EXCEEDS_BUFFER = "Data size exceeds buffer size";
    static constexpr std::string_view DH_PUBLIC_KEY_NULL = "DH public key is null";
    static constexpr std::string_view NO_CONNECTION = "No connection";
    static constexpr std::string_view REFLECTION_ATTACK = "Potential reflection attack detected - peer echoed our DH key";
    static constexpr std::string_view PARSE_PROTOBUF_FAILED = "Failed to parse peer public key bundle from protobuf";
    static constexpr std::string_view SIGNED_PRE_KEY_FAILED = "Signed pre-key signature verification failed";
    static constexpr std::string_view PROTOCOL_CONNECTION_NOT_INITIALIZED = "Protocol connection not initialized";
    static constexpr std::string_view AES_GCM_ENCRYPTION_FAILED = "AES-GCM encryption failed";
    static constexpr std::string_view AES_GCM_DECRYPTION_FAILED = "AES-GCM decryption failed (authentication tag mismatch)";
    static constexpr std::string_view CIPHERTEXT_TOO_SMALL = "Ciphertext too small";
};
}
