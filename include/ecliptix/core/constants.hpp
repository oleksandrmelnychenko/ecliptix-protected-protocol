#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <chrono>
namespace ecliptix::protocol {
struct Constants {
    static constexpr size_t ED_25519_PUBLIC_KEY_SIZE = 32;
    static constexpr size_t ED_25519_SECRET_KEY_SIZE = 64;
    static constexpr size_t ED_25519_SIGNATURE_SIZE = 64;
    static constexpr size_t X_25519_PUBLIC_KEY_SIZE = 32;
    static constexpr size_t X_25519_PRIVATE_KEY_SIZE = 32;
    static constexpr size_t X_25519_KEY_SIZE = 32;
    static constexpr size_t CURVE_25519_FIELD_ELEMENT_SIZE = 32;
    static constexpr size_t WORD_SIZE = 4;
    static constexpr size_t FIELD_256_WORD_COUNT = 8;
    static constexpr uint32_t FIELD_ELEMENT_MASK = 0x7FFFFFFF;
    static constexpr size_t AES_KEY_SIZE = 32;  
    static constexpr size_t AES_GCM_NONCE_SIZE = 12;
    static constexpr size_t AES_GCM_TAG_SIZE = 16;
    static constexpr std::string_view X3DH_INFO = "Ecliptix-X3DH-v1";
    static constexpr std::string_view MSG_INFO = "Ecliptix-Msg";
    static constexpr std::string_view CHAIN_INFO = "Ecliptix-Chain";
    static constexpr size_t SMALL_BUFFER_THRESHOLD = 1024;
    static constexpr uint32_t U_INT_32_LITTLE_ENDIAN_OFFSET = 8;
    static constexpr size_t CHANNEL_KEY_ID_SIZE = 16;
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
struct ProtocolConstants {
    static constexpr std::chrono::hours SESSION_TIMEOUT{24};
    static constexpr std::chrono::minutes NONCE_LIFETIME{5};
    static constexpr std::chrono::minutes CLEANUP_INTERVAL{1};
    static constexpr std::chrono::minutes WINDOW_ADJUSTMENT_INTERVAL{2};
    static constexpr std::chrono::hours DEFAULT_MAX_CHAIN_AGE{1};
    static constexpr int64_t INITIAL_NONCE_COUNTER = 0;
    static constexpr uint64_t MAX_NONCE_COUNTER = 4'294'967'295ULL;
    static constexpr int RANDOM_NONCE_PREFIX_SIZE = 8;
    static constexpr uint32_t DEFAULT_CHAIN_INDEX = 0;
    static constexpr int HKDF_OUTPUT_BUFFER_MULTIPLIER = 2;
    static constexpr int EMPTY_ARRAY_LENGTH = 0;
    static constexpr int MAX_IDENTITY_KEY_LENGTH = 1024;
    static constexpr int MAX_ASSOCIATED_DATA_LENGTH = MAX_IDENTITY_KEY_LENGTH * 2;
    static constexpr int MAX_PAYLOAD_SIZE = 10 * 1024 * 1024;
    static constexpr int BUFFER_COPY_START_OFFSET = 0;
    static constexpr int CIPHER_LENGTH_MINIMUM_THRESHOLD = 0;
    static constexpr uint32_t DEFAULT_CACHE_WINDOW_SIZE = 1000;
    static constexpr uint32_t INITIAL_INDEX = 0;
    static constexpr uint32_t INDEX_INCREMENT = 1;
    static constexpr uint32_t RESET_INDEX = 0;
    static constexpr uint32_t MIN_INDEX_TO_KEEP_OFFSET = 1;
    static constexpr uint32_t CLEANUP_THRESHOLD = 100;
    static constexpr uint32_t INDEX_OVERFLOW_BUFFER = 10000;
    static constexpr int DEFAULT_BUFFER_SIZE = 4096;
    static constexpr int MAX_POOL_SIZE = 100;
    static constexpr int SECURE_WIPE_CHUNK_SIZE = 1024;
    static constexpr int DLL_IMPORT_SUCCESS = 0;
    static constexpr int ZERO_VALUE = 0;
    static constexpr std::string_view X3DH_INFO = "Ecliptix-X3DH-v1";
    static constexpr std::string_view MSG_INFO = "Ecliptix-Msg";
    static constexpr std::string_view CHAIN_INFO = "Ecliptix-Chain";
    static constexpr std::string_view DH_RATCHET_INFO = "Ecliptix-DH-Ratchet";
    static constexpr std::string_view HYBRID_DH_RATCHET_INFO = "Ecliptix-Hybrid-DH-Ratchet";  // Post-quantum hybrid ratchet (X25519 + Kyber-768)
    static constexpr std::string_view INITIAL_SENDER_CHAIN_INFO = "Ecliptix-Initial-Sender";
    static constexpr std::string_view INITIAL_RECEIVER_CHAIN_INFO = "Ecliptix-Initial-Receiver";
    static constexpr std::string_view METADATA_ENCRYPTION_INFO = "ecliptix-metadata-v1";
    static constexpr std::string_view STATE_MAC_INFO = "ecliptix-state-mac-v1";
    static constexpr uint32_t DEFAULT_MESSAGE_COUNT_BEFORE_RATCHET = 100;
    static constexpr uint32_t HIGH_SECURITY_MESSAGE_COUNT_BEFORE_RATCHET = 50;
    static constexpr uint32_t HIGH_PERFORMANCE_MESSAGE_COUNT_BEFORE_RATCHET = 500;
    static constexpr uint32_t MAX_SKIP_MESSAGE_KEYS = 1000;
    static constexpr uint32_t MESSAGE_KEY_CACHE_WINDOW = 2000;
    static constexpr size_t MAX_REPLAY_TRACKED_NONCES = 20000;
    static constexpr size_t MAX_REPLAY_CHAINS = 1024;
    static constexpr uint32_t MAX_CHAIN_LENGTH = 10000;
    static constexpr uint32_t NONCE_RATE_LIMIT_PER_SECOND = 1000;
    static constexpr uint32_t MAX_DH_RATCHETS_PER_MINUTE = 10;
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
