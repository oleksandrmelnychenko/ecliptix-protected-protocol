#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server;
#else
namespace Ecliptix.Protocol.Client;
#endif

internal static class ProtocolSystemConstants
{
    public static class Timeouts
    {
        public static readonly TimeSpan SessionTimeout = TimeSpan.FromHours(24);
        public static readonly TimeSpan NonceLifetime = TimeSpan.FromMinutes(5);
        public static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(1);
        public static readonly TimeSpan WindowAdjustmentInterval = TimeSpan.FromMinutes(2);
        public static readonly TimeSpan DefaultMaxChainAge = TimeSpan.FromHours(1);
    }

    public static class MemoryPool
    {
        public const int DEFAULT_BUFFER_SIZE = 4096;
        public const int MAX_POOL_SIZE = 100;
        public const int SECURE_WIPE_CHUNK_SIZE = 1024;
    }

    public static class ErrorMessages
    {
        public const string FAILED_TO_ALLOCATE_SECURE_MEMORY = "Failed to allocate secure memory: ";
        public const string REQUESTED_SIZE_EXCEEDS_ALLOCATED = "Requested size {0} exceeds allocated size {1}";
        public const string FAILED_TO_READ_SECURE_MEMORY = "Failed to read secure memory: ";
        public const string BUFFER_DISPOSED = "Buffer is disposed";
        public const string HANDLE_DISPOSED = "Handle disposed";
        public const string DATA_EXCEEDS_BUFFER = "Data ({0}) > buffer ({1})";
        public const string REF_COUNT_FAILED = "Ref count failed";
        public const string UNEXPECTED_WRITE_ERROR = "Unexpected write error";
        public const string BUFFER_SIZE_POSITIVE = "Buffer size must be positive";
        public const string MAX_POOL_SIZE_POSITIVE = "Max pool size must be positive";
        public const string SIZE_POSITIVE = "Size must be positive";
        public const string LIB_SODIUM_CONSTANT_TIME_COMPARISON_FAILED = "libsodium constant-time comparison failed.";

        public const string SECURE_STRING_HANDLER_DISPOSED = "SecureStringHandler is disposed";
    }

    public static class Numeric
    {
        public const int DLL_IMPORT_SUCCESS = 0;
        public const int ZERO_VALUE = 0;
    }

    public static class Protocol
    {
        public const string INITIAL_SENDER_CHAIN_INFO = "ShieldInitSend";
        public const string INITIAL_RECEIVER_CHAIN_INFO = "ShieldInitRecv";
        public const string DH_RATCHET_INFO = "ShieldDhRatchet";

        public const long INITIAL_NONCE_COUNTER = 0;
        public const long MAX_NONCE_COUNTER = 10_000_000;
        public const int RANDOM_NONCE_PREFIX_SIZE = 8;
        public const uint DEFAULT_CHAIN_INDEX = 0;
        public const int HKDF_OUTPUT_BUFFER_MULTIPLIER = 2;
    }

    public static class RatchetRecovery
    {
        public const uint CLEANUP_THRESHOLD = 100;
        public const uint INDEX_OVERFLOW_BUFFER = 10000;
    }

    public static class ChainStep
    {
        public const uint DEFAULT_CACHE_WINDOW_SIZE = 1000;
        public const uint INITIAL_INDEX = 0;
        public const uint INDEX_INCREMENT = 1;
        public const uint RESET_INDEX = 0;
        public const uint MIN_INDEX_TO_KEEP_OFFSET = 1;
        public const uint VALIDATOR_ARRAY_EMPTY_THRESHOLD = 0;
    }

    public static class ProtocolSystem
    {
        public const int EMPTY_ARRAY_LENGTH = 0;
        public const int MAX_IDENTITY_KEY_LENGTH = 1024;
        public const int MAX_ASSOCIATED_DATA_LENGTH = MAX_IDENTITY_KEY_LENGTH * 2;
        public const int MAX_PAYLOAD_SIZE = 10 * 1024 * 1024;
        public const int INTEGER_OVERFLOW_DIVISOR = 2;
        public const int BUFFER_COPY_START_OFFSET = 0;
        public const int CIPHER_LENGTH_MINIMUM_THRESHOLD = 0;

        public const string DH_PUBLIC_KEY_NULL_MESSAGE = "DH public key is null";
        public const string NO_CONNECTION_MESSAGE = "No connection";
        public const string REFLECTION_ATTACK_MESSAGE = "Potential reflection attack detected - peer echoed our DH key";
        public const string PARSE_PROTOBUF_FAILED_MESSAGE = "Failed to parse peer public key bundle from protobuf.";
        public const string SIGNED_PRE_KEY_FAILED_MESSAGE = "Signed pre-key signature verification failed";
        public const string PROTOCOL_CONNECTION_NOT_INITIALIZED_MESSAGE = "Protocol connection not initialized";
        public const string IDENTITY_KEYS_TOO_LARGE_MESSAGE = "Identity keys too large (max {0} bytes each)";
        public const string INTEGER_OVERFLOW_MESSAGE = "Combined identity keys would cause integer overflow";
        public const string AES_GCM_ENCRYPTION_FAILED_MESSAGE = "AES-GCM encryption failed.";
        public const string CIPHERTEXT_TOO_SMALL_MESSAGE = "Received ciphertext length ({0}) is smaller than the GCM tag size ({1}).";
        public const string AES_GCM_DECRYPTION_FAILED_MESSAGE = "AES-GCM decryption failed (authentication tag mismatch).";
    }

    public static class Libraries
    {
        public const string LIB_SODIUM = "libsodium";
        public const string KERNEL_32 = "kernel32.dll";
        public const string LIB_C = "libc";
    }
}
