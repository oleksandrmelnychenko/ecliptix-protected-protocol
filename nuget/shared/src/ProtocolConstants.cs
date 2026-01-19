namespace EPP;

internal static class ProtocolConstants
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

    public static class Libraries
    {
        public const string LIB_SODIUM = "libsodium";
        public const string KERNEL_32 = "kernel32.dll";
        public const string LIB_C = "libc";
    }
}
