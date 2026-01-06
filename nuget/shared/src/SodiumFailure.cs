#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server;
#else
namespace Ecliptix.Protocol.Client;
#endif

public enum SodiumFailureType
{
    INITIALIZATION_FAILED,
    LIBRARY_NOT_FOUND,
    ALLOCATION_FAILED,
    MEMORY_PINNING_FAILED,
    SECURE_WIPE_FAILED,
    INVALID_BUFFER_SIZE,
    BUFFER_TOO_SMALL,
    BUFFER_TOO_LARGE,
    NULL_POINTER,
    MEMORY_PROTECTION_FAILED,
    COMPARISON_FAILED,
}

public sealed class SodiumFailure
{
    private SodiumFailure(SodiumFailureType type, string message, Exception? innerException = null)
    {
        Type = type;
        Message = message;
        InnerException = innerException;
    }

    public SodiumFailureType Type { get; }
    public string Message { get; }
    public Exception? InnerException { get; }

    public static SodiumFailure INITIALIZATION_FAILED(string details, Exception? inner = null) => new(SodiumFailureType.INITIALIZATION_FAILED, details, inner);

    public static SodiumFailure ComparisonFailed(string details, Exception? inner = null) => new(SodiumFailureType.COMPARISON_FAILED, details, inner);

    public static SodiumFailure LibraryNotFound(string details, Exception? inner = null) => new(SodiumFailureType.LIBRARY_NOT_FOUND, details, inner);

    public static SodiumFailure ALLOCATION_FAILED(string details, Exception? inner = null) => new(SodiumFailureType.ALLOCATION_FAILED, details, inner);

    public static SodiumFailure MemoryPinningFailed(string details, Exception? inner = null) => new(SodiumFailureType.MEMORY_PINNING_FAILED, details, inner);

    public static SodiumFailure SECURE_WIPE_FAILED(string details, Exception? inner = null) => new(SodiumFailureType.SECURE_WIPE_FAILED, details, inner);

    public static SodiumFailure MemoryProtectionFailed(string details, Exception? inner = null) => new(SodiumFailureType.MEMORY_PROTECTION_FAILED, details, inner);

    public static SodiumFailure NullPointer(string details) => new(SodiumFailureType.NULL_POINTER, details);

    public static SodiumFailure InvalidBufferSize(string details) => new(SodiumFailureType.INVALID_BUFFER_SIZE, details);

    public static SodiumFailure BUFFER_TOO_SMALL(string details) => new(SodiumFailureType.BUFFER_TOO_SMALL, details);

    public static SodiumFailure BUFFER_TOO_LARGE(string details) => new(SodiumFailureType.BUFFER_TOO_LARGE, details);

    public static SodiumFailure InvalidOperation(string details) => new(SodiumFailureType.INVALID_BUFFER_SIZE, details);

    public static SodiumFailure OBJECT_DISPOSED(string details) => new(SodiumFailureType.NULL_POINTER, details);

    public override string ToString() => $"SodiumFailure(Type={Type}, Message='{Message}'{(InnerException != null ? $", InnerException='{InnerException.GetType().Name}: {InnerException.Message}'" : "")})";

    public override bool Equals(object? obj)
    {
        return obj is SodiumFailure other &&
               Type == other.Type &&
               Message == other.Message &&
               Equals(InnerException, other.InnerException);
    }

    public override int GetHashCode() => HashCode.Combine(Type, Message, InnerException);

    public EcliptixProtocolFailure ToEcliptixProtocolFailure()
    {
        return Type switch
        {
            SodiumFailureType.INITIALIZATION_FAILED => EcliptixProtocolFailure.Generic(Message, InnerException),
            SodiumFailureType.LIBRARY_NOT_FOUND => EcliptixProtocolFailure.Generic(Message, InnerException),
            SodiumFailureType.ALLOCATION_FAILED => EcliptixProtocolFailure.ALLOCATION_FAILED(Message, InnerException),
            SodiumFailureType.MEMORY_PINNING_FAILED => EcliptixProtocolFailure.PinningFailure(Message, InnerException),
            SodiumFailureType.SECURE_WIPE_FAILED => EcliptixProtocolFailure.MemoryBufferError(Message, InnerException),
            SodiumFailureType.MEMORY_PROTECTION_FAILED => EcliptixProtocolFailure.MemoryBufferError(Message, InnerException),
            SodiumFailureType.NULL_POINTER => EcliptixProtocolFailure.OBJECT_DISPOSED(Message),
            SodiumFailureType.INVALID_BUFFER_SIZE => EcliptixProtocolFailure.InvalidInput(Message),
            SodiumFailureType.BUFFER_TOO_SMALL => EcliptixProtocolFailure.BUFFER_TOO_SMALL(Message),
            SodiumFailureType.BUFFER_TOO_LARGE => EcliptixProtocolFailure.DATA_TOO_LARGE(Message),
            _ => EcliptixProtocolFailure.Generic(Message, InnerException)
        };
    }
}

public static class ResultSodiumExtensions
{
    public static Result<T, EcliptixProtocolFailure> MapSodiumFailure<T>(this Result<T, SodiumFailure> result)
    {
        return result.IsOk
            ? Result<T, EcliptixProtocolFailure>.Ok(result.Unwrap())
            : Result<T, EcliptixProtocolFailure>.Err(result.UnwrapErr().ToEcliptixProtocolFailure());
    }
}

public static class SodiumExceptionMessagePatterns
{
    public const string SODIUM_INIT_PATTERN = "sodium_init() returned an error code";
    public const string ADDRESS_PINNED_OBJECT_PATTERN = "AddrOfPinnedObject returned IntPtr.Zero";
}

public static class SodiumFailureMessages
{
    public const string SODIUM_INIT_FAILED = "sodium_init() returned an error code.";

    public const string LIBRARY_LOAD_FAILED =
        "Failed to load {0}. Ensure the native library is available and compatible.";

    public const string INITIALIZATION_FAILED = "Failed to initialize libsodium library.";
    public const string UNEXPECTED_INIT_ERROR = "An unexpected error occurred during libsodium initialization.";
    public const string NOT_INITIALIZED = "SodiumInterop is not initialized. Cannot perform secure wipe.";
    public const string BUFFER_NULL = "Buffer cannot be null.";
    public const string BUFFER_TOO_LARGE = "Buffer size ({0:N0} bytes) exceeds maximum ({1:N0} bytes).";
    public const string SMALL_BUFFER_CLEAR_FAILED = "Failed to clear small buffer ({0} bytes) using Array.Clear.";
    public const string PINNING_FAILED = "Failed to pin buffer memory (GCHandle.Alloc). Invalid buffer or handle type.";
    public const string INSUFFICIENT_MEMORY = "Insufficient memory to pin buffer (GCHandle.Alloc).";

    public const string ADDRESS_OF_PINNED_OBJECT_FAILED =
        "GCHandle.Alloc succeeded, but AddrOfPinnedObject returned IntPtr.Zero for a non-empty buffer.";

    public const string GET_PINNED_ADDRESS_FAILED = "Failed to get address of pinned buffer.";
    public const string SECURE_WIPE_FAILED = "Unexpected error during secure wipe via sodium_memzero ({0} bytes).";

    public const string NEGATIVE_ALLOCATION_LENGTH = "Requested allocation length cannot be negative ({0}).";
    public const string SODIUM_NOT_INITIALIZED = "SodiumInterop is not initialized.";
    public const string ALLOCATION_FAILED = "sodium_malloc failed to allocate {0} bytes.";
    public const string UNEXPECTED_ALLOCATION_ERROR = "Unexpected error during allocation ({0} bytes).";
    public const string OBJECT_DISPOSED = "Cannot access disposed resource '{0}'.";
    public const string REFERENCE_COUNT_FAILED = "Failed to increment reference count.";
    public const string DISPOSED_AFTER_ADD_REF = "{0} disposed after AddRef.";
    public const string BUFFER_TOO_SMALL = "Destination buffer size ({0}) is smaller than the allocated size ({1}).";
    public const string UNEXPECTED_READ_ERROR = "Unexpected error during read operation.";
    public const string NEGATIVE_READ_LENGTH = "Requested read length cannot be negative ({0}).";
    public const string READ_LENGTH_EXCEEDS_SIZE = "Requested read length ({0}) exceeds allocated size ({1}).";
    public const string UNEXPECTED_READ_BYTES_ERROR = "Unexpected error reading {0} bytes.";
}
