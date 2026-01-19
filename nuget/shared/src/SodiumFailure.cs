using System;

namespace EPP;

public enum SodiumFailureType
{
    InitializationFailed,
    LibraryNotFound,
    AllocationFailed,
    MemoryPinningFailed,
    SecureWipeFailed,
    InvalidBufferSize,
    BufferTooSmall,
    BufferTooLarge,
    NullPointer,
    MemoryProtectionFailed,
    ComparisonFailed,
    ObjectDisposed,
    InvalidOperation,
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

    public static SodiumFailure InitializationFailed(string details, Exception? inner = null) =>
        new(SodiumFailureType.InitializationFailed, details, inner);

    public static SodiumFailure ComparisonFailed(string details, Exception? inner = null) =>
        new(SodiumFailureType.ComparisonFailed, details, inner);

    public static SodiumFailure LibraryNotFound(string details, Exception? inner = null) =>
        new(SodiumFailureType.LibraryNotFound, details, inner);

    public static SodiumFailure AllocationFailed(string details, Exception? inner = null) =>
        new(SodiumFailureType.AllocationFailed, details, inner);

    public static SodiumFailure MemoryPinningFailed(string details, Exception? inner = null) =>
        new(SodiumFailureType.MemoryPinningFailed, details, inner);

    public static SodiumFailure SecureWipeFailed(string details, Exception? inner = null) =>
        new(SodiumFailureType.SecureWipeFailed, details, inner);

    public static SodiumFailure MemoryProtectionFailed(string details, Exception? inner = null) =>
        new(SodiumFailureType.MemoryProtectionFailed, details, inner);

    public static SodiumFailure NullPointer(string details, Exception? inner = null) =>
        new(SodiumFailureType.NullPointer, details, inner);

    public static SodiumFailure InvalidBufferSize(string details) =>
        new(SodiumFailureType.InvalidBufferSize, details);

    public static SodiumFailure BufferTooSmall(string details) =>
        new(SodiumFailureType.BufferTooSmall, details);

    public static SodiumFailure BufferTooLarge(string details) =>
        new(SodiumFailureType.BufferTooLarge, details);

    public static SodiumFailure InvalidOperation(string details, Exception? inner = null) =>
        new(SodiumFailureType.InvalidOperation, details, inner);

    public static SodiumFailure ObjectDisposed(string details, Exception? inner = null) =>
        new(SodiumFailureType.ObjectDisposed, details, inner);

    public override string ToString() =>
        $"SodiumFailure(Type={Type}, Message='{Message}'" +
        (InnerException != null ? $", InnerException='{InnerException.GetType().Name}: {InnerException.Message}'" : "") +
        ")";

    public override bool Equals(object? obj)
    {
        return obj is SodiumFailure other &&
               Type == other.Type &&
               Message == other.Message &&
               Equals(InnerException, other.InnerException);
    }

    public override int GetHashCode() => HashCode.Combine(Type, Message, InnerException);

    public ProtocolFailure ToProtocolFailure()
    {
        return Type switch
        {
            SodiumFailureType.InitializationFailed => ProtocolFailure.SodiumFailure(Message, InnerException),
            SodiumFailureType.LibraryNotFound => ProtocolFailure.SodiumFailure(Message, InnerException),
            SodiumFailureType.AllocationFailed => ProtocolFailure.AllocationFailed(Message, InnerException),
            SodiumFailureType.MemoryPinningFailed => ProtocolFailure.PinningFailure(Message, InnerException),
            SodiumFailureType.SecureWipeFailed => ProtocolFailure.MemoryBufferError(Message, InnerException),
            SodiumFailureType.MemoryProtectionFailed => ProtocolFailure.MemoryBufferError(Message, InnerException),
            SodiumFailureType.NullPointer => ProtocolFailure.NullPointer(Message, InnerException),
            SodiumFailureType.ObjectDisposed => ProtocolFailure.ObjectDisposed(Message),
            SodiumFailureType.InvalidBufferSize => ProtocolFailure.InvalidInput(Message),
            SodiumFailureType.BufferTooSmall => ProtocolFailure.BufferTooSmall(Message),
            SodiumFailureType.BufferTooLarge => ProtocolFailure.DataTooLarge(Message),
            SodiumFailureType.ComparisonFailed => ProtocolFailure.SodiumFailure(Message, InnerException),
            SodiumFailureType.InvalidOperation => ProtocolFailure.InvalidState(Message, InnerException),
            _ => ProtocolFailure.Generic(Message, InnerException)
        };
    }
}

public static class ResultSodiumExtensions
{
    public static Result<T, ProtocolFailure> MapSodiumFailure<T>(this Result<T, SodiumFailure> result)
    {
        return result.IsOk
            ? Result<T, ProtocolFailure>.Ok(result.Unwrap())
            : Result<T, ProtocolFailure>.Err(result.UnwrapErr().ToProtocolFailure());
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
