using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Sodium;

#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server.Sodium;
#else
namespace Ecliptix.Protocol.Client.Sodium;
#endif

internal static partial class SodiumInterop
{
    private const string LIB_SODIUM = ProtocolSystemConstants.Libraries.LIB_SODIUM;

    private const int MAX_BUFFER_SIZE = 1_000_000_000;

    private static readonly Result<Unit, SodiumFailure> InitializationResult = InitializeSodium();

    public static bool IsInitialized => InitializationResult.IsOk;

    [LibraryImport(LIB_SODIUM, EntryPoint = "sodium_init")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int sodium_init();

    [LibraryImport(LIB_SODIUM, EntryPoint = "sodium_malloc")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr sodium_malloc(nuint size);

    [LibraryImport(LIB_SODIUM, EntryPoint = "sodium_free")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void sodium_free(IntPtr ptr);

    [LibraryImport(LIB_SODIUM, EntryPoint = "sodium_memzero")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial void sodium_memzero(IntPtr ptr, nuint length);

    [LibraryImport(LIB_SODIUM, EntryPoint = "sodium_memcmp")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int sodium_memcmp(byte[] b1, byte[] b2, nuint length);

    [LibraryImport(LIB_SODIUM, EntryPoint = "sodium_memcmp")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial int sodium_memcmp(void* b1, void* b2, nuint length);

    private static Result<Unit, SodiumFailure> InitializeSodium()
    {
        return Result<Unit, SodiumFailure>.Try(
            () =>
            {
                int result = sodium_init();
                const int dllImportSuccess = ProtocolSystemConstants.Numeric.DLL_IMPORT_SUCCESS;
                if (result < dllImportSuccess)
                {
                    throw new InvalidOperationException(SodiumFailureMessages.SODIUM_INIT_FAILED);
                }
            },
            ex => ex switch
            {
                DllNotFoundException dllEx => SodiumFailure.LibraryNotFound(
                    string.Format(SodiumFailureMessages.LIBRARY_LOAD_FAILED, LIB_SODIUM), dllEx),
                InvalidOperationException opEx when opEx.Message.Contains(SodiumExceptionMessagePatterns
                        .SODIUM_INIT_PATTERN) =>
                    SodiumFailure.INITIALIZATION_FAILED(SodiumFailureMessages.INITIALIZATION_FAILED, opEx),
                _ => SodiumFailure.INITIALIZATION_FAILED(SodiumFailureMessages.UNEXPECTED_INIT_ERROR, ex)
            }
        );
    }

    public static void SecureWipe(byte[]? buffer)
    {
        if (!IsInitialized)
        {
            Result<Unit, SodiumFailure>.Err(
                SodiumFailure.INITIALIZATION_FAILED(SodiumFailureMessages.NOT_INITIALIZED));
            return;
        }

        Result<byte[], SodiumFailure>
            .FromValue(buffer, SodiumFailure.BUFFER_TOO_SMALL(SodiumFailureMessages.BUFFER_NULL))
            .Bind(nonNullBuffer => nonNullBuffer switch
            {
                { Length: 0 } => Result<Unit, SodiumFailure>.Ok(Unit.Value),
                _ => Result<byte[], SodiumFailure>.Validate(
                        nonNullBuffer,
                        buf => buf.Length <= MAX_BUFFER_SIZE,
                        SodiumFailure.BUFFER_TOO_LARGE(
                            string.Format(SodiumFailureMessages.BUFFER_TOO_LARGE, nonNullBuffer.Length, MAX_BUFFER_SIZE)))
                    .Bind(validBuffer => validBuffer.Length <= Constants.SMALL_BUFFER_THRESHOLD
                        ? WipeSmallBuffer(validBuffer)
                        : WipeLargeBuffer(validBuffer))
            });
    }

    public static Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> GenerateX25519KeyPair(
        string keyPurpose)
    {
        try
        {
            Result<SodiumSecureMemoryHandle, SodiumFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.X_25519_PRIVATE_KEY_SIZE);
            if (allocResult.IsErr)
            {
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(allocResult.UnwrapErr()
                    .ToEcliptixProtocolFailure());
            }

            SodiumSecureMemoryHandle? skHandle = allocResult.Unwrap();

            byte[] skBytes = SodiumCore.GetRandomBytes(Constants.X_25519_PRIVATE_KEY_SIZE);
            try
            {
                Result<Unit, SodiumFailure> writeResult = skHandle.Write(skBytes);
                if (writeResult.IsErr)
                {
                    skHandle.Dispose();
                    return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(writeResult.UnwrapErr()
                        .ToEcliptixProtocolFailure());
                }
            }
            finally
            {
                SecureWipe(skBytes);
            }

            byte[] tempPrivCopy = new byte[Constants.X_25519_PRIVATE_KEY_SIZE];
            try
            {
                Result<Unit, SodiumFailure> readResult = skHandle.Read(tempPrivCopy);
                if (readResult.IsErr)
                {
                    skHandle.Dispose();
                    return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(readResult.UnwrapErr()
                        .ToEcliptixProtocolFailure());
                }

                Result<byte[], EcliptixProtocolFailure> deriveResult = Result<byte[], EcliptixProtocolFailure>.Try(
                    () => ScalarMult.Base(tempPrivCopy),
                    ex => EcliptixProtocolFailure.DeriveKey($"Failed to derive {keyPurpose} public key.", ex));

                if (deriveResult.IsErr)
                {
                    skHandle.Dispose();
                    return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>
                        .Err(deriveResult.UnwrapErr());
                }

                byte[] pkBytes = deriveResult.Unwrap();

                if (pkBytes.Length != Constants.X_25519_PUBLIC_KEY_SIZE)
                {
                    skHandle.Dispose();
                    SecureWipe(pkBytes);
                    return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.DeriveKey($"Derived {keyPurpose} public key has incorrect size."));
                }

                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Ok((skHandle, pkBytes));
            }
            finally
            {
                SecureWipe(tempPrivCopy);
            }
        }
        catch (Exception ex)
        {
            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration($"Unexpected error generating {keyPurpose} key pair.", ex));
        }
    }

    public static Result<bool, SodiumFailure> ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length)
        {
            return Result<bool, SodiumFailure>.Ok(false);
        }

        if (a.IsEmpty)
        {
            return Result<bool, SodiumFailure>.Ok(true);
        }

        try
        {
            unsafe
            {
                fixed (byte* ptrA = a)
                fixed (byte* ptrB = b)
                {
                    int result = sodium_memcmp(ptrA, ptrB, (nuint)a.Length);
                    return Result<bool, SodiumFailure>.Ok(result == ProtocolSystemConstants.Numeric.ZERO_VALUE);
                }
            }
        }
        catch (Exception ex)
        {
            return Result<bool, SodiumFailure>.Err(
                SodiumFailure.ComparisonFailed(ProtocolSystemConstants.ErrorMessages.LIB_SODIUM_CONSTANT_TIME_COMPARISON_FAILED, ex));
        }
    }

    private static Result<Unit, SodiumFailure> WipeSmallBuffer(byte[] buffer)
    {
        return Result<Unit, SodiumFailure>.Try(
            () => { Array.Clear(buffer, ProtocolSystemConstants.Numeric.ZERO_VALUE, buffer.Length); },
            ex =>
                SodiumFailure.SECURE_WIPE_FAILED(
                    string.Format(SodiumFailureMessages.SMALL_BUFFER_CLEAR_FAILED, buffer.Length), ex));
    }

    private static Result<Unit, SodiumFailure> WipeLargeBuffer(byte[] buffer)
    {
        GCHandle handle = default;
        return Result<Unit, SodiumFailure>.Try(
            () =>
            {
                handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                IntPtr ptr = handle.AddrOfPinnedObject();
                if (ptr == IntPtr.Zero && buffer.Length > ProtocolSystemConstants.Numeric.ZERO_VALUE)
                {
                    throw new InvalidOperationException(SodiumFailureMessages.ADDRESS_OF_PINNED_OBJECT_FAILED);
                }

                sodium_memzero(ptr, (UIntPtr)buffer.Length);
            },
            ex => ex switch
            {
                ArgumentException argEx => SodiumFailure.MemoryPinningFailed(
                    SodiumFailureMessages.PINNING_FAILED, argEx),
                OutOfMemoryException oomEx => SodiumFailure.MemoryPinningFailed(
                    SodiumFailureMessages.INSUFFICIENT_MEMORY, oomEx),
                InvalidOperationException opEx when opEx.Message.Contains(SodiumExceptionMessagePatterns
                        .ADDRESS_PINNED_OBJECT_PATTERN) =>
                    SodiumFailure.MemoryPinningFailed(SodiumFailureMessages.GET_PINNED_ADDRESS_FAILED, opEx),
                _ => SodiumFailure.MemoryPinningFailed(
                    string.Format(SodiumFailureMessages.SECURE_WIPE_FAILED, buffer.Length), ex)
            },
            () =>
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        );
    }
}
