using System.Security.Cryptography;
using System.Text;
#if ECLIPTIX_SERVER
using Ecliptix.Protocol.Server.Sodium;
#else
using Ecliptix.Protocol.Client.Sodium;
#endif

#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server.Utilities;
#else
namespace Ecliptix.Protocol.Client.Utilities;
#endif

internal sealed class SecureStringHandler : IDisposable
{
    private readonly SodiumSecureMemoryHandle _handle;
    private readonly int _length;
    private bool _disposed;

    internal SecureStringHandler(SodiumSecureMemoryHandle handle, int length)
    {
        _handle = handle;
        _length = length;
    }

    public static Result<SecureStringHandler, SodiumFailure> FromString(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return Result<SecureStringHandler, SodiumFailure>.Err(
                SodiumFailure.InvalidBufferSize("Input string cannot be null or empty"));
        }

        byte[]? bytes = null;
        try
        {
            bytes = Encoding.UTF8.GetBytes(input);

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(bytes.Length);
            if (allocResult.IsErr)
            {
                return Result<SecureStringHandler, SodiumFailure>.Err(allocResult.UnwrapErr());
            }

            SodiumSecureMemoryHandle handle = allocResult.Unwrap();
            Result<Unit, SodiumFailure> writeResult = handle.Write(bytes);
            if (!writeResult.IsErr)
            {
                return Result<SecureStringHandler, SodiumFailure>.Ok(
                    new SecureStringHandler(handle, bytes.Length));
            }

            handle.Dispose();
            return Result<SecureStringHandler, SodiumFailure>.Err(writeResult.UnwrapErr());
        }
        finally
        {
            if (bytes != null)
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    public Result<T, SodiumFailure> UseBytes<T>(Func<ReadOnlySpan<byte>, T> operation)
    {
        if (_disposed)
        {
            return Result<T, SodiumFailure>.Err(
                SodiumFailure.NullPointer(ProtocolSystemConstants.ErrorMessages.SECURE_STRING_HANDLER_DISPOSED));
        }

        byte[]? tempBytes = null;
        try
        {
            tempBytes = new byte[_length];
            Result<Unit, SodiumFailure> readResult = _handle.Read(tempBytes);
            if (readResult.IsErr)
            {
                return Result<T, SodiumFailure>.Err(readResult.UnwrapErr());
            }

            T result = operation(tempBytes.AsSpan(0, _length));
            return Result<T, SodiumFailure>.Ok(result);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tempBytes);
        }
    }

    public int ByteLength => _length;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _handle?.Dispose();
    }
}
