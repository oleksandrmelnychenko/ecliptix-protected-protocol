using System.Security.Cryptography;

#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server.Utilities;
#else
namespace Ecliptix.Protocol.Client.Utilities;
#endif

internal sealed class ScopedSecureMemory : IDisposable
{
    private byte[]? _data;
    private readonly bool _clearOnDispose;
    private bool _disposed;

    private ScopedSecureMemory(byte[] data, bool clearOnDispose = true)
    {
        _data = data;
        _clearOnDispose = clearOnDispose;
    }

    public static ScopedSecureMemory Allocate(int size) => size <= 0
        ? throw new ArgumentException(ProtocolSystemConstants.ErrorMessages.SIZE_POSITIVE, nameof(size))
        : new ScopedSecureMemory(new byte[size]);

    public Span<byte> AsSpan()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _data!.AsSpan();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_data != null && _clearOnDispose)
        {
            CryptographicOperations.ZeroMemory(_data);
        }

        _data = null;
        _disposed = true;
    }
}
