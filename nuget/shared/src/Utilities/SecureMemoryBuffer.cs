
using EPP.Sodium;

using EPP.Sodium;



namespace EPP.Utilities;




internal sealed class SecureMemoryBuffer : IDisposable
{
    private readonly SecureMemoryPool? _pool;
    private readonly SodiumSecureMemoryHandle _handle;
    private bool _disposed;
    private int _requestedSize;
    private readonly int _allocatedSize;

    public int Length => _requestedSize;
    public int AllocatedSize => _allocatedSize;
    public bool IsDisposed => _disposed;

    internal SecureMemoryBuffer(int requestedSize, int allocatedSize, SecureMemoryPool? pool = null)
    {
        _pool = pool;
        _requestedSize = requestedSize;
        _allocatedSize = allocatedSize;

        Result<SodiumSecureMemoryHandle, SodiumFailure> result = SodiumSecureMemoryHandle.Allocate(allocatedSize);
        if (result.IsErr)
        {
            throw new InvalidOperationException(ProtocolConstants.ErrorMessages.FAILED_TO_ALLOCATE_SECURE_MEMORY + result.UnwrapErr());
        }

        _handle = result.Unwrap();
    }

    internal void SetRequestedSize(int requestedSize)
    {
        if (requestedSize > _allocatedSize)
        {
            throw new ArgumentException(string.Format(ProtocolConstants.ErrorMessages.REQUESTED_SIZE_EXCEEDS_ALLOCATED, requestedSize, _allocatedSize));
        }

        _requestedSize = requestedSize;
    }

    public Span<byte> GetSpan()
    {
        if (!_disposed)
        {
            using SecurePooledArray<byte> tempBuffer = SecureArrayPool.Rent<byte>(AllocatedSize);
            Result<Unit, SodiumFailure> readResult = _handle.Read(tempBuffer.AsSpan());
            if (readResult.IsErr)
            {
                throw new InvalidOperationException(ProtocolConstants.ErrorMessages.FAILED_TO_READ_SECURE_MEMORY + readResult.UnwrapErr());
            }

            byte[] result = new byte[Length];
            tempBuffer.AsSpan()[..Length].CopyTo(result);
            return result.AsSpan(0, Length);
        }

        throw new ObjectDisposedException(nameof(SecureMemoryBuffer));
    }

    public Result<Unit, SodiumFailure> Read(Span<byte> destination)
    {
        if (_disposed)
        {
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.NullPointer(ProtocolConstants.ErrorMessages.BUFFER_DISPOSED));
        }

        return _handle.Read(destination);
    }

    internal void Clear()
    {
        if (_disposed)
        {
            return;
        }

        Span<byte> zeros = stackalloc byte[Math.Min(AllocatedSize, ProtocolConstants.MemoryPool.SECURE_WIPE_CHUNK_SIZE)];
        zeros.Clear();

        for (int offset = 0; offset < AllocatedSize; offset += zeros.Length)
        {
            int chunkSize = Math.Min(zeros.Length, AllocatedSize - offset);
            _ = _handle.Write(zeros[..chunkSize]);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Clear();

        if (_pool != null)
        {
            _pool.Return(this);
        }
        else
        {
            _handle?.Dispose();
        }
    }
}
