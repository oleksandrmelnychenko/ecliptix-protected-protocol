using System.Collections.Concurrent;


namespace EPP.Utilities;




internal sealed class SecureMemoryPool : IDisposable
{
    private readonly ConcurrentBag<SecureMemoryBuffer> _pool = new();
    private readonly int _defaultBufferSize;
    private readonly int _maxPoolSize;
    private int _currentPoolSize;
    private bool _disposed;

    public SecureMemoryPool(int defaultBufferSize = ProtocolSystemConstants.MemoryPool.DEFAULT_BUFFER_SIZE, int maxPoolSize = ProtocolSystemConstants.MemoryPool.MAX_POOL_SIZE)
    {
        if (defaultBufferSize <= 0)
        {
            throw new ArgumentException(ProtocolSystemConstants.ErrorMessages.BUFFER_SIZE_POSITIVE, nameof(defaultBufferSize));
        }

        if (maxPoolSize <= 0)
        {
            throw new ArgumentException(ProtocolSystemConstants.ErrorMessages.MAX_POOL_SIZE_POSITIVE, nameof(maxPoolSize));
        }

        _defaultBufferSize = defaultBufferSize;
        _maxPoolSize = maxPoolSize;
    }

    public SecureMemoryBuffer Rent(int minimumSize = -1)
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(SecureMemoryPool));
        }

        int requestedSize = minimumSize > 0 ? minimumSize : _defaultBufferSize;
        int allocatedSize = minimumSize > 0 ? Math.Max(minimumSize, _defaultBufferSize) : _defaultBufferSize;

        while (_pool.TryTake(out SecureMemoryBuffer? buffer))
        {
            if (!buffer.IsDisposed && buffer.AllocatedSize >= requestedSize)
            {
                buffer.Clear();
                buffer.SetRequestedSize(requestedSize);
                return buffer;
            }

            buffer.Dispose();
            Interlocked.Decrement(ref _currentPoolSize);
        }

        return new SecureMemoryBuffer(requestedSize, allocatedSize, this);
    }

    internal void Return(SecureMemoryBuffer buffer)
    {
        if (_disposed || buffer.IsDisposed)
        {
            buffer.Dispose();
            return;
        }

        buffer.Clear();

        if (_currentPoolSize < _maxPoolSize)
        {
            _pool.Add(buffer);
            Interlocked.Increment(ref _currentPoolSize);
        }
        else
        {
            buffer.Dispose();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        while (_pool.TryTake(out SecureMemoryBuffer? buffer))
        {
            buffer.Dispose();
        }
    }
}
