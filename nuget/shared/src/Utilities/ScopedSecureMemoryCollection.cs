
namespace EPP.Utilities;




internal sealed class ScopedSecureMemoryCollection : IDisposable
{
    private readonly List<IDisposable> _resources = [];
    private bool _disposed;

    public ScopedSecureMemory Allocate(int size)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        ScopedSecureMemory memory = ScopedSecureMemory.Allocate(size);
        _resources.Add(memory);
        return memory;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        for (int i = _resources.Count - 1; i >= 0; i--)
        {
            try
            {
                _resources[i].Dispose();
            }
            catch (Exception ex)
            {
                Serilog.Log.Error(ex, "[SCOPED-SECURE-MEMORY] Failed to dispose resource at index {Index}. Continuing with remaining resources",
                    i);
            }
        }

        _resources.Clear();
        _disposed = true;
    }
}
