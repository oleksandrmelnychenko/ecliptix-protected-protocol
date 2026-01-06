

namespace EPP.Utilities;




internal static class SecureMemoryUtils
{
    private static readonly SecureMemoryPool DefaultPool = new();

    public static Result<TResult, TError> WithSecureBuffers<TResult, TError>(
        int[] sizes,
        Func<SecureMemoryBuffer[], Result<TResult, TError>> operation)
        where TError : class
    {
        SecureMemoryBuffer[] buffers = new SecureMemoryBuffer[sizes.Length];

        try
        {
            for (int i = 0; i < sizes.Length; i++)
            {
                buffers[i] = DefaultPool.Rent(sizes[i]);
            }

            return operation(buffers);
        }
        finally
        {
            foreach (SecureMemoryBuffer buffer in buffers)
            {
                buffer?.Dispose();
            }
        }
    }
}
