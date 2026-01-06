#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server.Utilities;
#else
namespace Ecliptix.Protocol.Client.Utilities;
#endif

internal static class SecureArrayPool
{
    public static SecurePooledArray<T> Rent<T>(int minimumLength) where T : struct => new(minimumLength);
}
