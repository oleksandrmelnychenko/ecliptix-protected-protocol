
#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server.Interfaces;
#else
namespace Ecliptix.Protocol.Client.Interfaces;
#endif

internal interface IKeyProvider
{
    Result<T, EcliptixProtocolFailure> ExecuteWithKey<T>(uint keyIndex, Func<ReadOnlySpan<byte>, Result<T, EcliptixProtocolFailure>> operation);
}
