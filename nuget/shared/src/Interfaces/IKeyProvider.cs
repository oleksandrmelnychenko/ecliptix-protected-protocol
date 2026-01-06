

namespace EPP.Interfaces;




internal interface IKeyProvider
{
    Result<T, EcliptixProtocolFailure> ExecuteWithKey<T>(uint keyIndex, Func<ReadOnlySpan<byte>, Result<T, EcliptixProtocolFailure>> operation);
}
