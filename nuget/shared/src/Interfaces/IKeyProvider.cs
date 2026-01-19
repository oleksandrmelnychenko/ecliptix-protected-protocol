

namespace EPP.Interfaces;




internal interface IKeyProvider
{
    Result<T, ProtocolFailure> ExecuteWithKey<T>(uint keyIndex, Func<ReadOnlySpan<byte>, Result<T, ProtocolFailure>> operation);
}
