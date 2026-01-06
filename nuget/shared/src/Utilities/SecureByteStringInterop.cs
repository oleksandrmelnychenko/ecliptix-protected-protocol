#if ECLIPTIX_SERVER
using Ecliptix.Protocol.Server.Sodium;
#else
using Ecliptix.Protocol.Client.Sodium;
#endif
using Google.Protobuf;

#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server.Utilities;
#else
namespace Ecliptix.Protocol.Client.Utilities;
#endif

public static class SecureByteStringInterop
{
    public static Result<ByteString, SodiumFailure> CreateByteStringFromSecureMemory(SodiumSecureMemoryHandle source,
        int length)
    {
        switch (length)
        {
            case < 0:
                return Result<ByteString, SodiumFailure>.Err(
                    SodiumFailure.InvalidBufferSize($"Negative length requested: {length}"));
            case 0:
                return Result<ByteString, SodiumFailure>.Ok(ByteString.Empty);
        }

        if (length > source.Length)
        {
            return Result<ByteString, SodiumFailure>.Err(
                SodiumFailure.InvalidBufferSize($"Requested length {length} exceeds handle length {source.Length}"));
        }

        return source.WithReadAccess(span =>
            Result<ByteString, SodiumFailure>.Ok(ByteString.CopyFrom(span.Slice(0, length))));
    }

    public static TResult WithByteStringAsSpan<TResult>(ByteString byteString,
        Func<ReadOnlySpan<byte>, TResult> operation) =>
        operation(byteString.IsEmpty ? [] : byteString.Span);

    public static void SecureCopyWithCleanup(ByteString source, out byte[] destination)
    {
        if (source.IsEmpty)
        {
            destination = [];
            return;
        }

        destination = new byte[source.Length];
        source.Span.CopyTo(destination);
    }

    public static ByteString CreateByteStringFromSpan(ReadOnlySpan<byte> source) =>
        source.IsEmpty ? ByteString.Empty : ByteString.CopyFrom(source);

    public static Result<Unit, SodiumFailure> CopyFromByteStringToSecureMemory(ByteString source,
        SodiumSecureMemoryHandle destination) =>
        source.IsEmpty ? Result<Unit, SodiumFailure>.Ok(Unit.Value) : destination.Write(source.Span);
}
