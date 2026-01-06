#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server;
#else
namespace Ecliptix.Protocol.Client;
#endif

public enum EcliptixProtocolFailureType
{
    GENERIC,
    DECODE_FAILED,
    DERIVE_KEY_FAILED,
    HANDSHAKE_FAILED,
    PEER_PUB_KEY_FAILED,
    INVALID_INPUT,
    OBJECT_DISPOSED,
    ALLOCATION_FAILED,
    PINNING_FAILURE,
    BUFFER_TOO_SMALL,
    DATA_TOO_LARGE,
    KEY_GENERATION_FAILED,
    PREPARE_LOCAL_FAILED,
    MEMORY_BUFFER_ERROR,
    STATE_MISMATCH,
}

public sealed class EcliptixProtocolFailure
{
    public EcliptixProtocolFailureType FailureType { get; }
    public string Message { get; }
    public Exception? InnerException { get; }

    private EcliptixProtocolFailure(EcliptixProtocolFailureType failureType, string message, Exception? innerException = null)
    {
        FailureType = failureType;
        Message = message;
        InnerException = innerException;
    }

    public static EcliptixProtocolFailure Generic(string details, Exception? inner = null) => new(EcliptixProtocolFailureType.GENERIC, details, inner);

    public static EcliptixProtocolFailure Decode(string details, Exception? inner = null) => new(EcliptixProtocolFailureType.DECODE_FAILED, details, inner);

    public static EcliptixProtocolFailure DeriveKey(string details, Exception? inner = null) => new(EcliptixProtocolFailureType.DERIVE_KEY_FAILED, details, inner);

    public static EcliptixProtocolFailure Handshake(string details, Exception? inner = null) => new(EcliptixProtocolFailureType.HANDSHAKE_FAILED, details, inner);

    public static EcliptixProtocolFailure PeerPubKey(string details, Exception? inner = null) => new(EcliptixProtocolFailureType.PEER_PUB_KEY_FAILED, details, inner);

    public static EcliptixProtocolFailure InvalidInput(string details) => new(EcliptixProtocolFailureType.INVALID_INPUT, details);

    public static EcliptixProtocolFailure OBJECT_DISPOSED(string resourceName) => new(EcliptixProtocolFailureType.OBJECT_DISPOSED, $"Cannot access disposed resource '{resourceName}'.");

    public static EcliptixProtocolFailure ALLOCATION_FAILED(string details, Exception? inner = null) => new(EcliptixProtocolFailureType.ALLOCATION_FAILED, details, inner);

    public static EcliptixProtocolFailure PinningFailure(string details, Exception? inner = null) => new(EcliptixProtocolFailureType.PINNING_FAILURE, details, inner);

    public static EcliptixProtocolFailure BUFFER_TOO_SMALL(string details) => new(EcliptixProtocolFailureType.BUFFER_TOO_SMALL, details);

    public static EcliptixProtocolFailure DATA_TOO_LARGE(string details) => new(EcliptixProtocolFailureType.DATA_TOO_LARGE, details);

    public static EcliptixProtocolFailure KeyGeneration(string details, Exception? inner = null) => new(EcliptixProtocolFailureType.KEY_GENERATION_FAILED, details, inner);

    public static EcliptixProtocolFailure PrepareLocal(string details, Exception? inner = null) => new(EcliptixProtocolFailureType.PREPARE_LOCAL_FAILED, details, inner);

    public static EcliptixProtocolFailure MemoryBufferError(string details, Exception? inner = null) => new(EcliptixProtocolFailureType.MEMORY_BUFFER_ERROR, details, inner);

    public static EcliptixProtocolFailure StateMismatch(string details, Exception? inner = null) => new(EcliptixProtocolFailureType.STATE_MISMATCH, details, inner);

    public override string ToString() => $"EcliptixProtocolFailure(Type={FailureType}, Message='{Message}'{(InnerException != null ? $", InnerException='{InnerException.GetType().Name}'" : "")})";
}
