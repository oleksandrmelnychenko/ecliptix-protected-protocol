
#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server.Native;
#else
namespace Ecliptix.Protocol.Client.Native;
#endif

public static class NativeProtocolSystem
{
    public static Result<Unit, EcliptixProtocolFailure> Initialize()
    {
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_initialize();
        return result == EcliptixErrorCode.SUCCESS
            ? Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value)
            : Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(
                    $"Failed to initialize native protocol: {EcliptixNativeInterop.ErrorCodeToString(result)}"));
    }

    public static void Shutdown() => EcliptixNativeInterop.ecliptix_shutdown();

    public static Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> CreateIdentity()
        => EcliptixIdentityKeysWrapper.Create();

    public static Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> CreateIdentityFromSeed(
        byte[] seed,
        string accountId)
        => EcliptixIdentityKeysWrapper.CreateFromSeed(seed, accountId);

    public static Result<NativeProtocolSession, EcliptixProtocolFailure> CreateSessionAdapter(
        EcliptixIdentityKeysWrapper identity,
        Action<uint>? onProtocolStateChanged = null)
    {
        Result<NativeProtocolSession, EcliptixProtocolFailure> sessionResult = NativeProtocolSession.Create(identity);
        if (sessionResult.IsErr)
        {
            return sessionResult;
        }
        NativeProtocolSession session = sessionResult.Unwrap();
        session.SetEventHandler(onProtocolStateChanged);
        return Result<NativeProtocolSession, EcliptixProtocolFailure>.Ok(session);
    }

    public static string GetVersion() => EcliptixNativeInterop.GetVersion();
}
