namespace Ecliptix.Protocol.Client;

/// <summary>
/// Represents a failure in the Ecliptix Protocol System.
/// </summary>
public sealed class EcliptixProtocolFailure
{
    public EcliptixProtocolFailureKind Kind { get; }
    public string Message { get; }

    private EcliptixProtocolFailure(EcliptixProtocolFailureKind kind, string message)
    {
        Kind = kind;
        Message = message;
    }

    public static EcliptixProtocolFailure Generic(string message) =>
        new(EcliptixProtocolFailureKind.Generic, message);

    public static EcliptixProtocolFailure InvalidInput(string message) =>
        new(EcliptixProtocolFailureKind.InvalidInput, message);

    public static EcliptixProtocolFailure KeyGeneration(string message) =>
        new(EcliptixProtocolFailureKind.KeyGeneration, message);

    public static EcliptixProtocolFailure DeriveKey(string message) =>
        new(EcliptixProtocolFailureKind.DeriveKey, message);

    public static EcliptixProtocolFailure Handshake(string message) =>
        new(EcliptixProtocolFailureKind.Handshake, message);

    public static EcliptixProtocolFailure Encryption(string message) =>
        new(EcliptixProtocolFailureKind.Encryption, message);

    public static EcliptixProtocolFailure Decryption(string message) =>
        new(EcliptixProtocolFailureKind.Decryption, message);

    public static EcliptixProtocolFailure Decode(string message) =>
        new(EcliptixProtocolFailureKind.Decode, message);

    public static EcliptixProtocolFailure Encode(string message) =>
        new(EcliptixProtocolFailureKind.Encode, message);

    public static EcliptixProtocolFailure BufferTooSmall(string message) =>
        new(EcliptixProtocolFailureKind.BufferTooSmall, message);

    public static EcliptixProtocolFailure ObjectDisposed(string message) =>
        new(EcliptixProtocolFailureKind.ObjectDisposed, message);

    public static EcliptixProtocolFailure PrepareLocal(string message) =>
        new(EcliptixProtocolFailureKind.PrepareLocal, message);

    public static EcliptixProtocolFailure ReplayAttack(string message) =>
        new(EcliptixProtocolFailureKind.ReplayAttack, message);

    public static EcliptixProtocolFailure SessionExpired(string message) =>
        new(EcliptixProtocolFailureKind.SessionExpired, message);

    public static EcliptixProtocolFailure PqMissing(string message) =>
        new(EcliptixProtocolFailureKind.PqMissing, message);

    public override string ToString() => $"[{Kind}] {Message}";
}

public enum EcliptixProtocolFailureKind
{
    Generic,
    InvalidInput,
    KeyGeneration,
    DeriveKey,
    Handshake,
    Encryption,
    Decryption,
    Decode,
    Encode,
    BufferTooSmall,
    ObjectDisposed,
    PrepareLocal,
    ReplayAttack,
    SessionExpired,
    PqMissing
}
