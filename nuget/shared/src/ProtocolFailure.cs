using System;

namespace EPP;

public enum ProtocolFailureType
{
    Generic,
    KeyGeneration,
    DeriveKey,
    InvalidInput,
    PrepareLocal,
    PeerPublicKey,
    Handshake,
    Encryption,
    Decryption,
    Decode,
    Encode,
    BufferTooSmall,
    ObjectDisposed,
    ReplayAttack,
    InvalidState,
    NullPointer,
    OutOfMemory,
    SodiumFailure,
    SessionExpired,
    PqMissing,
    AllocationFailed,
    PinningFailure,
    MemoryBufferError,
    DataTooLarge,
    StateMismatch,
}

public sealed class ProtocolFailure
{
    public ProtocolFailureType FailureType { get; }
    public string Message { get; }
    public Exception? InnerException { get; }

    private ProtocolFailure(ProtocolFailureType failureType, string message, Exception? innerException = null)
    {
        FailureType = failureType;
        Message = message;
        InnerException = innerException;
    }

    public static ProtocolFailure Generic(string details, Exception? inner = null) =>
        new(ProtocolFailureType.Generic, details, inner);

    public static ProtocolFailure Decode(string details, Exception? inner = null) =>
        new(ProtocolFailureType.Decode, details, inner);

    public static ProtocolFailure Encode(string details, Exception? inner = null) =>
        new(ProtocolFailureType.Encode, details, inner);

    public static ProtocolFailure DeriveKey(string details, Exception? inner = null) =>
        new(ProtocolFailureType.DeriveKey, details, inner);

    public static ProtocolFailure Handshake(string details, Exception? inner = null) =>
        new(ProtocolFailureType.Handshake, details, inner);

    public static ProtocolFailure PeerPublicKey(string details, Exception? inner = null) =>
        new(ProtocolFailureType.PeerPublicKey, details, inner);

    public static ProtocolFailure InvalidInput(string details) =>
        new(ProtocolFailureType.InvalidInput, details);

    public static ProtocolFailure ObjectDisposed(string details) =>
        new(ProtocolFailureType.ObjectDisposed, details);

    public static ProtocolFailure AllocationFailed(string details, Exception? inner = null) =>
        new(ProtocolFailureType.AllocationFailed, details, inner);

    public static ProtocolFailure PinningFailure(string details, Exception? inner = null) =>
        new(ProtocolFailureType.PinningFailure, details, inner);

    public static ProtocolFailure BufferTooSmall(string details) =>
        new(ProtocolFailureType.BufferTooSmall, details);

    public static ProtocolFailure DataTooLarge(string details) =>
        new(ProtocolFailureType.DataTooLarge, details);

    public static ProtocolFailure KeyGeneration(string details, Exception? inner = null) =>
        new(ProtocolFailureType.KeyGeneration, details, inner);

    public static ProtocolFailure PrepareLocal(string details, Exception? inner = null) =>
        new(ProtocolFailureType.PrepareLocal, details, inner);

    public static ProtocolFailure MemoryBufferError(string details, Exception? inner = null) =>
        new(ProtocolFailureType.MemoryBufferError, details, inner);

    public static ProtocolFailure StateMismatch(string details, Exception? inner = null) =>
        new(ProtocolFailureType.StateMismatch, details, inner);

    public static ProtocolFailure Encryption(string details, Exception? inner = null) =>
        new(ProtocolFailureType.Encryption, details, inner);

    public static ProtocolFailure Decryption(string details, Exception? inner = null) =>
        new(ProtocolFailureType.Decryption, details, inner);

    public static ProtocolFailure InvalidState(string details, Exception? inner = null) =>
        new(ProtocolFailureType.InvalidState, details, inner);

    public static ProtocolFailure ReplayAttack(string details, Exception? inner = null) =>
        new(ProtocolFailureType.ReplayAttack, details, inner);

    public static ProtocolFailure SessionExpired(string details, Exception? inner = null) =>
        new(ProtocolFailureType.SessionExpired, details, inner);

    public static ProtocolFailure NullPointer(string details, Exception? inner = null) =>
        new(ProtocolFailureType.NullPointer, details, inner);

    public static ProtocolFailure OutOfMemory(string details, Exception? inner = null) =>
        new(ProtocolFailureType.OutOfMemory, details, inner);

    public static ProtocolFailure SodiumFailure(string details, Exception? inner = null) =>
        new(ProtocolFailureType.SodiumFailure, details, inner);

    public static ProtocolFailure PqMissing(string details, Exception? inner = null) =>
        new(ProtocolFailureType.PqMissing, details, inner);

    public override string ToString() =>
        $"ProtocolFailure(Type={FailureType}, Message='{Message}'" +
        (InnerException != null ? $", InnerException='{InnerException.GetType().Name}'" : "") +
        ")";
}
