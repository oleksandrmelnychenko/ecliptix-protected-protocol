using System.Runtime.InteropServices;

namespace EPP;

public enum EppErrorCode
{
    Success = 0,
    ErrorGeneric = 1,
    ErrorInvalidInput = 2,
    ErrorKeyGeneration = 3,
    ErrorDeriveKey = 4,
    ErrorHandshake = 5,
    ErrorEncryption = 6,
    ErrorDecryption = 7,
    ErrorDecode = 8,
    ErrorEncode = 9,
    ErrorBufferTooSmall = 10,
    ErrorObjectDisposed = 11,
    ErrorPrepareLocal = 12,
    ErrorOutOfMemory = 13,
    ErrorSodiumFailure = 14,
    ErrorNullPointer = 15,
    ErrorInvalidState = 16,
    ErrorReplayAttack = 17,
    ErrorSessionExpired = 18,
    ErrorPqMissing = 19
}

public enum EppEnvelopeType
{
    Request = 0,
    Response = 1,
    Notification = 2,
    Heartbeat = 3,
    ErrorResponse = 4
}

[StructLayout(LayoutKind.Sequential)]
public struct EppBuffer
{
    public IntPtr Data;
    public nuint Length;
}

[StructLayout(LayoutKind.Sequential)]
public struct EppError
{
    public EppErrorCode Code;
    public IntPtr Message;

    public readonly string GetMessage() => Message != IntPtr.Zero ? Marshal.PtrToStringAnsi(Message) ?? string.Empty : string.Empty;
}

[StructLayout(LayoutKind.Sequential)]
public struct EppSessionConfig
{
    public uint MaxMessagesPerRatchet;
}
