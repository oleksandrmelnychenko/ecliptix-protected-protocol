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
    ErrorBufferTooSmall = 9,
    ErrorObjectDisposed = 10,
    ErrorPrepareLocal = 11,
    ErrorOutOfMemory = 12,
    ErrorSodiumFailure = 13,
    ErrorNullPointer = 14,
    ErrorInvalidState = 15,
    ErrorReplayAttack = 16,
    ErrorSessionExpired = 17,
    ErrorPqMissing = 19
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

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void EppProtocolEventCallback(uint connectionId, IntPtr userData);

[StructLayout(LayoutKind.Sequential)]
public struct EppCallbacks
{
    public EppProtocolEventCallback? OnProtocolStateChanged;
    public IntPtr UserData;
}
