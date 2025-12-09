using System;
using System.Runtime.InteropServices;

namespace Ecliptix.Protocol.Native;

public enum EcliptixErrorCode
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
    ErrorSessionExpired = 17
}

[StructLayout(LayoutKind.Sequential)]
public struct EcliptixBuffer
{
    public IntPtr Data;
    public nuint Length;
}

[StructLayout(LayoutKind.Sequential)]
public struct EcliptixError
{
    public EcliptixErrorCode Code;
    public IntPtr Message;

    public readonly string GetMessage()
    {
        return Message != IntPtr.Zero ? Marshal.PtrToStringAnsi(Message) ?? string.Empty : string.Empty;
    }
}

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void EcliptixProtocolEventCallback(uint connectionId, IntPtr userData);

[StructLayout(LayoutKind.Sequential)]
public struct EcliptixCallbacks
{
    public EcliptixProtocolEventCallback? OnProtocolStateChanged;
    public IntPtr UserData;
}

public static class EcliptixNativeInterop
{
    private const string LibraryName = "ecliptix_protocol";

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr ecliptix_get_version();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_initialize();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_shutdown();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_identity_keys_create(
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_identity_keys_create_from_seed(
        [In] byte[] seed,
        nuint seedLength,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_identity_keys_get_public_x25519(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_identity_keys_get_public_ed25519(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_identity_keys_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_create(
        IntPtr identityKeys,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_set_callbacks(
        IntPtr handle,
        in EcliptixCallbacks callbacks,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_send_message(
        IntPtr handle,
        [In] byte[] plaintext,
        nuint plaintextLength,
        out EcliptixBuffer outEncryptedEnvelope,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_receive_message(
        IntPtr handle,
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        out EcliptixBuffer outPlaintext,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_protocol_system_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ecliptix_buffer_allocate(nuint capacity);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_buffer_free(IntPtr buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_error_free(ref EcliptixError error);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr ecliptix_error_code_to_string(EcliptixErrorCode code);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_secure_wipe(
        [In, Out] byte[] data,
        nuint length);

    public static string GetVersion()
    {
        IntPtr versionPtr = ecliptix_get_version();
        return Marshal.PtrToStringAnsi(versionPtr) ?? "unknown";
    }

    public static string ErrorCodeToString(EcliptixErrorCode code)
    {
        IntPtr messagePtr = ecliptix_error_code_to_string(code);
        return Marshal.PtrToStringAnsi(messagePtr) ?? "unknown error";
    }
}
