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
    ErrorSessionExpired = 17,
    ErrorPqMissing = 19
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
#if ECLIPTIX_SERVER_NATIVE
    // Warning: the server target does not export the C API. Only enable this
    // if you are shipping a client build that happens to be named like the server
    // artifact. Default is the client library name.
    private const string LibraryName = "ecliptix_protocol_server";
#else
    private const string LibraryName = "ecliptix_protocol";
#endif

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

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern EcliptixErrorCode ecliptix_identity_keys_create_from_seed_with_context(
        [In] byte[] seed,
        nuint seedLength,
        string membershipId,
        nuint membershipIdLength,
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

    // NOTE: ecliptix_protocol_system_begin_handshake (without Kyber) has been removed.
    // Post-quantum Kyber cryptography is now MANDATORY for all handshakes.
    // Use ecliptix_protocol_system_begin_handshake_with_peer_kyber instead.

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_begin_handshake_with_peer_kyber(
        IntPtr handle,
        uint connectionId,
        byte exchangeType,
        [In] byte[] peerKyberPublicKey,
        nuint peerKyberPublicKeyLength,
        out EcliptixBuffer outHandshakeMessage,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_complete_handshake(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_complete_handshake_auto(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_send_message(
        IntPtr handle,
        [In] byte[] plaintext,
        nuint plaintextLength,
        out EcliptixBuffer outEncryptedEnvelope,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_has_connection(
        IntPtr handle,
        out bool outHasConnection,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_get_connection_id(
        IntPtr handle,
        out uint outConnectionId,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_get_selected_opk_id(
        IntPtr handle,
        [MarshalAs(UnmanagedType.I1)] out bool outHasOpkId,
        out uint outOpkId,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_connection_get_session_age_seconds(
        IntPtr handle,
        out ulong outAgeSeconds,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_set_kyber_secrets(
        IntPtr handle,
        [In] byte[] kyberCiphertext,
        nuint kyberCiphertextLength,
        [In] byte[] kyberSharedSecret,
        nuint kyberSharedSecretLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_receive_message(
        IntPtr handle,
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        out EcliptixBuffer outPlaintext,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_create_from_root(
        IntPtr identityKeys,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        [In] byte[] peerBundle,
        nuint peerBundleLength,
        [MarshalAs(UnmanagedType.I1)] bool isInitiator,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_export_state(
        IntPtr handle,
        out EcliptixBuffer outState,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_import_state(
        IntPtr identityKeys,
        [In] byte[] stateBytes,
        nuint stateBytesLength,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_envelope_validate_hybrid_requirements(
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_derive_root_from_opaque_session_key(
        [In] byte[] opaqueSessionKey,
        nuint opaqueSessionKeyLength,
        [In] byte[] userContext,
        nuint userContextLength,
        [Out] byte[] outRootKey,
        nuint outRootKeyLength,
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
