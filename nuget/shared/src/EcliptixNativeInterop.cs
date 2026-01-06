using System.Runtime.InteropServices;

#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server;
#else
namespace Ecliptix.Protocol.Client;
#endif

public enum EcliptixErrorCode
{
    SUCCESS = 0,
    ERROR_GENERIC = 1,
    ERROR_INVALID_INPUT = 2,
    ERROR_KEY_GENERATION = 3,
    ERROR_DERIVE_KEY = 4,
    ERROR_HANDSHAKE = 5,
    ERROR_ENCRYPTION = 6,
    ERROR_DECRYPTION = 7,
    ERROR_DECODE = 8,
    ERROR_BUFFER_TOO_SMALL = 9,
    ERROR_OBJECT_DISPOSED = 10,
    ERROR_PREPARE_LOCAL = 11,
    ERROR_OUT_OF_MEMORY = 12,
    ERROR_SODIUM_FAILURE = 13,
    ERROR_NULL_POINTER = 14,
    ERROR_INVALID_STATE = 15,
    ERROR_REPLAY_ATTACK = 16,
    ERROR_SESSION_EXPIRED = 17,
    ERROR_PQ_MISSING = 19
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

    public readonly string GetMessage() => Message != IntPtr.Zero ? Marshal.PtrToStringAnsi(Message) ?? string.Empty : string.Empty;
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
#if ECLIPTIX_SERVER
    private const string LIBRARY_NAME = "ecliptix_protocol_server";
#else
    private const string LIBRARY_NAME = "ecliptix_protocol";
#endif

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr ecliptix_get_version();

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_initialize();

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_shutdown();

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_identity_keys_create(
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_identity_keys_create_from_seed(
        [In] byte[] seed,
        nuint seedLength,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern EcliptixErrorCode ecliptix_identity_keys_create_from_seed_with_context(
        [In] byte[] seed,
        nuint seedLength,
        string accountId,
        nuint accountIdLength,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_identity_keys_get_public_x25519(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_identity_keys_get_public_ed25519(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_identity_keys_get_public_kyber(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_identity_keys_destroy(IntPtr handle);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_create(
        IntPtr identityKeys,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_set_callbacks(
        IntPtr handle,
        in EcliptixCallbacks callbacks,
        out EcliptixError outError);

    // NOTE: ecliptix_protocol_system_begin_handshake (without Kyber) has been removed.
    // Post-quantum Kyber cryptography is now MANDATORY for all handshakes.
    // Use ecliptix_protocol_system_begin_handshake_with_peer_kyber instead.

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_begin_handshake_with_peer_kyber(
        IntPtr handle,
        uint connectionId,
        byte exchangeType,
        [In] byte[] peerKyberPublicKey,
        nuint peerKyberPublicKeyLength,
        IntPtr outHandshakeMessage,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_complete_handshake(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_complete_handshake_auto(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_send_message(
        IntPtr handle,
        [In] byte[] plaintext,
        nuint plaintextLength,
        IntPtr outEncryptedEnvelope,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_has_connection(
        IntPtr handle,
        out bool outHasConnection,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_get_connection_id(
        IntPtr handle,
        out uint outConnectionId,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_get_chain_indices(
        IntPtr handle,
        out uint outSendingIndex,
        out uint outReceivingIndex,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_get_selected_opk_id(
        IntPtr handle,
        [MarshalAs(UnmanagedType.I1)] out bool outHasOpkId,
        out uint outOpkId,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_receive_message(
        IntPtr handle,
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        IntPtr outPlaintext,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_create_from_root(
        IntPtr identityKeys,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        [In] byte[] peerBundle,
        nuint peerBundleLength,
        [MarshalAs(UnmanagedType.I1)] bool isInitiator,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_export_state(
        IntPtr handle,
        IntPtr outState,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_protocol_system_import_state(
        IntPtr identityKeys,
        [In] byte[] stateBytes,
        nuint stateBytesLength,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_envelope_validate_hybrid_requirements(
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode ecliptix_derive_root_from_opaque_session_key(
        [In] byte[] opaqueSessionKey,
        nuint opaqueSessionKeyLength,
        [In] byte[] userContext,
        nuint userContextLength,
        [Out] byte[] outRootKey,
        nuint outRootKeyLength,
        out EcliptixError outError);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_protocol_system_destroy(IntPtr handle);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ecliptix_buffer_allocate(nuint capacity);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_buffer_free(IntPtr buffer);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_error_free(ref EcliptixError error);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
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
