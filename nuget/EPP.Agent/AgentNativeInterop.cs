using System.Runtime.InteropServices;
using EPP;

namespace EPP.Agent;

public static class AgentNativeInterop
{
    private const string LibraryName = "epp_agent";

    #region Version & Initialization

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr ecliptix_get_version();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_initialize();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_shutdown();

    #endregion

    #region Identity Keys

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_identity_keys_create(
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_identity_keys_create_from_seed(
        [In] byte[] seed,
        nuint seedLength,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern EppErrorCode ecliptix_identity_keys_create_from_seed_with_context(
        [In] byte[] seed,
        nuint seedLength,
        string accountId,
        nuint accountIdLength,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_identity_keys_get_public_x25519(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_identity_keys_get_public_ed25519(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_identity_keys_get_public_kyber(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_identity_keys_destroy(IntPtr handle);

    #endregion

    #region Protocol System

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_create(
        IntPtr identityKeys,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_set_callbacks(
        IntPtr handle,
        in EppCallbacks callbacks,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_begin_handshake_with_peer_kyber(
        IntPtr handle,
        uint connectionId,
        byte exchangeType,
        [In] byte[] peerKyberPublicKey,
        nuint peerKyberPublicKeyLength,
        IntPtr outHandshakeMessage,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_complete_handshake(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_complete_handshake_auto(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_send_message(
        IntPtr handle,
        [In] byte[] plaintext,
        nuint plaintextLength,
        IntPtr outEncryptedEnvelope,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_receive_message(
        IntPtr handle,
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        IntPtr outPlaintext,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_has_connection(
        IntPtr handle,
        out bool outHasConnection,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_get_connection_id(
        IntPtr handle,
        out uint outConnectionId,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_get_chain_indices(
        IntPtr handle,
        out uint outSendingIndex,
        out uint outReceivingIndex,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_get_selected_opk_id(
        IntPtr handle,
        [MarshalAs(UnmanagedType.I1)] out bool outHasOpkId,
        out uint outOpkId,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_create_from_root(
        IntPtr identityKeys,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        [In] byte[] peerBundle,
        nuint peerBundleLength,
        [MarshalAs(UnmanagedType.I1)] bool isInitiator,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_export_state(
        IntPtr handle,
        IntPtr outState,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_protocol_system_import_state(
        IntPtr identityKeys,
        [In] byte[] stateBytes,
        nuint stateBytesLength,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_protocol_system_destroy(IntPtr handle);

    #endregion

    #region Utilities

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_envelope_validate_hybrid_requirements(
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode ecliptix_derive_root_from_opaque_session_key(
        [In] byte[] opaqueSessionKey,
        nuint opaqueSessionKeyLength,
        [In] byte[] userContext,
        nuint userContextLength,
        [Out] byte[] outRootKey,
        nuint outRootKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ecliptix_buffer_allocate(nuint capacity);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_buffer_free(IntPtr buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ecliptix_error_free(ref EppError error);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr ecliptix_error_code_to_string(EppErrorCode code);

    #endregion

    #region Helper Methods

    public static string GetVersion()
    {
        IntPtr versionPtr = ecliptix_get_version();
        return Marshal.PtrToStringAnsi(versionPtr) ?? "unknown";
    }

    public static string ErrorCodeToString(EppErrorCode code)
    {
        IntPtr messagePtr = ecliptix_error_code_to_string(code);
        return Marshal.PtrToStringAnsi(messagePtr) ?? "unknown error";
    }

    #endregion
}
