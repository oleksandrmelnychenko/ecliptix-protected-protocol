using System.Runtime.InteropServices;
using EPP;

namespace EPP.Agent;

public static class AgentNativeInterop
{
    private const string LibraryName = "epp_agent";

    #region Version & Initialization

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr epp_version();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_init();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_shutdown();

    #endregion

    #region Identity Keys

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_identity_create(
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_identity_create_from_seed(
        [In] byte[] seed,
        nuint seedLength,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern EppErrorCode epp_identity_create_with_context(
        [In] byte[] seed,
        nuint seedLength,
        string accountId,
        nuint accountIdLength,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_identity_get_x25519_public(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_identity_get_ed25519_public(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_identity_get_kyber_public(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_identity_destroy(IntPtr handle);

    #endregion

    #region Protocol System

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_create(
        IntPtr identityKeys,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_set_callbacks(
        IntPtr handle,
        in EppCallbacks callbacks,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_begin_handshake(
        IntPtr handle,
        uint connectionId,
        byte exchangeType,
        [In] byte[] peerKyberPublicKey,
        nuint peerKyberPublicKeyLength,
        IntPtr outHandshakeMessage,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_complete_handshake(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_complete_handshake_auto(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_encrypt(
        IntPtr handle,
        [In] byte[] plaintext,
        nuint plaintextLength,
        IntPtr outEncryptedEnvelope,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_decrypt(
        IntPtr handle,
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        IntPtr outPlaintext,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_is_established(
        IntPtr handle,
        out bool outHasConnection,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_get_id(
        IntPtr handle,
        out uint outConnectionId,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_get_chain_indices(
        IntPtr handle,
        out uint outSendingIndex,
        out uint outReceivingIndex,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_get_used_prekey_id(
        IntPtr handle,
        [MarshalAs(UnmanagedType.I1)] out bool outHasOpkId,
        out uint outOpkId,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_create_from_root(
        IntPtr identityKeys,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        [In] byte[] peerBundle,
        nuint peerBundleLength,
        [MarshalAs(UnmanagedType.I1)] bool isInitiator,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_serialize(
        IntPtr handle,
        IntPtr outState,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_session_deserialize(
        IntPtr identityKeys,
        [In] byte[] stateBytes,
        nuint stateBytesLength,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_session_destroy(IntPtr handle);

    #endregion

    #region Utilities

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_envelope_validate(
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EppErrorCode epp_derive_root_key(
        [In] byte[] opaqueSessionKey,
        nuint opaqueSessionKeyLength,
        [In] byte[] userContext,
        nuint userContextLength,
        [Out] byte[] outRootKey,
        nuint outRootKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr epp_buffer_alloc(nuint capacity);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_buffer_free(IntPtr buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_error_free(ref EppError error);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr epp_error_string(EppErrorCode code);

    #endregion

    #region Helper Methods

    public static string GetVersion()
    {
        IntPtr versionPtr = epp_version();
        return Marshal.PtrToStringAnsi(versionPtr) ?? "unknown";
    }

    public static string ErrorCodeToString(EppErrorCode code)
    {
        IntPtr messagePtr = epp_error_string(code);
        return Marshal.PtrToStringAnsi(messagePtr) ?? "unknown error";
    }

    #endregion
}
