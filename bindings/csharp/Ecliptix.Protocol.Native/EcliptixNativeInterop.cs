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

[StructLayout(LayoutKind.Sequential)]
public struct EcliptixBuffer
{
    public IntPtr Data;
    public nuint Length;
}

public enum EcliptixEnvelopeType
{
    Request = 0,
    Response = 1,
    Notification = 2,
    Heartbeat = 3,
    ErrorResponse = 4
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

[StructLayout(LayoutKind.Sequential)]
public struct EcliptixSessionConfig
{
    public uint MaxMessagesPerRatchet;
}

public static class EcliptixNativeInterop
{
#if ECLIPTIX_SERVER_NATIVE
    private const string LibraryName = "epp_relay";
#else
    private const string LibraryName = "epp_agent";
#endif

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr epp_version();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_init();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_shutdown();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_identity_create(
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_identity_create_from_seed(
        [In] byte[] seed,
        nuint seedLength,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern EcliptixErrorCode epp_identity_create_with_context(
        [In] byte[] seed,
        nuint seedLength,
        string membershipId,
        nuint membershipIdLength,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_identity_get_x25519_public(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_identity_get_ed25519_public(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_identity_get_kyber_public(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_identity_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_prekey_bundle_create(
        IntPtr identityKeys,
        out EcliptixBuffer outBundle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_handshake_initiator_start(
        IntPtr identityKeys,
        [In] byte[] peerPrekeyBundle,
        nuint peerPrekeyBundleLength,
        ref EcliptixSessionConfig config,
        out IntPtr outHandle,
        out EcliptixBuffer outHandshakeInit,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_handshake_initiator_finish(
        IntPtr handle,
        [In] byte[] handshakeAck,
        nuint handshakeAckLength,
        out IntPtr outSession,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_handshake_initiator_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_handshake_responder_start(
        IntPtr identityKeys,
        [In] byte[] localPrekeyBundle,
        nuint localPrekeyBundleLength,
        [In] byte[] handshakeInit,
        nuint handshakeInitLength,
        ref EcliptixSessionConfig config,
        out IntPtr outHandle,
        out EcliptixBuffer outHandshakeAck,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_handshake_responder_finish(
        IntPtr handle,
        out IntPtr outSession,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_handshake_responder_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_session_encrypt(
        IntPtr handle,
        [In] byte[] plaintext,
        nuint plaintextLength,
        EcliptixEnvelopeType envelopeType,
        uint envelopeId,
        [In] byte[]? correlationId,
        nuint correlationIdLength,
        out EcliptixBuffer outEncryptedEnvelope,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_session_decrypt(
        IntPtr handle,
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        out EcliptixBuffer outPlaintext,
        out EcliptixBuffer outMetadata,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_session_serialize(
        IntPtr handle,
        out EcliptixBuffer outState,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_session_deserialize(
        [In] byte[] stateBytes,
        nuint stateBytesLength,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_session_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_envelope_validate(
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_derive_root_key(
        [In] byte[] opaqueSessionKey,
        nuint opaqueSessionKeyLength,
        [In] byte[] userContext,
        nuint userContextLength,
        [Out] byte[] outRootKey,
        nuint outRootKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_shamir_split(
        [In] byte[] secret,
        nuint secretLength,
        byte threshold,
        byte shareCount,
        [In] byte[] authKey,
        nuint authKeyLength,
        out EcliptixBuffer outShares,
        out nuint outShareLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_shamir_reconstruct(
        [In] byte[] shares,
        nuint sharesLength,
        nuint shareLength,
        nuint shareCount,
        [In] byte[] authKey,
        nuint authKeyLength,
        out EcliptixBuffer outSecret,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_buffer_release(ref EcliptixBuffer buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr epp_buffer_alloc(nuint capacity);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_buffer_free(IntPtr buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void epp_error_free(ref EcliptixError error);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr epp_error_string(EcliptixErrorCode code);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixErrorCode epp_secure_wipe(
        IntPtr data,
        nuint length);
}
