using System;
using System.Runtime.InteropServices;
using System.Text;
using EPP;

namespace EPP.Native;

public sealed class IdentityKeys : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    public IntPtr Handle => _handle;
    public bool IsDisposed => _disposed;

    public static Result<IdentityKeys, ProtocolFailure> Create()
    {
        EppErrorCode result = NativeInterop.epp_identity_create(
            out IntPtr handle,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<IdentityKeys, ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<IdentityKeys, ProtocolFailure>.Ok(new IdentityKeys(handle));
    }

    public static Result<IdentityKeys, ProtocolFailure> CreateFromSeed(byte[] seed)
    {
        if (seed == null)
        {
            return Result<IdentityKeys, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Seed is null"));
        }

        EppErrorCode result = NativeInterop.epp_identity_create_from_seed(
            seed,
            (nuint)seed.Length,
            out IntPtr handle,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<IdentityKeys, ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<IdentityKeys, ProtocolFailure>.Ok(new IdentityKeys(handle));
    }

    public static Result<IdentityKeys, ProtocolFailure> CreateFromSeedWithContext(
        byte[] seed,
        string membershipId)
    {
        if (seed == null)
        {
            return Result<IdentityKeys, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Seed is null"));
        }
        if (string.IsNullOrEmpty(membershipId))
        {
            return Result<IdentityKeys, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Membership ID is missing"));
        }

        EppErrorCode result = NativeInterop.epp_identity_create_with_context(
            seed,
            (nuint)seed.Length,
            membershipId,
            (nuint)membershipId.Length,
            out IntPtr handle,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<IdentityKeys, ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<IdentityKeys, ProtocolFailure>.Ok(new IdentityKeys(handle));
    }

    public Result<byte[], ProtocolFailure> GetPublicX25519()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[32];
        EppErrorCode result = NativeInterop.epp_identity_get_x25519_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<byte[], ProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], ProtocolFailure> GetPublicEd25519()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[32];
        EppErrorCode result = NativeInterop.epp_identity_get_ed25519_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<byte[], ProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], ProtocolFailure> GetPublicKyber()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[1184];
        EppErrorCode result = NativeInterop.epp_identity_get_kyber_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<byte[], ProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], ProtocolFailure> CreatePreKeyBundle()
    {
        ThrowIfDisposed();

        EppErrorCode result = NativeInterop.epp_prekey_bundle_create(
            _handle,
            out EppBuffer buffer,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return InteropHelpers.CopyBuffer(ref buffer, "PreKey bundle");
    }

    private IdentityKeys(IntPtr handle)
    {
        _handle = handle;
        _disposed = false;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(IdentityKeys));
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_handle != IntPtr.Zero)
        {
            NativeInterop.epp_identity_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~IdentityKeys()
    {
        Dispose();
    }
}

#if !ECLIPTIX_SERVER_NATIVE
public sealed class HandshakeInitiator : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    internal IntPtr Handle => _handle;

    public static Result<HandshakeInitiatorStart, ProtocolFailure> Start(
        IdentityKeys identityKeys,
        byte[] peerPreKeyBundle,
        uint maxMessagesPerChain)
    {
        if (identityKeys == null || identityKeys.IsDisposed)
        {
            return Result<HandshakeInitiatorStart, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Identity keys are null or disposed"));
        }
        if (peerPreKeyBundle == null)
        {
            return Result<HandshakeInitiatorStart, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Peer bundle is null"));
        }
        if (maxMessagesPerChain == 0)
        {
            return Result<HandshakeInitiatorStart, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Max messages per chain must be greater than zero"));
        }

        EppSessionConfig config = new()
        {
            MaxMessagesPerChain = maxMessagesPerChain
        };
        EppErrorCode result = NativeInterop.epp_handshake_initiator_start(
            identityKeys.Handle,
            peerPreKeyBundle,
            (nuint)peerPreKeyBundle.Length,
            ref config,
            out IntPtr handle,
            out EppBuffer buffer,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<HandshakeInitiatorStart, ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        var messageResult = InteropHelpers.CopyBuffer(ref buffer, "Handshake init");
        if (messageResult.IsErr)
        {
            NativeInterop.epp_handshake_initiator_destroy(handle);
            return Result<HandshakeInitiatorStart, ProtocolFailure>.Err(messageResult.UnwrapErr());
        }

        var initiator = new HandshakeInitiator(handle);
        return Result<HandshakeInitiatorStart, ProtocolFailure>.Ok(
            new HandshakeInitiatorStart(initiator, messageResult.Unwrap()));
    }

    public Result<Session, ProtocolFailure> Finish(byte[] handshakeAck)
    {
        ThrowIfDisposed();

        if (handshakeAck == null)
        {
            return Result<Session, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Handshake ack is null"));
        }

        EppErrorCode result = NativeInterop.epp_handshake_initiator_finish(
            _handle,
            handshakeAck,
            (nuint)handshakeAck.Length,
            out IntPtr sessionHandle,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<Session, ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        Dispose();
        return Result<Session, ProtocolFailure>.Ok(new Session(sessionHandle));
    }

    private HandshakeInitiator(IntPtr handle)
    {
        _handle = handle;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(HandshakeInitiator));
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_handle != IntPtr.Zero)
        {
            NativeInterop.epp_handshake_initiator_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~HandshakeInitiator()
    {
        Dispose();
    }
}

public sealed class HandshakeInitiatorStart
{
    public HandshakeInitiator Initiator { get; }
    public byte[] HandshakeInit { get; }

    internal HandshakeInitiatorStart(HandshakeInitiator initiator, byte[] handshakeInit)
    {
        Initiator = initiator;
        HandshakeInit = handshakeInit;
    }
}
#endif

public sealed class HandshakeResponder : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    internal IntPtr Handle => _handle;

    public static Result<HandshakeResponderStart, ProtocolFailure> Start(
        IdentityKeys identityKeys,
        byte[] localPreKeyBundle,
        byte[] handshakeInit,
        uint maxMessagesPerChain)
    {
        if (identityKeys == null || identityKeys.IsDisposed)
        {
            return Result<HandshakeResponderStart, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Identity keys are null or disposed"));
        }
        if (localPreKeyBundle == null)
        {
            return Result<HandshakeResponderStart, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Local bundle is null"));
        }
        if (handshakeInit == null)
        {
            return Result<HandshakeResponderStart, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Handshake init is null"));
        }
        if (maxMessagesPerChain == 0)
        {
            return Result<HandshakeResponderStart, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Max messages per chain must be greater than zero"));
        }

        EppSessionConfig config = new()
        {
            MaxMessagesPerChain = maxMessagesPerChain
        };
        EppErrorCode result = NativeInterop.epp_handshake_responder_start(
            identityKeys.Handle,
            localPreKeyBundle,
            (nuint)localPreKeyBundle.Length,
            handshakeInit,
            (nuint)handshakeInit.Length,
            ref config,
            out IntPtr handle,
            out EppBuffer buffer,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<HandshakeResponderStart, ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        var messageResult = InteropHelpers.CopyBuffer(ref buffer, "Handshake ack");
        if (messageResult.IsErr)
        {
            NativeInterop.epp_handshake_responder_destroy(handle);
            return Result<HandshakeResponderStart, ProtocolFailure>.Err(messageResult.UnwrapErr());
        }

        var responder = new HandshakeResponder(handle);
        return Result<HandshakeResponderStart, ProtocolFailure>.Ok(
            new HandshakeResponderStart(responder, messageResult.Unwrap()));
    }

    public Result<Session, ProtocolFailure> Finish()
    {
        ThrowIfDisposed();

        EppErrorCode result = NativeInterop.epp_handshake_responder_finish(
            _handle,
            out IntPtr sessionHandle,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<Session, ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        Dispose();
        return Result<Session, ProtocolFailure>.Ok(new Session(sessionHandle));
    }

    private HandshakeResponder(IntPtr handle)
    {
        _handle = handle;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(HandshakeResponder));
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_handle != IntPtr.Zero)
        {
            NativeInterop.epp_handshake_responder_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~HandshakeResponder()
    {
        Dispose();
    }
}

public sealed class HandshakeResponderStart
{
    public HandshakeResponder Responder { get; }
    public byte[] HandshakeAck { get; }

    internal HandshakeResponderStart(HandshakeResponder responder, byte[] handshakeAck)
    {
        Responder = responder;
        HandshakeAck = handshakeAck;
    }
}

public sealed class Session : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    internal IntPtr Handle => _handle;

    public static Result<Session, ProtocolFailure> Deserialize(byte[] state)
    {
        if (state == null)
        {
            return Result<Session, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("State bytes are null"));
        }

        EppErrorCode result = NativeInterop.epp_session_deserialize(
            state,
            (nuint)state.Length,
            out IntPtr handle,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<Session, ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<Session, ProtocolFailure>.Ok(new Session(handle));
    }

    public Result<byte[], ProtocolFailure> Encrypt(
        byte[] plaintext,
        EppEnvelopeType envelopeType,
        uint envelopeId,
        string? correlationId = null)
    {
        ThrowIfDisposed();

        if (plaintext == null)
        {
            return Result<byte[], ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Plaintext is null"));
        }

        byte[]? correlationBytes = null;
        if (!string.IsNullOrEmpty(correlationId))
        {
            correlationBytes = Encoding.UTF8.GetBytes(correlationId);
        }

        EppErrorCode result = NativeInterop.epp_session_encrypt(
            _handle,
            plaintext,
            (nuint)plaintext.Length,
            envelopeType,
            envelopeId,
            correlationBytes,
            (nuint)(correlationBytes?.Length ?? 0),
            out EppBuffer buffer,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return InteropHelpers.CopyBuffer(ref buffer, "Encrypted envelope");
    }

    public Result<SessionDecryptResult, ProtocolFailure> Decrypt(byte[] encryptedEnvelope)
    {
        ThrowIfDisposed();

        if (encryptedEnvelope == null)
        {
            return Result<SessionDecryptResult, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Encrypted envelope is null"));
        }

        EppErrorCode result = NativeInterop.epp_session_decrypt(
            _handle,
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            out EppBuffer plaintextBuffer,
            out EppBuffer metadataBuffer,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<SessionDecryptResult, ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        var plaintextResult = InteropHelpers.CopyBuffer(ref plaintextBuffer, "Plaintext");
        if (plaintextResult.IsErr)
        {
            NativeInterop.epp_buffer_release(ref metadataBuffer);
            return Result<SessionDecryptResult, ProtocolFailure>.Err(plaintextResult.UnwrapErr());
        }

        var metadataResult = InteropHelpers.CopyBuffer(ref metadataBuffer, "Metadata");
        if (metadataResult.IsErr)
        {
            return Result<SessionDecryptResult, ProtocolFailure>.Err(metadataResult.UnwrapErr());
        }

        return Result<SessionDecryptResult, ProtocolFailure>.Ok(
            new SessionDecryptResult(plaintextResult.Unwrap(), metadataResult.Unwrap()));
    }

    public Result<byte[], ProtocolFailure> Serialize()
    {
        ThrowIfDisposed();

        EppErrorCode result = NativeInterop.epp_session_serialize(
            _handle,
            out EppBuffer buffer,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return InteropHelpers.CopyBuffer(ref buffer, "Session state");
    }

    private Session(IntPtr handle)
    {
        _handle = handle;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(Session));
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_handle != IntPtr.Zero)
        {
            NativeInterop.epp_session_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~Session()
    {
        Dispose();
    }
}

public sealed class SessionDecryptResult
{
    public byte[] Plaintext { get; }
    public byte[] Metadata { get; }

    internal SessionDecryptResult(byte[] plaintext, byte[] metadata)
    {
        Plaintext = plaintext;
        Metadata = metadata;
    }
}

public static class ProtocolUtilities
{
    public static Result<Unit, ProtocolFailure> ValidateEnvelope(byte[] encryptedEnvelope)
    {
        if (encryptedEnvelope == null)
        {
            return Result<Unit, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Encrypted envelope is null"));
        }

        EppErrorCode result = NativeInterop.epp_envelope_validate(
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<Unit, ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<Unit, ProtocolFailure>.Ok(Unit.Value);
    }

    public static Result<byte[], ProtocolFailure> DeriveRootKey(
        byte[] opaqueSessionKey,
        byte[] userContext)
    {
        if (opaqueSessionKey == null || opaqueSessionKey.Length == 0)
        {
            return Result<byte[], ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Opaque session key is null or empty"));
        }
        if (userContext == null || userContext.Length == 0)
        {
            return Result<byte[], ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("User context is null or empty"));
        }

        byte[] rootKey = new byte[32];
        EppErrorCode result = NativeInterop.epp_derive_root_key(
            opaqueSessionKey,
            (nuint)opaqueSessionKey.Length,
            userContext,
            (nuint)userContext.Length,
            rootKey,
            (nuint)rootKey.Length,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<byte[], ProtocolFailure>.Ok(rootKey);
    }

    public static Result<ShamirSplitResult, ProtocolFailure> ShamirSplit(
        byte[] secret,
        byte threshold,
        byte shareCount,
        byte[] authKey)
    {
        if (secret == null || secret.Length == 0)
        {
            return Result<ShamirSplitResult, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Secret is null or empty"));
        }
        if (authKey == null)
        {
            return Result<ShamirSplitResult, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Auth key is null"));
        }

        EppErrorCode result = NativeInterop.epp_shamir_split(
            secret,
            (nuint)secret.Length,
            threshold,
            shareCount,
            authKey,
            (nuint)authKey.Length,
            out EppBuffer sharesBuffer,
            out nuint shareLength,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<ShamirSplitResult, ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        var sharesResult = InteropHelpers.CopyBuffer(ref sharesBuffer, "Shares");
        if (sharesResult.IsErr)
        {
            return Result<ShamirSplitResult, ProtocolFailure>.Err(sharesResult.UnwrapErr());
        }

        if (shareLength > int.MaxValue)
        {
            return Result<ShamirSplitResult, ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Share length exceeds maximum array size"));
        }

        return Result<ShamirSplitResult, ProtocolFailure>.Ok(
            new ShamirSplitResult(sharesResult.Unwrap(), (int)shareLength));
    }

    public static Result<byte[], ProtocolFailure> ShamirReconstruct(
        byte[] shares,
        int shareLength,
        int shareCount,
        byte[] authKey)
    {
        if (shares == null || shares.Length == 0)
        {
            return Result<byte[], ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Shares are null or empty"));
        }
        if (shareLength <= 0 || shareCount <= 0)
        {
            return Result<byte[], ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Share length or count is invalid"));
        }
        if (authKey == null)
        {
            return Result<byte[], ProtocolFailure>.Err(
                ProtocolFailure.InvalidInput("Auth key is null"));
        }

        EppErrorCode result = NativeInterop.epp_shamir_reconstruct(
            shares,
            (nuint)shares.Length,
            (nuint)shareLength,
            (nuint)shareCount,
            authKey,
            (nuint)authKey.Length,
            out EppBuffer secretBuffer,
            out EppError error);

        if (result != EppErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], ProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, errorMessage));
        }

        return InteropHelpers.CopyBuffer(ref secretBuffer, "Secret");
    }
}

public sealed class ShamirSplitResult
{
    public byte[] Shares { get; }
    public int ShareLength { get; }

    internal ShamirSplitResult(byte[] shares, int shareLength)
    {
        Shares = shares;
        ShareLength = shareLength;
    }
}

internal static class InteropHelpers
{
    public static Result<byte[], ProtocolFailure> CopyBuffer(ref EppBuffer buffer, string label)
    {
        try
        {
            if (buffer.Length == 0)
            {
                return Result<byte[], ProtocolFailure>.Ok(Array.Empty<byte>());
            }
            if (buffer.Data == IntPtr.Zero)
            {
                return Result<byte[], ProtocolFailure>.Err(
                    ProtocolFailure.InvalidInput($"{label} buffer is null"));
            }
            if (buffer.Length > int.MaxValue)
            {
                return Result<byte[], ProtocolFailure>.Err(
                    ProtocolFailure.InvalidInput($"{label} length exceeds maximum array size"));
            }

            byte[] data = new byte[(int)buffer.Length];
            Marshal.Copy(buffer.Data, data, 0, data.Length);
            return Result<byte[], ProtocolFailure>.Ok(data);
        }
        finally
        {
            NativeInterop.epp_buffer_release(ref buffer);
        }
    }

    public static ProtocolFailure ConvertError(EppErrorCode code, string message)
    {
        return code switch
        {
            EppErrorCode.ErrorInvalidInput => ProtocolFailure.InvalidInput(message),
            EppErrorCode.ErrorKeyGeneration => ProtocolFailure.KeyGeneration(message),
            EppErrorCode.ErrorDeriveKey => ProtocolFailure.DeriveKey(message),
            EppErrorCode.ErrorHandshake => ProtocolFailure.Handshake(message),
            EppErrorCode.ErrorEncryption => ProtocolFailure.Encryption(message),
            EppErrorCode.ErrorDecryption => ProtocolFailure.Decryption(message),
            EppErrorCode.ErrorDecode => ProtocolFailure.Decode(message),
            EppErrorCode.ErrorEncode => ProtocolFailure.Encode(message),
            EppErrorCode.ErrorBufferTooSmall => ProtocolFailure.BufferTooSmall(message),
            EppErrorCode.ErrorObjectDisposed => ProtocolFailure.ObjectDisposed(message),
            EppErrorCode.ErrorPrepareLocal => ProtocolFailure.PrepareLocal(message),
            EppErrorCode.ErrorOutOfMemory => ProtocolFailure.OutOfMemory(message),
            EppErrorCode.ErrorSodiumFailure => ProtocolFailure.SodiumFailure(message),
            EppErrorCode.ErrorNullPointer => ProtocolFailure.NullPointer(message),
            EppErrorCode.ErrorInvalidState => ProtocolFailure.InvalidState(message),
            EppErrorCode.ErrorReplayAttack => ProtocolFailure.ReplayAttack(message),
            EppErrorCode.ErrorSessionExpired => ProtocolFailure.SessionExpired(message),
            EppErrorCode.ErrorPqMissing => ProtocolFailure.PqMissing(message),
            _ => ProtocolFailure.Generic(message)
        };
    }
}
