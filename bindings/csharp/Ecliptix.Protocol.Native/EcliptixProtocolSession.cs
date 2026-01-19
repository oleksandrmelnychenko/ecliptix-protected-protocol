using System;
using System.Runtime.InteropServices;
using System.Text;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures.EcliptixProtocol;

namespace Ecliptix.Protocol.Native;

public sealed class EcliptixIdentityKeys : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    public IntPtr Handle => _handle;
    public bool IsDisposed => _disposed;

    public static Result<EcliptixIdentityKeys, EcliptixProtocolFailure> Create()
    {
        EcliptixErrorCode result = EcliptixNativeInterop.epp_identity_create(
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Ok(new EcliptixIdentityKeys(handle));
    }

    public static Result<EcliptixIdentityKeys, EcliptixProtocolFailure> CreateFromSeed(byte[] seed)
    {
        if (seed == null)
        {
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Seed is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.epp_identity_create_from_seed(
            seed,
            (nuint)seed.Length,
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Ok(new EcliptixIdentityKeys(handle));
    }

    public static Result<EcliptixIdentityKeys, EcliptixProtocolFailure> CreateFromSeedWithContext(
        byte[] seed,
        string membershipId)
    {
        if (seed == null)
        {
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Seed is null"));
        }
        if (string.IsNullOrEmpty(membershipId))
        {
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Membership id is missing"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.epp_identity_create_with_context(
            seed,
            (nuint)seed.Length,
            membershipId,
            (nuint)membershipId.Length,
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Ok(new EcliptixIdentityKeys(handle));
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicX25519()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[32];
        EcliptixErrorCode result = EcliptixNativeInterop.epp_identity_get_x25519_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicEd25519()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[32];
        EcliptixErrorCode result = EcliptixNativeInterop.epp_identity_get_ed25519_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicKyber()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[1184];
        EcliptixErrorCode result = EcliptixNativeInterop.epp_identity_get_kyber_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], EcliptixProtocolFailure> CreatePreKeyBundle()
    {
        ThrowIfDisposed();

        EcliptixErrorCode result = EcliptixNativeInterop.epp_prekey_bundle_create(
            _handle,
            out EcliptixBuffer buffer,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return EcliptixInteropHelpers.CopyBuffer(ref buffer, "PreKey bundle");
    }

    private EcliptixIdentityKeys(IntPtr handle)
    {
        _handle = handle;
        _disposed = false;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcliptixIdentityKeys));
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
            EcliptixNativeInterop.epp_identity_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~EcliptixIdentityKeys()
    {
        Dispose();
    }
}

public sealed class EcliptixHandshakeInitiator : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    internal IntPtr Handle => _handle;

    public static Result<EcliptixHandshakeInitiatorStart, EcliptixProtocolFailure> Start(
        EcliptixIdentityKeys identityKeys,
        byte[] peerPreKeyBundle,
        uint maxMessagesPerChain)
    {
        if (identityKeys == null || identityKeys.IsDisposed)
        {
            return Result<EcliptixHandshakeInitiatorStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Identity keys are null or disposed"));
        }
        if (peerPreKeyBundle == null)
        {
            return Result<EcliptixHandshakeInitiatorStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Peer bundle is null"));
        }
        if (maxMessagesPerChain == 0)
        {
            return Result<EcliptixHandshakeInitiatorStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Max messages per chain must be greater than zero"));
        }

        EcliptixSessionConfig config = new()
        {
            MaxMessagesPerChain = maxMessagesPerChain
        };
        EcliptixErrorCode result = EcliptixNativeInterop.epp_handshake_initiator_start(
            identityKeys.Handle,
            peerPreKeyBundle,
            (nuint)peerPreKeyBundle.Length,
            ref config,
            out IntPtr handle,
            out EcliptixBuffer buffer,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<EcliptixHandshakeInitiatorStart, EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        var messageResult = EcliptixInteropHelpers.CopyBuffer(ref buffer, "Handshake init");
        if (messageResult.IsErr)
        {
            EcliptixNativeInterop.epp_handshake_initiator_destroy(handle);
            return Result<EcliptixHandshakeInitiatorStart, EcliptixProtocolFailure>.Err(messageResult.UnwrapErr());
        }

        var initiator = new EcliptixHandshakeInitiator(handle);
        return Result<EcliptixHandshakeInitiatorStart, EcliptixProtocolFailure>.Ok(
            new EcliptixHandshakeInitiatorStart(initiator, messageResult.Unwrap()));
    }

    public Result<EcliptixSession, EcliptixProtocolFailure> Finish(byte[] handshakeAck)
    {
        ThrowIfDisposed();

        if (handshakeAck == null)
        {
            return Result<EcliptixSession, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Handshake ack is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.epp_handshake_initiator_finish(
            _handle,
            handshakeAck,
            (nuint)handshakeAck.Length,
            out IntPtr sessionHandle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<EcliptixSession, EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        Dispose();
        return Result<EcliptixSession, EcliptixProtocolFailure>.Ok(new EcliptixSession(sessionHandle));
    }

    private EcliptixHandshakeInitiator(IntPtr handle)
    {
        _handle = handle;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcliptixHandshakeInitiator));
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
            EcliptixNativeInterop.epp_handshake_initiator_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~EcliptixHandshakeInitiator()
    {
        Dispose();
    }
}

public sealed class EcliptixHandshakeInitiatorStart
{
    public EcliptixHandshakeInitiator Initiator { get; }
    public byte[] HandshakeInit { get; }

    internal EcliptixHandshakeInitiatorStart(EcliptixHandshakeInitiator initiator, byte[] handshakeInit)
    {
        Initiator = initiator;
        HandshakeInit = handshakeInit;
    }
}

public sealed class EcliptixHandshakeResponder : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    internal IntPtr Handle => _handle;

    public static Result<EcliptixHandshakeResponderStart, EcliptixProtocolFailure> Start(
        EcliptixIdentityKeys identityKeys,
        byte[] localPreKeyBundle,
        byte[] handshakeInit,
        uint maxMessagesPerChain)
    {
        if (identityKeys == null || identityKeys.IsDisposed)
        {
            return Result<EcliptixHandshakeResponderStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Identity keys are null or disposed"));
        }
        if (localPreKeyBundle == null)
        {
            return Result<EcliptixHandshakeResponderStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Local bundle is null"));
        }
        if (handshakeInit == null)
        {
            return Result<EcliptixHandshakeResponderStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Handshake init is null"));
        }
        if (maxMessagesPerChain == 0)
        {
            return Result<EcliptixHandshakeResponderStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Max messages per chain must be greater than zero"));
        }

        EcliptixSessionConfig config = new()
        {
            MaxMessagesPerChain = maxMessagesPerChain
        };
        EcliptixErrorCode result = EcliptixNativeInterop.epp_handshake_responder_start(
            identityKeys.Handle,
            localPreKeyBundle,
            (nuint)localPreKeyBundle.Length,
            handshakeInit,
            (nuint)handshakeInit.Length,
            ref config,
            out IntPtr handle,
            out EcliptixBuffer buffer,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<EcliptixHandshakeResponderStart, EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        var messageResult = EcliptixInteropHelpers.CopyBuffer(ref buffer, "Handshake ack");
        if (messageResult.IsErr)
        {
            EcliptixNativeInterop.epp_handshake_responder_destroy(handle);
            return Result<EcliptixHandshakeResponderStart, EcliptixProtocolFailure>.Err(messageResult.UnwrapErr());
        }

        var responder = new EcliptixHandshakeResponder(handle);
        return Result<EcliptixHandshakeResponderStart, EcliptixProtocolFailure>.Ok(
            new EcliptixHandshakeResponderStart(responder, messageResult.Unwrap()));
    }

    public Result<EcliptixSession, EcliptixProtocolFailure> Finish()
    {
        ThrowIfDisposed();

        EcliptixErrorCode result = EcliptixNativeInterop.epp_handshake_responder_finish(
            _handle,
            out IntPtr sessionHandle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<EcliptixSession, EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        Dispose();
        return Result<EcliptixSession, EcliptixProtocolFailure>.Ok(new EcliptixSession(sessionHandle));
    }

    private EcliptixHandshakeResponder(IntPtr handle)
    {
        _handle = handle;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcliptixHandshakeResponder));
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
            EcliptixNativeInterop.epp_handshake_responder_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~EcliptixHandshakeResponder()
    {
        Dispose();
    }
}

public sealed class EcliptixHandshakeResponderStart
{
    public EcliptixHandshakeResponder Responder { get; }
    public byte[] HandshakeAck { get; }

    internal EcliptixHandshakeResponderStart(EcliptixHandshakeResponder responder, byte[] handshakeAck)
    {
        Responder = responder;
        HandshakeAck = handshakeAck;
    }
}

public sealed class EcliptixSession : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    internal IntPtr Handle => _handle;

    public static Result<EcliptixSession, EcliptixProtocolFailure> Deserialize(byte[] state)
    {
        if (state == null)
        {
            return Result<EcliptixSession, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("State bytes are null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.epp_session_deserialize(
            state,
            (nuint)state.Length,
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<EcliptixSession, EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<EcliptixSession, EcliptixProtocolFailure>.Ok(new EcliptixSession(handle));
    }

    public Result<byte[], EcliptixProtocolFailure> Encrypt(
        byte[] plaintext,
        EcliptixEnvelopeType envelopeType,
        uint envelopeId,
        string? correlationId = null)
    {
        ThrowIfDisposed();

        if (plaintext == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Plaintext is null"));
        }

        byte[]? correlationBytes = null;
        if (!string.IsNullOrEmpty(correlationId))
        {
            correlationBytes = Encoding.UTF8.GetBytes(correlationId);
        }

        EcliptixErrorCode result = EcliptixNativeInterop.epp_session_encrypt(
            _handle,
            plaintext,
            (nuint)plaintext.Length,
            envelopeType,
            envelopeId,
            correlationBytes,
            (nuint)(correlationBytes?.Length ?? 0),
            out EcliptixBuffer buffer,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return EcliptixInteropHelpers.CopyBuffer(ref buffer, "Encrypted envelope");
    }

    public Result<EcliptixSessionDecryptResult, EcliptixProtocolFailure> Decrypt(byte[] encryptedEnvelope)
    {
        ThrowIfDisposed();

        if (encryptedEnvelope == null)
        {
            return Result<EcliptixSessionDecryptResult, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Encrypted envelope is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.epp_session_decrypt(
            _handle,
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            out EcliptixBuffer plaintextBuffer,
            out EcliptixBuffer metadataBuffer,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<EcliptixSessionDecryptResult, EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        var plaintextResult = EcliptixInteropHelpers.CopyBuffer(ref plaintextBuffer, "Plaintext");
        if (plaintextResult.IsErr)
        {
            EcliptixNativeInterop.epp_buffer_release(ref metadataBuffer);
            return Result<EcliptixSessionDecryptResult, EcliptixProtocolFailure>.Err(plaintextResult.UnwrapErr());
        }

        var metadataResult = EcliptixInteropHelpers.CopyBuffer(ref metadataBuffer, "Metadata");
        if (metadataResult.IsErr)
        {
            return Result<EcliptixSessionDecryptResult, EcliptixProtocolFailure>.Err(metadataResult.UnwrapErr());
        }

        return Result<EcliptixSessionDecryptResult, EcliptixProtocolFailure>.Ok(
            new EcliptixSessionDecryptResult(plaintextResult.Unwrap(), metadataResult.Unwrap()));
    }

    public Result<byte[], EcliptixProtocolFailure> Serialize()
    {
        ThrowIfDisposed();

        EcliptixErrorCode result = EcliptixNativeInterop.epp_session_serialize(
            _handle,
            out EcliptixBuffer buffer,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return EcliptixInteropHelpers.CopyBuffer(ref buffer, "Session state");
    }

    private EcliptixSession(IntPtr handle)
    {
        _handle = handle;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcliptixSession));
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
            EcliptixNativeInterop.epp_session_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~EcliptixSession()
    {
        Dispose();
    }
}

public sealed class EcliptixSessionDecryptResult
{
    public byte[] Plaintext { get; }
    public byte[] Metadata { get; }

    internal EcliptixSessionDecryptResult(byte[] plaintext, byte[] metadata)
    {
        Plaintext = plaintext;
        Metadata = metadata;
    }
}

public static class EcliptixProtocolUtilities
{
    public static Result<Unit, EcliptixProtocolFailure> ValidateEnvelope(byte[] encryptedEnvelope)
    {
        if (encryptedEnvelope == null)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Encrypted envelope is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.epp_envelope_validate(
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public static Result<byte[], EcliptixProtocolFailure> DeriveRootKey(
        byte[] opaqueSessionKey,
        byte[] userContext)
    {
        if (opaqueSessionKey == null || opaqueSessionKey.Length == 0)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Opaque session key is null or empty"));
        }
        if (userContext == null || userContext.Length == 0)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("User context is null or empty"));
        }

        byte[] rootKey = new byte[32];
        EcliptixErrorCode result = EcliptixNativeInterop.epp_derive_root_key(
            opaqueSessionKey,
            (nuint)opaqueSessionKey.Length,
            userContext,
            (nuint)userContext.Length,
            rootKey,
            (nuint)rootKey.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(rootKey);
    }

    public static Result<EcliptixShamirSplitResult, EcliptixProtocolFailure> ShamirSplit(
        byte[] secret,
        byte threshold,
        byte shareCount,
        byte[] authKey)
    {
        if (secret == null || secret.Length == 0)
        {
            return Result<EcliptixShamirSplitResult, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Secret is null or empty"));
        }
        if (authKey == null)
        {
            return Result<EcliptixShamirSplitResult, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Auth key is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.epp_shamir_split(
            secret,
            (nuint)secret.Length,
            threshold,
            shareCount,
            authKey,
            (nuint)authKey.Length,
            out EcliptixBuffer sharesBuffer,
            out nuint shareLength,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<EcliptixShamirSplitResult, EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        var sharesResult = EcliptixInteropHelpers.CopyBuffer(ref sharesBuffer, "Shares");
        if (sharesResult.IsErr)
        {
            return Result<EcliptixShamirSplitResult, EcliptixProtocolFailure>.Err(sharesResult.UnwrapErr());
        }

        if (shareLength > int.MaxValue)
        {
            return Result<EcliptixShamirSplitResult, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Share length exceeds maximum array size"));
        }

        return Result<EcliptixShamirSplitResult, EcliptixProtocolFailure>.Ok(
            new EcliptixShamirSplitResult(sharesResult.Unwrap(), (int)shareLength));
    }

    public static Result<byte[], EcliptixProtocolFailure> ShamirReconstruct(
        byte[] shares,
        int shareLength,
        int shareCount,
        byte[] authKey)
    {
        if (shares == null || shares.Length == 0)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Shares are null or empty"));
        }
        if (shareLength <= 0 || shareCount <= 0)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Share length or count is invalid"));
        }
        if (authKey == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Auth key is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.epp_shamir_reconstruct(
            shares,
            (nuint)shares.Length,
            (nuint)shareLength,
            (nuint)shareCount,
            authKey,
            (nuint)authKey.Length,
            out EcliptixBuffer secretBuffer,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixInteropHelpers.ConvertError(result, errorMessage));
        }

        return EcliptixInteropHelpers.CopyBuffer(ref secretBuffer, "Secret");
    }
}

public sealed class EcliptixShamirSplitResult
{
    public byte[] Shares { get; }
    public int ShareLength { get; }

    internal EcliptixShamirSplitResult(byte[] shares, int shareLength)
    {
        Shares = shares;
        ShareLength = shareLength;
    }
}

internal static class EcliptixInteropHelpers
{
    public static Result<byte[], EcliptixProtocolFailure> CopyBuffer(ref EcliptixBuffer buffer, string label)
    {
        try
        {
            if (buffer.Length == 0)
            {
                return Result<byte[], EcliptixProtocolFailure>.Ok(Array.Empty<byte>());
            }
            if (buffer.Data == IntPtr.Zero)
            {
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput($"{label} buffer is null"));
            }
            if (buffer.Length > int.MaxValue)
            {
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput($"{label} length exceeds maximum array size"));
            }

            byte[] data = new byte[(int)buffer.Length];
            Marshal.Copy(buffer.Data, data, 0, data.Length);
            return Result<byte[], EcliptixProtocolFailure>.Ok(data);
        }
        finally
        {
            EcliptixNativeInterop.epp_buffer_release(ref buffer);
        }
    }

    public static EcliptixProtocolFailure ConvertError(EcliptixErrorCode code, string message)
    {
        return code switch
        {
            EcliptixErrorCode.ErrorInvalidInput => EcliptixProtocolFailure.InvalidInput(message),
            EcliptixErrorCode.ErrorKeyGeneration => EcliptixProtocolFailure.KeyGeneration(message),
            EcliptixErrorCode.ErrorDeriveKey => EcliptixProtocolFailure.DeriveKey(message),
            EcliptixErrorCode.ErrorHandshake => EcliptixProtocolFailure.Handshake(message),
            EcliptixErrorCode.ErrorEncryption => EcliptixProtocolFailure.Encryption(message),
            EcliptixErrorCode.ErrorDecryption => EcliptixProtocolFailure.Decryption(message),
            EcliptixErrorCode.ErrorDecode => EcliptixProtocolFailure.Decode(message),
            EcliptixErrorCode.ErrorEncode => EcliptixProtocolFailure.Decode(message),
            EcliptixErrorCode.ErrorBufferTooSmall => EcliptixProtocolFailure.BUFFER_TOO_SMALL(message),
            EcliptixErrorCode.ErrorObjectDisposed => EcliptixProtocolFailure.OBJECT_DISPOSED(message),
            EcliptixErrorCode.ErrorPrepareLocal => EcliptixProtocolFailure.PrepareLocal(message),
            EcliptixErrorCode.ErrorInvalidState => EcliptixProtocolFailure.Generic(message),
            EcliptixErrorCode.ErrorReplayAttack => EcliptixProtocolFailure.Generic(message),
            EcliptixErrorCode.ErrorSessionExpired => EcliptixProtocolFailure.Generic(message),
            EcliptixErrorCode.ErrorPqMissing => EcliptixProtocolFailure.InvalidInput(message),
            _ => EcliptixProtocolFailure.Generic(message)
        };
    }
}
