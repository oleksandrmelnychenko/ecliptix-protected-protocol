using System.Runtime.InteropServices;

namespace Ecliptix.Protocol.Server;

public sealed class EcliptixProtocolSystemWrapper : IDisposable
{
    private IntPtr _handle;
    private readonly EcliptixIdentityKeysWrapper _identityKeys;
    private bool _disposed;
    private GCHandle _callbackHandle;
    private EcliptixCallbacks _callbacks;

    public static Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure> Create(
        EcliptixIdentityKeysWrapper identityKeys)
    {
        if (identityKeys == null || identityKeys.IsDisposed)
        {
            return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Identity keys are null or disposed"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_server_system_create(
            identityKeys.Handle,
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Ok(
            new EcliptixProtocolSystemWrapper(handle, identityKeys));
    }

    private EcliptixProtocolSystemWrapper(IntPtr handle, EcliptixIdentityKeysWrapper identityKeys)
    {
        _handle = handle;
        _identityKeys = identityKeys;
        _disposed = false;
    }

    public void SetEventHandler(Action<uint>? onProtocolStateChanged)
    {
        ThrowIfDisposed();

        if (_callbackHandle.IsAllocated)
        {
            _callbackHandle.Free();
        }

        if (onProtocolStateChanged != null)
        {
            EcliptixProtocolEventCallback callback = (connectionId, _) =>
            {
                onProtocolStateChanged(connectionId);
            };

            _callbackHandle = GCHandle.Alloc(callback);

            _callbacks = new EcliptixCallbacks
            {
                OnProtocolStateChanged = callback,
                UserData = IntPtr.Zero
            };

            EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_server_system_set_callbacks(
                _handle,
                in _callbacks,
                out EcliptixError error);

            if (result != EcliptixErrorCode.Success)
            {
                string errorMessage = error.GetMessage();
                EcliptixNativeInterop.ecliptix_error_free(ref error);

                _callbackHandle.Free();
                throw new InvalidOperationException($"Failed to set callbacks: {errorMessage}");
            }
        }
        else
        {
            _callbacks = new EcliptixCallbacks
            {
                OnProtocolStateChanged = null,
                UserData = IntPtr.Zero
            };

            EcliptixNativeInterop.ecliptix_protocol_server_system_set_callbacks(
                _handle,
                in _callbacks,
                out _);
        }
    }

    public Result<byte[], EcliptixProtocolFailure> SendMessage(byte[] plaintext)
    {
        ThrowIfDisposed();

        if (plaintext == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Plaintext is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_server_system_send_message(
            _handle,
            plaintext,
            (nuint)plaintext.Length,
            out EcliptixBuffer buffer,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        try
        {
            byte[] encrypted = new byte[buffer.Length];
            Marshal.Copy(buffer.Data, encrypted, 0, (int)buffer.Length);
            return Result<byte[], EcliptixProtocolFailure>.Ok(encrypted);
        }
        finally
        {
            if (buffer.Data != IntPtr.Zero)
            {
                EcliptixNativeInterop.ecliptix_buffer_free(buffer.Data);
            }
        }
    }

    public Result<byte[], EcliptixProtocolFailure> ReceiveMessage(byte[] encryptedEnvelope)
    {
        ThrowIfDisposed();

        if (encryptedEnvelope == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Encrypted envelope is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_server_system_receive_message(
            _handle,
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            out EcliptixBuffer buffer,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        try
        {
            byte[] plaintext = new byte[buffer.Length];
            Marshal.Copy(buffer.Data, plaintext, 0, (int)buffer.Length);
            return Result<byte[], EcliptixProtocolFailure>.Ok(plaintext);
        }
        finally
        {
            if (buffer.Data != IntPtr.Zero)
            {
                EcliptixNativeInterop.ecliptix_buffer_free(buffer.Data);
            }
        }
    }

    public Result<uint, EcliptixProtocolFailure> GetConnectionId()
    {
        ThrowIfDisposed();

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_server_system_get_connection_id(
            _handle,
            out uint connectionId,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<uint, EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        return Result<uint, EcliptixProtocolFailure>.Ok(connectionId);
    }

    /// <summary>
    /// Returns the session age in seconds since creation.
    /// </summary>
    public Result<ulong, EcliptixProtocolFailure> GetSessionAgeSeconds()
    {
        ThrowIfDisposed();

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_connection_get_session_age_seconds(
            _handle,
            out ulong ageSeconds,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<ulong, EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        return Result<ulong, EcliptixProtocolFailure>.Ok(ageSeconds);
    }

    /// <summary>
    /// Set Kyber hybrid handshake secrets on the active connection.
    /// </summary>
    public Result<Unit, EcliptixProtocolFailure> SetKyberSecrets(byte[] kyberCiphertext, byte[] kyberSharedSecret)
    {
        ThrowIfDisposed();

        if (kyberCiphertext == null || kyberCiphertext.Length == 0)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Kyber ciphertext is null or empty"));
        }
        if (kyberSharedSecret == null || kyberSharedSecret.Length == 0)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Kyber shared secret is null or empty"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_server_system_set_kyber_secrets(
            _handle,
            kyberCiphertext,
            (nuint)kyberCiphertext.Length,
            kyberSharedSecret,
            (nuint)kyberSharedSecret.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public EcliptixIdentityKeysWrapper GetIdentityKeys() => _identityKeys;

    public static Result<Unit, EcliptixProtocolFailure> ValidateEnvelopeHybridRequirements(byte[] encryptedEnvelope)
    {
        if (encryptedEnvelope == null)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Encrypted envelope is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_envelope_validate_hybrid_requirements(
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public static Result<byte[], EcliptixProtocolFailure> DeriveRootFromOpaqueSessionKey(
        byte[] opaqueSessionKey,
        byte[] userContext)
    {
        if (opaqueSessionKey == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("OPAQUE session key is null"));
        }
        if (userContext == null || userContext.Length == 0)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("OPAQUE user context is missing"));
        }

        byte[] rootKey = new byte[32];
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_derive_root_from_opaque_session_key(
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
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(rootKey);
    }

    private static EcliptixProtocolFailure ConvertError(EcliptixErrorCode code, string message)
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
            EcliptixErrorCode.ErrorPqMissing => EcliptixProtocolFailure.PqMissing(message),
            EcliptixErrorCode.ErrorBufferTooSmall => EcliptixProtocolFailure.BufferTooSmall(message),
            EcliptixErrorCode.ErrorObjectDisposed => EcliptixProtocolFailure.ObjectDisposed(message),
            EcliptixErrorCode.ErrorPrepareLocal => EcliptixProtocolFailure.PrepareLocal(message),
            _ => EcliptixProtocolFailure.Generic(message)
        };
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcliptixProtocolSystemWrapper));
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_callbackHandle.IsAllocated)
        {
            _callbackHandle.Free();
        }

        if (_handle != IntPtr.Zero)
        {
            EcliptixNativeInterop.ecliptix_protocol_server_system_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~EcliptixProtocolSystemWrapper()
    {
        Dispose();
    }
}

public sealed class EcliptixIdentityKeysWrapper : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    public IntPtr Handle => _handle;
    public bool IsDisposed => _disposed;

    public static Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> Create()
    {
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_identity_keys_create(
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(errorMessage));
        }

        return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Ok(
            new EcliptixIdentityKeysWrapper(handle));
    }

    public static Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> CreateFromSeed(byte[] seed)
    {
        if (seed == null)
        {
            return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Seed is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_identity_keys_create_from_seed(
            seed,
            (nuint)seed.Length,
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(errorMessage));
        }

        return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Ok(
            new EcliptixIdentityKeysWrapper(handle));
    }

    private EcliptixIdentityKeysWrapper(IntPtr handle)
    {
        _handle = handle;
        _disposed = false;
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicX25519()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[32];
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_identity_keys_get_public_x25519(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(errorMessage));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicEd25519()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[32];
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_identity_keys_get_public_ed25519(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(errorMessage));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    /// <summary>
    /// Gets the identity Kyber (ML-KEM-768) public key (1184 bytes).
    /// </summary>
    public Result<byte[], EcliptixProtocolFailure> GetPublicKyber()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[1184]; // ML-KEM-768 public key size
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_identity_keys_get_public_kyber(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(errorMessage));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcliptixIdentityKeysWrapper));
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
            EcliptixNativeInterop.ecliptix_identity_keys_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~EcliptixIdentityKeysWrapper()
    {
        Dispose();
    }
}
