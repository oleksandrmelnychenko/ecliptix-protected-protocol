using System;
using System.Runtime.InteropServices;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures.EcliptixProtocol;

namespace Ecliptix.Protocol.Native;

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

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_create(
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

            EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_set_callbacks(
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

            EcliptixNativeInterop.ecliptix_protocol_system_set_callbacks(
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

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_send_message(
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

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_receive_message(
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

    public EcliptixIdentityKeysWrapper GetIdentityKeys() => _identityKeys;

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
            EcliptixErrorCode.ErrorBufferTooSmall => EcliptixProtocolFailure.BUFFER_TOO_SMALL(message),
            EcliptixErrorCode.ErrorObjectDisposed => EcliptixProtocolFailure.OBJECT_DISPOSED(message),
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
            EcliptixNativeInterop.ecliptix_protocol_system_destroy(_handle);
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
