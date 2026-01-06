using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;


namespace EPP.Sodium;




public sealed class SodiumSecureMemoryHandle : SafeHandle
{
    private readonly ReaderWriterLockSlim _lock = new();
    private bool _isLocked;

    public int Length { get; }

    public override bool IsInvalid => handle == IntPtr.Zero;

    private SodiumSecureMemoryHandle(IntPtr preexistingHandle, int length, bool ownsHandle)
        : base(IntPtr.Zero, ownsHandle)
    {
        SetHandle(preexistingHandle);
        Length = length;
        _isLocked = false;

        if (length > 0 && preexistingHandle != IntPtr.Zero)
        {
            TryLockMemory();
        }
    }

    public static Result<SodiumSecureMemoryHandle, SodiumFailure> Allocate(int length)
    {
        switch (length)
        {
            case < 0:
                return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(
                    SodiumFailure.InvalidBufferSize(string.Format(SodiumFailureMessages.NEGATIVE_ALLOCATION_LENGTH,
                        length)));
            case 0:
                return Result<SodiumSecureMemoryHandle, SodiumFailure>.Ok(
                    new SodiumSecureMemoryHandle(IntPtr.Zero, 0, true));
        }

        if (!SodiumInterop.IsInitialized)
        {
            return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(
                SodiumFailure.INITIALIZATION_FAILED(SodiumFailureMessages.SODIUM_NOT_INITIALIZED));
        }

        Result<IntPtr, SodiumFailure> allocationResult = ExecuteWithErrorHandling(
            () => SodiumInterop.sodium_malloc((UIntPtr)length),
            ex => SodiumFailure.ALLOCATION_FAILED(
                string.Format(SodiumFailureMessages.UNEXPECTED_ALLOCATION_ERROR, length), ex)
        );

        if (allocationResult.IsErr)
        {
            return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(allocationResult.UnwrapErr());
        }

        IntPtr ptr = allocationResult.Unwrap();
        if (ptr == IntPtr.Zero)
        {
            return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(
                SodiumFailure.ALLOCATION_FAILED(string.Format(SodiumFailureMessages.ALLOCATION_FAILED,
                    length)));
        }

        return Result<SodiumSecureMemoryHandle, SodiumFailure>.Ok(
            new SodiumSecureMemoryHandle(ptr, length, true));
    }

    public Result<Unit, SodiumFailure> Write(ReadOnlySpan<byte> data)
    {
        _lock.EnterWriteLock();

        bool success = false;

        try
        {
            if (IsInvalid || IsClosed)
            {
                return Result<Unit, SodiumFailure>.Err(
                    SodiumFailure.NullPointer(ProtocolSystemConstants.ErrorMessages.HANDLE_DISPOSED));
            }

            if (data.Length > Length)
            {
                return Result<Unit, SodiumFailure>.Err(
                    SodiumFailure.BUFFER_TOO_LARGE(string.Format(ProtocolSystemConstants.ErrorMessages.DATA_EXCEEDS_BUFFER, data.Length, Length)));
            }

            if (data.IsEmpty)
            {
                return Result<Unit, SodiumFailure>.Ok(Unit.Value);
            }

            DangerousAddRef(ref success);
            if (!success)
            {
                return Result<Unit, SodiumFailure>.Err(
                    SodiumFailure.MemoryPinningFailed(ProtocolSystemConstants.ErrorMessages.REF_COUNT_FAILED));
            }

            unsafe
            {
                Buffer.MemoryCopy(
                    Unsafe.AsPointer(ref MemoryMarshal.GetReference(data)),
                    (void*)handle,
                    Length,
                    data.Length);
            }

            return Result<Unit, SodiumFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.MemoryProtectionFailed(ProtocolSystemConstants.ErrorMessages.UNEXPECTED_WRITE_ERROR, ex));
        }
        finally
        {
            if (success)
            {
                DangerousRelease();
            }

            _lock.ExitWriteLock();
        }
    }

    public Result<Unit, SodiumFailure> Read(Span<byte> destination)
    {
        if (IsInvalid || IsClosed)
        {
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.NullPointer(string.Format(SodiumFailureMessages.OBJECT_DISPOSED,
                    nameof(SodiumSecureMemoryHandle))));
        }

        if (destination.Length < Length)
        {
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.BUFFER_TOO_SMALL(
                    string.Format(SodiumFailureMessages.BUFFER_TOO_SMALL, destination.Length, Length)));
        }

        if (Length == 0)
        {
            return Result<Unit, SodiumFailure>.Ok(Unit.Value);
        }

        _lock.EnterReadLock();
        bool success = false;

        try
        {
            DangerousAddRef(ref success);
            if (!success)
            {
                return Result<Unit, SodiumFailure>.Err(
                    SodiumFailure.MemoryPinningFailed(SodiumFailureMessages.REFERENCE_COUNT_FAILED));
            }

            if (IsInvalid || IsClosed)
            {
                return Result<Unit, SodiumFailure>.Err(
                    SodiumFailure.NullPointer(
                        string.Format(SodiumFailureMessages.DISPOSED_AFTER_ADD_REF, nameof(SodiumSecureMemoryHandle))));
            }

            unsafe
            {
                Buffer.MemoryCopy(
                    (void*)handle,
                    Unsafe.AsPointer(ref MemoryMarshal.GetReference(destination)),
                    (ulong)destination.Length,
                    (ulong)Length);
            }

            return Result<Unit, SodiumFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.MemoryProtectionFailed(SodiumFailureMessages.UNEXPECTED_READ_ERROR, ex));
        }
        finally
        {
            if (success)
            {
                DangerousRelease();
            }

            _lock.ExitReadLock();
        }
    }

    public Result<byte[], SodiumFailure> ReadBytes(int length)
    {
        if (IsInvalid || IsClosed)
        {
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.NullPointer(string.Format(SodiumFailureMessages.OBJECT_DISPOSED,
                    nameof(SodiumSecureMemoryHandle))));
        }

        if (length < 0)
        {
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidBufferSize(string.Format(SodiumFailureMessages.NEGATIVE_READ_LENGTH, length)));
        }

        if (length > Length)
        {
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.BUFFER_TOO_SMALL(string.Format(SodiumFailureMessages.READ_LENGTH_EXCEEDS_SIZE,
                    length,
                    Length)));
        }

        if (length == 0)
        {
            return Result<byte[], SodiumFailure>.Ok([]);
        }

        _lock.EnterReadLock();
        byte[] buffer = new byte[length];
        bool success = false;

        try
        {
            Result<byte[], SodiumFailure> copyResult = ExecuteWithErrorHandling(
                () =>
                {
                    DangerousAddRef(ref success);
                    if (!success)
                    {
                        throw new InvalidOperationException(SodiumFailureMessages.REFERENCE_COUNT_FAILED);
                    }

                    if (IsInvalid || IsClosed)
                    {
                        throw new ObjectDisposedException(
                            string.Format(SodiumFailureMessages.DISPOSED_AFTER_ADD_REF, nameof(SodiumSecureMemoryHandle)));
                    }

                    unsafe
                    {
                        Buffer.MemoryCopy(
                            (void*)handle,
                            Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer.AsSpan())),
                            (ulong)length,
                            (ulong)length);
                    }

                    return buffer;
                },
                ex => ex switch
                {
                    InvalidOperationException { Message: SodiumFailureMessages.REFERENCE_COUNT_FAILED } =>
                        SodiumFailure.MemoryPinningFailed(SodiumFailureMessages.REFERENCE_COUNT_FAILED),
                    ObjectDisposedException => SodiumFailure.NullPointer(
                        string.Format(SodiumFailureMessages.DISPOSED_AFTER_ADD_REF, nameof(SodiumSecureMemoryHandle))),
                    _ => SodiumFailure.MemoryProtectionFailed(
                        string.Format(SodiumFailureMessages.UNEXPECTED_READ_BYTES_ERROR, length), ex)
                }
            );

            return copyResult;
        }
        finally
        {
            if (success)
            {
                DangerousRelease();
            }

            _lock.ExitReadLock();
        }
    }

    protected override bool ReleaseHandle()
    {
        try
        {
            _lock.EnterWriteLock();
        }
        catch
        {
            return false;
        }

        try
        {
            if (IsInvalid)
            {
                return true;
            }

            if (_isLocked)
            {
                TryUnlockMemory();
            }

            SodiumInterop.sodium_free(handle);
            SetHandleAsInvalid();
            return true;
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _lock?.Dispose();
        }
    }

    private void TryLockMemory()
    {
        if (handle == IntPtr.Zero || Length <= 0)
        {
            return;
        }

        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (VirtualLock(handle, (UIntPtr)Length))
                {
                    _isLocked = true;
                    return;
                }

                int errorCode = Marshal.GetLastWin32Error();

                if (errorCode == 1453)
                {
                    IntPtr hProcess = GetCurrentProcess();
                    if (GetProcessWorkingSetSize(hProcess, out UIntPtr min, out UIntPtr max))
                    {
                        UIntPtr overhead = (UIntPtr)(Length + 4096 * 10);

                        if (SetProcessWorkingSetSize(hProcess, min + overhead, max + overhead))
                        {
                            if (VirtualLock(handle, (UIntPtr)Length))
                            {
                                _isLocked = true;
                                return;
                            }
                            errorCode = Marshal.GetLastWin32Error();
                        }
                    }
                }

                Serilog.Log.Warning(
                    "[SODIUM-MEMORY] Failed to lock memory with VirtualLock on Windows. Error Code: {ErrorCode}, Address: {Address}, Size: {Size}",
                    errorCode, handle, Length);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
                     RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                if (mlock(handle, (UIntPtr)Length) == 0)
                {
                    _isLocked = true;
                }
                else
                {
                    int errno = Marshal.GetLastWin32Error();
                    Serilog.Log.Warning(
                        "[SODIUM-MEMORY] Failed to lock memory with mlock. Errno: {Errno}, Address: {Address}, Size: {Size}",
                        errno, handle, Length);
                }
            }
        }
        catch (Exception ex)
        {
            _isLocked = false;
            Serilog.Log.Error(ex, "[SODIUM-MEMORY] Exception during memory locking. Address: {Address}, Size: {Size}",
                handle, Length);
        }
    }

    private void TryUnlockMemory()
    {
        if (handle == IntPtr.Zero || Length <= 0 || !_isLocked)
        {
            return;
        }

        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                VirtualUnlock(handle, (UIntPtr)Length);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
                     RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                munlock(handle, (UIntPtr)Length);
            }
        }
        catch (Exception ex)
        {
            Serilog.Log.Debug(ex, "[SODIUM-MEMORY] Exception during memory unlocking (may be expected). Address: {Address}, Size: {Size}",
                handle, Length);
        }
        finally
        {
            _isLocked = false;
        }
    }

    private static Result<T, SodiumFailure> ExecuteWithErrorHandling<T>(
        Func<T> action,
        Func<Exception, SodiumFailure> errorMapper)
    {
        try
        {
            T result = action();
            return Result<T, SodiumFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            return Result<T, SodiumFailure>.Err(errorMapper(ex));
        }
    }

    public Result<TResult, SodiumFailure> WithReadAccess<TResult>(
        Func<ReadOnlySpan<byte>, Result<TResult, SodiumFailure>> operation)
    {
        if (IsInvalid || IsClosed)
        {
            return Result<TResult, SodiumFailure>.Err(
                SodiumFailure.NullPointer(string.Format(SodiumFailureMessages.OBJECT_DISPOSED,
                    nameof(SodiumSecureMemoryHandle))));
        }

        _lock.EnterReadLock();
        bool success = false;

        try
        {
            DangerousAddRef(ref success);
            if (!success)
            {
                return Result<TResult, SodiumFailure>.Err(
                    SodiumFailure.MemoryProtectionFailed(SodiumFailureMessages.REFERENCE_COUNT_FAILED));
            }

            if (IsInvalid || IsClosed)
            {
                return Result<TResult, SodiumFailure>.Err(
                    SodiumFailure.OBJECT_DISPOSED(string.Format(SodiumFailureMessages.DISPOSED_AFTER_ADD_REF,
                        nameof(SodiumSecureMemoryHandle))));
            }

            unsafe
            {
                ReadOnlySpan<byte> span = new((void*)handle, Length);
                return operation(span);
            }
        }
        catch (Exception ex)
        {
            return Result<TResult, SodiumFailure>.Err(
                SodiumFailure.MemoryProtectionFailed(SodiumFailureMessages.UNEXPECTED_READ_ERROR, ex));
        }
        finally
        {
            if (success)
            {
                DangerousRelease();
            }

            _lock.ExitReadLock();
        }
    }

    [SupportedOSPlatform("windows")]
    [DllImport(ProtocolSystemConstants.Libraries.KERNEL_32, SetLastError = true)]
    private static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);

    [SupportedOSPlatform("windows")]
    [DllImport(ProtocolSystemConstants.Libraries.KERNEL_32, SetLastError = true)]
    private static extern bool VirtualUnlock(IntPtr lpAddress, UIntPtr dwSize);

    [SupportedOSPlatform("windows")]
    [DllImport(ProtocolSystemConstants.Libraries.KERNEL_32, SetLastError = true)]
    private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, UIntPtr dwMinimumWorkingSetSize, UIntPtr dwMaximumWorkingSetSize);

    [SupportedOSPlatform("windows")]
    [DllImport(ProtocolSystemConstants.Libraries.KERNEL_32, SetLastError = true)]
    private static extern bool GetProcessWorkingSetSize(IntPtr hProcess, out UIntPtr lpMinimumWorkingSetSize, out UIntPtr lpMaximumWorkingSetSize);

    [SupportedOSPlatform("windows")]
    [DllImport(ProtocolSystemConstants.Libraries.KERNEL_32, SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport(ProtocolSystemConstants.Libraries.LIB_C, SetLastError = true)]
    private static extern int mlock(IntPtr addr, UIntPtr len);

    [DllImport(ProtocolSystemConstants.Libraries.LIB_C, SetLastError = true)]
    private static extern int munlock(IntPtr addr, UIntPtr len);
}
