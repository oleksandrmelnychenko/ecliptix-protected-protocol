using System.Diagnostics.CodeAnalysis;


namespace EPP;




public readonly struct Result<T, TE> : IEquatable<Result<T, TE>>
{
    private readonly T? _value;
    private readonly TE? _error;

    private Result(T value, bool isOk)
    {
        _value = value;
        _error = default;
        IsOk = isOk;
    }

    private Result(TE error)
    {
        _value = default;
        _error = error;
        IsOk = false;
    }


    public static Result<T, TE> Ok(T value) => new(value, true);

    public static Result<T, TE> Err(TE error) => new(error);

    public static Result<T, TE> FromValue(T? value, TE errorWhenNull)
    {
        return value switch
        {
            not null => Ok(value),
            _ => Err(errorWhenNull)
        };
    }

    public static Result<T, TE> Validate(T value, Func<T, bool> predicate, TE errorWhenInvalid) => predicate(value) ? Ok(value) : Err(errorWhenInvalid);

    public static Result<T, TE> Try(Func<T> func, Func<Exception, TE> errorMapper)
    {
        try
        {
            return Ok(func());
        }
        catch (Exception ex) when (ex is not ThreadAbortException and not StackOverflowException)
        {
            TE error = errorMapper(ex);
            return EqualityComparer<TE>.Default.Equals(error, default)
                ? throw new InvalidOperationException(UtilityConstants.ErrorMessages.ERROR_MAPPER_RETURNED_NULL)
                : Err(error);
        }
    }

    public static Result<Unit, TE> Try(Action action, Func<Exception, TE> errorMapper, Action? cleanup = null)
    {
        try
        {
            action();
            return Result<Unit, TE>.Ok(Unit.Value);
        }
        catch (Exception ex) when (ex is not ThreadAbortException and not StackOverflowException)
        {
            TE error = errorMapper(ex);
            return EqualityComparer<TE>.Default.Equals(error, default)
                ? throw new InvalidOperationException(UtilityConstants.ErrorMessages.ERROR_MAPPER_RETURNED_NULL)
                : Result<Unit, TE>.Err(error);
        }
        finally
        {
            cleanup?.Invoke();
        }
    }

    [MemberNotNullWhen(true, nameof(_value))]
    [MemberNotNullWhen(false, nameof(_error))]
    public bool IsOk { get; }

    [MemberNotNullWhen(false, nameof(_value))]
    [MemberNotNullWhen(true, nameof(_error))]
    public bool IsErr => !IsOk;

    public T Unwrap() =>
        IsOk ? _value! : throw new InvalidOperationException(UtilityConstants.ErrorMessages.CANNOT_UNWRAP_ERR);

    public TE UnwrapErr() =>
        IsOk ? throw new InvalidOperationException(UtilityConstants.ErrorMessages.CANNOT_UNWRAP_OK) : _error!;

    public Result<TNext, TE> Map<TNext>(Func<T, TNext> mapFn) =>
        IsOk ? Result<TNext, TE>.Ok(mapFn(_value!)) : Result<TNext, TE>.Err(_error!);

    public Result<TNext, TE> Bind<TNext>(Func<T, Result<TNext, TE>> bindFn) =>
        IsOk ? bindFn(_value!) : Result<TNext, TE>.Err(_error!);

    public Result<TNext, TE> AndThen<TNext>(Func<T, Result<TNext, TE>> bindFn) => Bind(bindFn);

    public override string ToString() =>
        IsOk ? UtilityConstants.ResultType.OK_STRING : UtilityConstants.ResultType.ERR_STRING;

    public bool Equals(Result<T, TE> other)
    {
        return IsOk == other.IsOk &&
               (IsOk
                   ? EqualityComparer<T?>.Default.Equals(_value, other._value)
                   : EqualityComparer<TE>.Default.Equals(_error, other._error));
    }

    public override bool Equals(object? obj) => obj is Result<T, TE> other && Equals(other);

    public override int GetHashCode()
    {
        unchecked
        {
            int hash = UtilityConstants.Hash.INITIAL_HASH_SEED;
            hash = hash * UtilityConstants.Hash.HASH_MULTIPLIER + IsOk.GetHashCode();
            hash = hash * UtilityConstants.Hash.HASH_MULTIPLIER + (IsOk
                ? EqualityComparer<T?>.Default.GetHashCode(_value)
                : EqualityComparer<TE>.Default.GetHashCode(_error!));
            return hash;
        }
    }

    public static bool operator ==(Result<T, TE> left, Result<T, TE> right) => left.Equals(right);

    public static bool operator !=(Result<T, TE> left, Result<T, TE> right) => !left.Equals(right);
}
