namespace Ecliptix.Protocol.Server;

/// <summary>
/// Represents a unit type (void equivalent for Result types).
/// </summary>
public readonly struct Unit
{
    public static readonly Unit Value = new();
}

/// <summary>
/// A Result type for representing success or failure outcomes.
/// </summary>
/// <typeparam name="T">The success value type.</typeparam>
/// <typeparam name="E">The error type.</typeparam>
public readonly struct Result<T, E>
{
    private readonly T? _value;
    private readonly E? _error;
    private readonly bool _isOk;

    private Result(T value)
    {
        _value = value;
        _error = default;
        _isOk = true;
    }

    private Result(E error, bool _)
    {
        _value = default;
        _error = error;
        _isOk = false;
    }

    public bool IsOk => _isOk;
    public bool IsErr => !_isOk;

    public static Result<T, E> Ok(T value) => new(value);
    public static Result<T, E> Err(E error) => new(error, false);

    public T Unwrap()
    {
        if (!_isOk)
            throw new InvalidOperationException("Called Unwrap on an Err result");
        return _value!;
    }

    public E UnwrapErr()
    {
        if (_isOk)
            throw new InvalidOperationException("Called UnwrapErr on an Ok result");
        return _error!;
    }

    public T UnwrapOr(T defaultValue) => _isOk ? _value! : defaultValue;

    public Result<U, E> Map<U>(Func<T, U> mapper)
    {
        return _isOk
            ? Result<U, E>.Ok(mapper(_value!))
            : Result<U, E>.Err(_error!);
    }

    public Result<T, F> MapErr<F>(Func<E, F> mapper)
    {
        return _isOk
            ? Result<T, F>.Ok(_value!)
            : Result<T, F>.Err(mapper(_error!));
    }

    public Result<U, E> Bind<U>(Func<T, Result<U, E>> binder)
    {
        return _isOk ? binder(_value!) : Result<U, E>.Err(_error!);
    }

    public void Match(Action<T> onOk, Action<E> onErr)
    {
        if (_isOk)
            onOk(_value!);
        else
            onErr(_error!);
    }

    public U Match<U>(Func<T, U> onOk, Func<E, U> onErr)
    {
        return _isOk ? onOk(_value!) : onErr(_error!);
    }
}
