#pragma once
#include <variant>
#include <utility>
#include <functional>
#include <type_traits>
#include <stdexcept>
#include <optional>
namespace ecliptix::protocol {
template<typename T, typename E>
class Result;
struct Unit {
    constexpr bool operator==(const Unit&) const noexcept { return true; }
    constexpr bool operator!=(const Unit&) const noexcept { return false; }
};
inline constexpr Unit unit{};
template<typename T, typename E>
class Result {
private:
    std::variant<T, E> value_;
    bool is_ok_;
public:
    Result(const Result&) = default;
    Result(Result&&) noexcept = default;
    Result& operator=(const Result&) = default;
    Result& operator=(Result&&) noexcept = default;
    ~Result() = default;
    static Result Ok(T value) {
        return Result(std::in_place_index<0>, std::move(value));
    }
    static Result Err(E error) {
        return Result(std::in_place_index<1>, std::move(error));
    }
    static Result FromOptional(std::optional<T> opt, E error_if_none) {
        if (opt.has_value()) {
            return Ok(std::move(*opt));
        }
        return Err(std::move(error_if_none));
    }
    template<typename Func, typename ErrorFunc>
    static Result Try(Func&& func, ErrorFunc&& on_error) {
        try {
            if constexpr (std::is_void_v<std::invoke_result_t<Func>>) {
                std::forward<Func>(func)();
                return Ok(Unit{});
            } else {
                return Ok(std::forward<Func>(func)());
            }
        } catch (const std::exception& ex) {
            return Err(std::forward<ErrorFunc>(on_error)(ex));
        } catch (...) {
            return Err(std::forward<ErrorFunc>(on_error)(
                std::runtime_error("Unknown exception")));
        }
    }
    [[nodiscard]] bool IsOk() const noexcept { return is_ok_; }
    [[nodiscard]] bool IsErr() const noexcept { return !is_ok_; }
    template<typename Pred>
    [[nodiscard]] bool IsOkAnd(Pred&& pred) const {
        return IsOk() && std::forward<Pred>(pred)(std::get<0>(value_));
    }
    template<typename Pred>
    [[nodiscard]] bool IsErrAnd(Pred&& pred) const {
        return IsErr() && std::forward<Pred>(pred)(std::get<1>(value_));
    }
    [[nodiscard]] T& Unwrap() & {
        if (IsErr()) {
            throw std::runtime_error("Called Unwrap() on an Err Result");
        }
        return std::get<0>(value_);
    }
    [[nodiscard]] const T& Unwrap() const& {
        if (IsErr()) {
            throw std::runtime_error("Called Unwrap() on an Err Result");
        }
        return std::get<0>(value_);
    }
    [[nodiscard]] T&& Unwrap() && {
        if (IsErr()) {
            throw std::runtime_error("Called Unwrap() on an Err Result");
        }
        return std::get<0>(std::move(value_));
    }
    [[nodiscard]] E& UnwrapErr() & {
        if (IsOk()) {
            throw std::runtime_error("Called UnwrapErr() on an Ok Result");
        }
        return std::get<1>(value_);
    }
    [[nodiscard]] const E& UnwrapErr() const& {
        if (IsOk()) {
            throw std::runtime_error("Called UnwrapErr() on an Ok Result");
        }
        return std::get<1>(value_);
    }
    [[nodiscard]] E&& UnwrapErr() && {
        if (IsOk()) {
            throw std::runtime_error("Called UnwrapErr() on an Ok Result");
        }
        return std::get<1>(std::move(value_));
    }
    [[nodiscard]] T UnwrapOr(T default_value) && {
        if (IsOk()) {
            return std::get<0>(std::move(value_));
        }
        return default_value;
    }
    template<typename F>
    [[nodiscard]] T UnwrapOrElse(F&& f) && {
        if (IsOk()) {
            return std::get<0>(std::move(value_));
        }
        return std::forward<F>(f)(std::get<1>(std::move(value_)));
    }
    template<typename F>
    [[nodiscard]] auto Map(F&& func) && -> Result<std::invoke_result_t<F, T>, E> {
        using U = std::invoke_result_t<F, T>;
        if (IsOk()) {
            return Result<U, E>::Ok(std::forward<F>(func)(std::get<0>(std::move(value_))));
        }
        return Result<U, E>::Err(std::get<1>(std::move(value_)));
    }
    template<typename F>
    [[nodiscard]] auto MapErr(F&& func) && -> Result<T, std::invoke_result_t<F, E>> {
        using U = std::invoke_result_t<F, E>;
        if (IsErr()) {
            return Result<T, U>::Err(std::forward<F>(func)(std::get<1>(std::move(value_))));
        }
        return Result<T, U>::Ok(std::get<0>(std::move(value_)));
    }
    template<typename F>
    [[nodiscard]] auto Bind(F&& func) && -> std::invoke_result_t<F, T> {
        using ResultType = std::invoke_result_t<F, T>;
        static_assert(std::is_same_v<typename ResultType::error_type, E>,
                      "Bind function must return Result with same error type");
        if (IsOk()) {
            return std::forward<F>(func)(std::get<0>(std::move(value_)));
        }
        return ResultType::Err(std::get<1>(std::move(value_)));
    }
    template<typename F>
    Result& Inspect(F&& func) & {
        if (IsOk()) {
            std::forward<F>(func)(std::get<0>(value_));
        }
        return *this;
    }
    template<typename F>
    Result& InspectErr(F&& func) & {
        if (IsErr()) {
            std::forward<F>(func)(std::get<1>(value_));
        }
        return *this;
    }
    [[nodiscard]] std::optional<T> Ok() && {
        if (IsOk()) {
            return std::get<0>(std::move(value_));
        }
        return std::nullopt;
    }
    [[nodiscard]] std::optional<E> Err() && {
        if (IsErr()) {
            return std::get<1>(std::move(value_));
        }
        return std::nullopt;
    }
    using value_type = T;
    using error_type = E;
private:
    template<std::size_t I, typename... Args>
    explicit Result(std::in_place_index_t<I> idx, Args&&... args)
        : value_(idx, std::forward<Args>(args)...)
        , is_ok_(I == 0) {}
};
#define TRY(result_expr) \
    do { \
        auto&& __ecliptix_result = (result_expr); \
        if (__ecliptix_result.IsErr()) { \
            return std::move(__ecliptix_result).MapErr([](auto&& e) { return std::forward<decltype(e)>(e); }); \
        } \
    } while(0)

#define TRY_UNIT(result_expr) TRY(result_expr)
}
