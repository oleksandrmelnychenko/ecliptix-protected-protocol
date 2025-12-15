#pragma once
#include <optional>
#include <functional>
namespace ecliptix::protocol {
template<typename T>
using Option = std::optional<T>;
template<typename T>
[[nodiscard]] constexpr Option<std::decay_t<T>> Some(T&& value) {
    return Option<std::decay_t<T>>{std::forward<T>(value)};
}
template<typename T>
[[nodiscard]] constexpr Option<T> None() {
    return std::nullopt;
}
template<typename T>
class OptionExt {
public:
    [[nodiscard]] static bool IsSome(const Option<T>& opt) {
        return opt.has_value();
    }
    [[nodiscard]] static bool IsNone(const Option<T>& opt) {
        return !opt.has_value();
    }
    [[nodiscard]] static T ValueOr(Option<T> opt, T default_value) {
        return opt.value_or(std::move(default_value));
    }
    template<typename F>
    [[nodiscard]] static auto Map(Option<T> opt, F&& func) -> Option<std::invoke_result_t<F, T>> {
        using U = std::invoke_result_t<F, T>;
        if (opt.has_value()) {
            return Some(std::forward<F>(func)(*std::move(opt)));
        }
        return None<U>();
    }
    template<typename F>
    [[nodiscard]] static auto Bind(Option<T> opt, F&& func) -> std::invoke_result_t<F, T> {
        if (opt.has_value()) {
            return std::forward<F>(func)(*std::move(opt));
        }
        using ResultType = std::invoke_result_t<F, T>;
        return ResultType{};
    }
    template<typename Pred>
    [[nodiscard]] static Option<T> Filter(Option<T> opt, Pred&& pred) {
        if (opt.has_value() && std::forward<Pred>(pred)(*opt)) {
            return opt;
        }
        return None<T>();
    }
};
} 
