#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <cstdint>
#include <functional>
#include <span>
namespace ecliptix::protocol::interfaces {
using protocol::Result;
using protocol::Unit;
using protocol::EcliptixProtocolFailure;
class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;
    [[nodiscard]] virtual Result<Unit, EcliptixProtocolFailure> ExecuteWithKey(
        uint32_t index,
        std::function<Result<Unit, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation) = 0;
    template<typename T>
    [[nodiscard]] Result<T, EcliptixProtocolFailure> ExecuteWithKeyTyped(
        uint32_t index,
        std::function<Result<T, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation) {
        Result<T, EcliptixProtocolFailure> result_holder =
            Result<T, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Operation not executed"));
        auto wrapper = [&operation, &result_holder](std::span<const uint8_t> key)
            -> Result<Unit, EcliptixProtocolFailure> {
            result_holder = operation(key);
            return result_holder.IsOk()
                ? Result<Unit, EcliptixProtocolFailure>::Ok(Unit{})
                : Result<Unit, EcliptixProtocolFailure>::Err(result_holder.UnwrapErr());
        };
        auto exec_result = ExecuteWithKey(index, wrapper);
        if (exec_result.IsErr()) {
            return Result<T, EcliptixProtocolFailure>::Err(exec_result.UnwrapErr());
        }
        return result_holder;
    }
};
} 
