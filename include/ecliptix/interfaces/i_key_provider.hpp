#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <cstdint>
#include <functional>
#include <span>
namespace ecliptix::protocol::interfaces {
using protocol::Result;
using protocol::Unit;
using protocol::ProtocolFailure;
class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;
    [[nodiscard]] virtual Result<Unit, ProtocolFailure> ExecuteWithKey(
        uint32_t index,
        std::function<Result<Unit, ProtocolFailure>(std::span<const uint8_t>)> operation) = 0;
    template<typename T>
    [[nodiscard]] Result<T, ProtocolFailure> ExecuteWithKeyTyped(
        uint32_t index,
        std::function<Result<T, ProtocolFailure>(std::span<const uint8_t>)> operation) {
        Result<T, ProtocolFailure> result_holder =
            Result<T, ProtocolFailure>::Err(
                ProtocolFailure::Generic("Operation not executed"));
        auto wrapper = [&operation, &result_holder](std::span<const uint8_t> key)
            -> Result<Unit, ProtocolFailure> {
            result_holder = operation(key);
            return result_holder.IsOk()
                ? Result<Unit, ProtocolFailure>::Ok(Unit{})
                : Result<Unit, ProtocolFailure>::Err(result_holder.UnwrapErr());
        };
        auto exec_result = ExecuteWithKey(index, wrapper);
        if (exec_result.IsErr()) {
            return Result<T, ProtocolFailure>::Err(exec_result.UnwrapErr());
        }
        return result_holder;
    }
};
} 
