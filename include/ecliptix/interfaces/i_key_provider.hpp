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

/**
 * @brief Interface for deferred key access with secure key material handling
 *
 * This interface allows ChainStep to provide key material without exposing
 * the actual keys. It enables lazy evaluation and ensures keys are only
 * accessed when needed, within a secure execution context.
 *
 * **Design Pattern: Strategy + Template Method**
 * - ChainStep implements this interface to provide controlled key access
 * - RatchetChainKey and MessageKey use this to access derived keys
 * - Keys are never exposed outside the provider's execution scope
 *
 * **Usage Example**:
 * ```cpp
 * class MyChainStep : public IKeyProvider {
 *     Result<Unit, EcliptixProtocolFailure> ExecuteWithKey(
 *         uint32_t index,
 *         std::function<Result<Unit, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation
 *     ) override {
 *         // Derive or retrieve key for index
 *         std::vector<uint8_t> key = DeriveKey(index);
 *
 *         // Execute operation with key material
 *         Result<Unit, EcliptixProtocolFailure> result = operation(key);
 *
 *         // Securely wipe key before returning
 *         SodiumInterop::SecureWipe(std::span<uint8_t>(key));
 *
 *         return result;
 *     }
 * };
 * ```
 */
class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;

    /**
     * @brief Execute an operation with the key material for a specific index
     *
     * Provides temporary access to the key material through a callback function.
     * The key material is guaranteed to be available only during the callback
     * execution and will be securely wiped afterwards.
     *
     * @param index The chain index for which to provide the key
     * @param operation Callback that receives the key material as std::span<const uint8_t>
     *
     * @return Result containing the operation's return value or an error
     *
     * @note The key material span is only valid during the operation callback
     * @note Implementations MUST securely wipe the key material after the operation
     * @note The operation callback should not store the span or its data
     *
     * **Thread Safety**: Implementations should ensure thread-safe access to keys
     */
    [[nodiscard]] virtual Result<Unit, EcliptixProtocolFailure> ExecuteWithKey(
        uint32_t index,
        std::function<Result<Unit, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation) = 0;

    /**
     * @brief Execute an operation that returns a value with the key material
     *
     * Similar to ExecuteWithKey but allows the operation to return a typed value.
     * This is useful for encryption operations that need to return encrypted data.
     *
     * @tparam T The return type of the operation
     * @param index The chain index for which to provide the key
     * @param operation Callback that receives key material and returns Result<T, EcliptixProtocolFailure>
     *
     * @return Result containing the operation's return value or an error
     *
     * @note Same security constraints as ExecuteWithKey apply
     */
    template<typename T>
    [[nodiscard]] Result<T, EcliptixProtocolFailure> ExecuteWithKeyTyped(
        uint32_t index,
        std::function<Result<T, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation) {

        // Use type erasure to call the base ExecuteWithKey
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

} // namespace ecliptix::protocol::interfaces
