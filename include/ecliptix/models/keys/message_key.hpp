#pragma once
#include "ecliptix/interfaces/i_key_provider.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <cstdint>
#include <functional>
#include <span>
#include <vector>
namespace ecliptix::protocol::models {
using protocol::Result;
using protocol::Unit;
using protocol::EcliptixProtocolFailure;
using interfaces::IKeyProvider;
class MessageKey {
public:
    MessageKey(IKeyProvider* provider, const uint32_t index) noexcept
        : provider_(provider), index_(index) {}
    [[nodiscard]] uint32_t Index() const noexcept {
        return index_;
    }
    template<typename T>
    [[nodiscard]] Result<T, EcliptixProtocolFailure> WithKeyMaterial(
        std::function<Result<T, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation) const {
        if (provider_ == nullptr) {
            return Result<T, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Key provider is null"));
        }
        return provider_->ExecuteWithKeyTyped<T>(index_, operation);
    }
    [[nodiscard]] bool operator==(const MessageKey& other) const noexcept {
        return index_ == other.index_;
    }
    [[nodiscard]] bool operator!=(const MessageKey& other) const noexcept {
        return !(*this == other);
    }
    [[nodiscard]] bool operator<(const MessageKey& other) const noexcept {
        return index_ < other.index_;
    }
    MessageKey(const MessageKey&) = default;
    MessageKey& operator=(const MessageKey&) = default;
    MessageKey(MessageKey&&) noexcept = default;
    MessageKey& operator=(MessageKey&&) noexcept = default;
    ~MessageKey() = default;
private:
    IKeyProvider* provider_;  
    uint32_t index_;           
};
} 
