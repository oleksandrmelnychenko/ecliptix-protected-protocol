#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <span>
#include <cstddef>
#include <cstdint>
namespace ecliptix::protocol::crypto {
class SecureMemoryHandle {
public:
    static Result<SecureMemoryHandle, SodiumFailure> Allocate(size_t size);
    ~SecureMemoryHandle();
    SecureMemoryHandle() noexcept : ptr_(nullptr), size_(0) {}
    SecureMemoryHandle(SecureMemoryHandle&& other) noexcept;
    SecureMemoryHandle& operator=(SecureMemoryHandle&& other) noexcept;
    SecureMemoryHandle(const SecureMemoryHandle&) = delete;
    SecureMemoryHandle& operator=(const SecureMemoryHandle&) = delete;
    Result<Unit, SodiumFailure> Write(std::span<const uint8_t> data) const;
    Result<Unit, SodiumFailure> Read(std::span<uint8_t> output) const;
    Result<std::vector<uint8_t>, SodiumFailure> ReadBytes(size_t size) const;
    template<typename F>
    auto WithReadAccess(F&& func) const -> Result<std::invoke_result_t<F, std::span<const uint8_t>>, SodiumFailure> {
        using T = std::invoke_result_t<F, std::span<const uint8_t>>;
        if (IsInvalid()) {
            return Result<T, SodiumFailure>::Err(
                SodiumFailure::InvalidOperation("Handle has been disposed"));
        }
        std::span<const uint8_t> secure_span(
            static_cast<const uint8_t*>(ptr_),
            size_);
        return Result<T, SodiumFailure>::Ok(std::forward<F>(func)(secure_span));
    }
    template<typename F>
    auto WithWriteAccess(F&& func) -> Result<std::invoke_result_t<F, std::span<uint8_t>>, SodiumFailure> {
        using T = std::invoke_result_t<F, std::span<uint8_t>>;
        if (IsInvalid()) {
            return Result<T, SodiumFailure>::Err(
                SodiumFailure::InvalidOperation("Handle has been disposed"));
        }
        std::span<uint8_t> secure_span(
            static_cast<uint8_t*>(ptr_),
            size_);
        return Result<T, SodiumFailure>::Ok(std::forward<F>(func)(secure_span));
    }
    [[nodiscard]] bool IsInvalid() const noexcept {
        return ptr_ == nullptr;
    }
    [[nodiscard]] size_t Size() const noexcept {
        return size_;
    }
private:
    SecureMemoryHandle(void* ptr, const size_t size) noexcept
        : ptr_(ptr), size_(size) {}
    void* ptr_;      
    size_t size_;    
};
} 
