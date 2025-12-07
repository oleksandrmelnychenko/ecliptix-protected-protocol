#pragma once

#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"

#include <span>
#include <cstddef>
#include <cstdint>

namespace ecliptix::protocol::crypto {

/**
 * @brief RAII wrapper for libsodium secure memory
 *
 * Manages memory allocated via sodium_malloc with the following properties:
 * - Guard pages before/after (detect buffer overflows)
 * - Memory locked in RAM (no swap)
 * - Automatically zeroed on free
 * - Protected from dumps/core files
 *
 * This class is:
 * - Move-only (non-copyable) - ensures single ownership
 * - Exception-safe - destructor always frees
 * - Thread-compatible - can be used from different threads with external sync
 *
 * Example:
 * @code
 * auto handle_result = SecureMemoryHandle::Allocate(32);
 * if (handle_result.IsOk()) {
 *     auto handle = std::move(handle_result).Unwrap();
 *
 *     std::vector<uint8_t> data(32);
 *     // ... fill data ...
 *     handle.Write(data);
 *
 *     // handle is automatically freed when going out of scope
 * }
 * @endcode
 */
class SecureMemoryHandle {
public:
    // ========================================================================
    // Construction / Destruction
    // ========================================================================

    /**
     * @brief Allocate secure memory
     *
     * @param size Number of bytes to allocate
     * @return Ok(SecureMemoryHandle) or Err on allocation failure
     */
    static Result<SecureMemoryHandle, SodiumFailure> Allocate(size_t size);

    /**
     * @brief Destructor - automatically frees secure memory
     */
    ~SecureMemoryHandle();

    /**
     * @brief Default constructor - creates invalid handle
     *
     * Creates an empty handle with nullptr. Useful for containers.
     */
    SecureMemoryHandle() noexcept : ptr_(nullptr), size_(0) {}

    // Move-only semantics
    SecureMemoryHandle(SecureMemoryHandle&& other) noexcept;
    SecureMemoryHandle& operator=(SecureMemoryHandle&& other) noexcept;

    // Non-copyable
    SecureMemoryHandle(const SecureMemoryHandle&) = delete;
    SecureMemoryHandle& operator=(const SecureMemoryHandle&) = delete;

    // ========================================================================
    // Memory Operations
    // ========================================================================

    /**
     * @brief Write data to secure memory
     *
     * @param data Data to write (must be <= allocated size)
     * @return Ok on success, Err if buffer too small or handle invalid
     */
    Result<Unit, SodiumFailure> Write(std::span<const uint8_t> data);

    /**
     * @brief Read data from secure memory
     *
     * @param output Buffer to read into (must be >= allocated size)
     * @return Ok on success, Err if buffer too small or handle invalid
     */
    Result<Unit, SodiumFailure> Read(std::span<uint8_t> output) const;

    /**
     * @brief Read data into a new vector
     *
     * @param size Number of bytes to read (must be <= allocated size)
     * @return Ok(vector) with data, or Err
     */
    Result<std::vector<uint8_t>, SodiumFailure> ReadBytes(size_t size) const;

    /**
     * @brief Execute a function with read-only access to the secure memory
     *
     * Prevents the need to copy data out of secure memory.
     *
     * @param func Function to execute with std::span<const uint8_t>
     * @return Result from the function
     */
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

    /**
     * @brief Execute a function with read-write access to the secure memory
     *
     * USE WITH CAUTION - ensures you don't accidentally expose secure data
     *
     * @param func Function to execute with std::span<uint8_t>
     * @return Result from the function
     */
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

    // ========================================================================
    // State Queries
    // ========================================================================

    /**
     * @brief Check if handle is invalid (null or moved-from)
     */
    [[nodiscard]] bool IsInvalid() const noexcept {
        return ptr_ == nullptr;
    }

    /**
     * @brief Get allocated size in bytes
     */
    [[nodiscard]] size_t Size() const noexcept {
        return size_;
    }

private:
    // Private constructor - use Allocate() factory
    SecureMemoryHandle(void* ptr, size_t size) noexcept
        : ptr_(ptr), size_(size) {}

    void* ptr_;      // Pointer to secure memory
    size_t size_;    // Allocated size in bytes
};

} // namespace ecliptix::protocol::crypto
