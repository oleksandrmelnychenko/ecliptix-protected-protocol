#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"

#include <cstring>
#include <algorithm>

namespace ecliptix::protocol::crypto {

// ============================================================================
// Construction / Destruction
// ============================================================================

Result<SecureMemoryHandle, SodiumFailure> SecureMemoryHandle::Allocate(size_t size) {
    if (!SodiumInterop::IsInitialized()) {
        return Result<SecureMemoryHandle, SodiumFailure>::Err(
            SodiumFailure::InitializationFailed(
                std::string(ErrorMessages::NOT_INITIALIZED)));
    }

    if (size == 0) {
        return Result<SecureMemoryHandle, SodiumFailure>::Err(
            SodiumFailure::AllocationFailed(
                "Cannot allocate zero-sized secure memory"));
    }

    void* ptr = SodiumInterop::AllocateSecure(size);
    if (ptr == nullptr) {
        return Result<SecureMemoryHandle, SodiumFailure>::Err(
            SodiumFailure::AllocationFailed(
                std::string(ErrorMessages::FAILED_TO_ALLOCATE_SECURE_MEMORY) +
                std::to_string(size) + " bytes"));
    }

    return Result<SecureMemoryHandle, SodiumFailure>::Ok(
        SecureMemoryHandle(ptr, size));
}

SecureMemoryHandle::~SecureMemoryHandle() {
    if (ptr_ != nullptr) {
        SodiumInterop::FreeSecure(ptr_);
        ptr_ = nullptr;
        size_ = 0;
    }
}

SecureMemoryHandle::SecureMemoryHandle(SecureMemoryHandle&& other) noexcept
    : ptr_(other.ptr_)
    , size_(other.size_) {
    other.ptr_ = nullptr;
    other.size_ = 0;
}

SecureMemoryHandle& SecureMemoryHandle::operator=(SecureMemoryHandle&& other) noexcept {
    if (this != &other) {
        // Free current memory
        if (ptr_ != nullptr) {
            SodiumInterop::FreeSecure(ptr_);
        }

        // Transfer ownership
        ptr_ = other.ptr_;
        size_ = other.size_;

        // Reset other
        other.ptr_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

// ============================================================================
// Memory Operations
// ============================================================================

Result<Unit, SodiumFailure> SecureMemoryHandle::Write(std::span<const uint8_t> data) {
    if (IsInvalid()) {
        return Result<Unit, SodiumFailure>::Err(
            SodiumFailure::InvalidOperation(
                std::string(ErrorMessages::HANDLE_DISPOSED)));
    }

    if (data.size() > size_) {
        return Result<Unit, SodiumFailure>::Err(
            SodiumFailure::BufferTooSmall(
                std::string(ErrorMessages::DATA_EXCEEDS_BUFFER) +
                " (data: " + std::to_string(data.size()) +
                ", buffer: " + std::to_string(size_) + ")"));
    }

    try {
        std::memcpy(ptr_, data.data(), data.size());

        // Zero remaining bytes if data is smaller than allocation
        if (data.size() < size_) {
            std::memset(
                static_cast<uint8_t*>(ptr_) + data.size(),
                0,
                size_ - data.size());
        }

        return Result<Unit, SodiumFailure>::Ok(unit);

    } catch (const std::exception& ex) {
        return Result<Unit, SodiumFailure>::Err(
            SodiumFailure::WriteOperationFailed(
                "Failed to write to secure memory: " + std::string(ex.what())));
    }
}

Result<Unit, SodiumFailure> SecureMemoryHandle::Read(std::span<uint8_t> output) const {
    if (IsInvalid()) {
        return Result<Unit, SodiumFailure>::Err(
            SodiumFailure::InvalidOperation(
                std::string(ErrorMessages::HANDLE_DISPOSED)));
    }

    if (output.size() < size_) {
        return Result<Unit, SodiumFailure>::Err(
            SodiumFailure::BufferTooSmall(
                "Output buffer too small (requested: " + std::to_string(size_) +
                ", provided: " + std::to_string(output.size()) + ")"));
    }

    try {
        std::memcpy(output.data(), ptr_, size_);
        return Result<Unit, SodiumFailure>::Ok(unit);

    } catch (const std::exception& ex) {
        return Result<Unit, SodiumFailure>::Err(
            SodiumFailure::ReadOperationFailed(
                std::string(ErrorMessages::FAILED_TO_READ_SECURE_MEMORY) +
                ex.what()));
    }
}

Result<std::vector<uint8_t>, SodiumFailure> SecureMemoryHandle::ReadBytes(size_t size) const {
    if (IsInvalid()) {
        return Result<std::vector<uint8_t>, SodiumFailure>::Err(
            SodiumFailure::InvalidOperation(
                std::string(ErrorMessages::HANDLE_DISPOSED)));
    }

    if (size > size_) {
        return Result<std::vector<uint8_t>, SodiumFailure>::Err(
            SodiumFailure::BufferTooSmall(
                "Requested size exceeds allocated size"));
    }

    try {
        std::vector<uint8_t> result(size);
        std::memcpy(result.data(), ptr_, size);
        return Result<std::vector<uint8_t>, SodiumFailure>::Ok(std::move(result));

    } catch (const std::exception& ex) {
        return Result<std::vector<uint8_t>, SodiumFailure>::Err(
            SodiumFailure::ReadOperationFailed(
                std::string(ErrorMessages::FAILED_TO_READ_SECURE_MEMORY) +
                ex.what()));
    }
}

} // namespace ecliptix::protocol::crypto
