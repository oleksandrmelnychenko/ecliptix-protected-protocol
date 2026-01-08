#pragma once
#include <string>
#include <string_view>
#include <exception>
#include <variant>
namespace ecliptix::protocol {
enum class SodiumFailureType {
    LibraryNotFound,
    InitializationFailed,
    BufferTooSmall,
    BufferTooLarge,
    SecureWipeFailed,
    MemoryPinningFailed,
    AllocationFailed,
    WriteOperationFailed,
    ReadOperationFailed,
    ComparisonFailed,
    InvalidOperation
};
enum class EcliptixProtocolFailureType {
    Generic,
    KeyGeneration,
    DeriveKey,
    InvalidInput,
    PrepareLocal,
    PeerPubKey,
    Handshake,
    Decode,
    Encode,
    BufferTooSmall,
    ObjectDisposed
};
class SodiumFailure {
public:
    SodiumFailureType type;
    std::string message;
    SodiumFailure(const SodiumFailureType t, std::string msg)
        : type(t), message(std::move(msg)) {}
    static SodiumFailure LibraryNotFound(std::string msg) {
        return {SodiumFailureType::LibraryNotFound, std::move(msg)};
    }
    static SodiumFailure InitializationFailed(std::string msg) {
        return {SodiumFailureType::InitializationFailed, std::move(msg)};
    }
    static SodiumFailure BufferTooSmall(std::string msg) {
        return {SodiumFailureType::BufferTooSmall, std::move(msg)};
    }
    static SodiumFailure BufferTooLarge(std::string msg) {
        return {SodiumFailureType::BufferTooLarge, std::move(msg)};
    }
    static SodiumFailure SecureWipeFailed(std::string msg) {
        return {SodiumFailureType::SecureWipeFailed, std::move(msg)};
    }
    static SodiumFailure MemoryPinningFailed(std::string msg) {
        return {SodiumFailureType::MemoryPinningFailed, std::move(msg)};
    }
    static SodiumFailure AllocationFailed(std::string msg) {
        return {SodiumFailureType::AllocationFailed, std::move(msg)};
    }
    static SodiumFailure WriteOperationFailed(std::string msg) {
        return {SodiumFailureType::WriteOperationFailed, std::move(msg)};
    }
    static SodiumFailure ReadOperationFailed(std::string msg) {
        return {SodiumFailureType::ReadOperationFailed, std::move(msg)};
    }
    static SodiumFailure ComparisonFailed(std::string msg) {
        return {SodiumFailureType::ComparisonFailed, std::move(msg)};
    }
    static SodiumFailure InvalidOperation(std::string msg) {
        return {SodiumFailureType::InvalidOperation, std::move(msg)};
    }
};
class EcliptixProtocolFailure {
public:
    EcliptixProtocolFailureType type;
    std::string message;
    EcliptixProtocolFailure(const EcliptixProtocolFailureType t, std::string msg)
        : type(t), message(std::move(msg)) {}
    static EcliptixProtocolFailure Generic(std::string msg) {
        return {EcliptixProtocolFailureType::Generic, std::move(msg)};
    }
    static EcliptixProtocolFailure KeyGeneration(std::string msg) {
        return {EcliptixProtocolFailureType::KeyGeneration, std::move(msg)};
    }
    static EcliptixProtocolFailure DeriveKey(std::string msg) {
        return {EcliptixProtocolFailureType::DeriveKey, std::move(msg)};
    }
    static EcliptixProtocolFailure InvalidInput(std::string msg) {
        return {EcliptixProtocolFailureType::InvalidInput, std::move(msg)};
    }
    static EcliptixProtocolFailure PrepareLocal(std::string msg) {
        return {EcliptixProtocolFailureType::PrepareLocal, std::move(msg)};
    }
    static EcliptixProtocolFailure PeerPubKey(std::string msg) {
        return {EcliptixProtocolFailureType::PeerPubKey, std::move(msg)};
    }
    static EcliptixProtocolFailure Handshake(std::string msg) {
        return {EcliptixProtocolFailureType::Handshake, std::move(msg)};
    }
    static EcliptixProtocolFailure Decode(std::string msg) {
        return {EcliptixProtocolFailureType::Decode, std::move(msg)};
    }
    static EcliptixProtocolFailure Encode(std::string msg) {
        return {EcliptixProtocolFailureType::Encode, std::move(msg)};
    }
    static EcliptixProtocolFailure BufferTooSmall(std::string msg) {
        return {EcliptixProtocolFailureType::BufferTooSmall, std::move(msg)};
    }
    static EcliptixProtocolFailure ObjectDisposed(std::string msg) {
        return {EcliptixProtocolFailureType::ObjectDisposed, std::move(msg)};
    }
    static EcliptixProtocolFailure FromSodiumFailure(const SodiumFailure& sf) {
        return Generic(sf.message);
    }
};
} 
