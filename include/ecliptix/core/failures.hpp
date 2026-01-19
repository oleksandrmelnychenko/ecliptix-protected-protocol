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
enum class ProtocolFailureType {
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
    ObjectDisposed,
    ReplayAttack,
    InvalidState,
    NullPointer
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
class ProtocolFailure {
public:
    ProtocolFailureType type;
    std::string message;
    ProtocolFailure(const ProtocolFailureType t, std::string msg)
        : type(t), message(std::move(msg)) {}
    static ProtocolFailure Generic(std::string msg) {
        return {ProtocolFailureType::Generic, std::move(msg)};
    }
    static ProtocolFailure KeyGeneration(std::string msg) {
        return {ProtocolFailureType::KeyGeneration, std::move(msg)};
    }
    static ProtocolFailure DeriveKey(std::string msg) {
        return {ProtocolFailureType::DeriveKey, std::move(msg)};
    }
    static ProtocolFailure InvalidInput(std::string msg) {
        return {ProtocolFailureType::InvalidInput, std::move(msg)};
    }
    static ProtocolFailure PrepareLocal(std::string msg) {
        return {ProtocolFailureType::PrepareLocal, std::move(msg)};
    }
    static ProtocolFailure PeerPubKey(std::string msg) {
        return {ProtocolFailureType::PeerPubKey, std::move(msg)};
    }
    static ProtocolFailure Handshake(std::string msg) {
        return {ProtocolFailureType::Handshake, std::move(msg)};
    }
    static ProtocolFailure Decode(std::string msg) {
        return {ProtocolFailureType::Decode, std::move(msg)};
    }
    static ProtocolFailure Encode(std::string msg) {
        return {ProtocolFailureType::Encode, std::move(msg)};
    }
    static ProtocolFailure BufferTooSmall(std::string msg) {
        return {ProtocolFailureType::BufferTooSmall, std::move(msg)};
    }
    static ProtocolFailure ObjectDisposed(std::string msg) {
        return {ProtocolFailureType::ObjectDisposed, std::move(msg)};
    }
    static ProtocolFailure ReplayAttack(std::string msg) {
        return {ProtocolFailureType::ReplayAttack, std::move(msg)};
    }
    static ProtocolFailure InvalidState(std::string msg) {
        return {ProtocolFailureType::InvalidState, std::move(msg)};
    }
    static ProtocolFailure NullPointer(std::string msg) {
        return {ProtocolFailureType::NullPointer, std::move(msg)};
    }
    static ProtocolFailure FromSodiumFailure(const SodiumFailure& sf) {
        return Generic(sf.message);
    }
};
}
