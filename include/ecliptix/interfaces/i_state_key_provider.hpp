#pragma once
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"

namespace ecliptix::protocol::interfaces {

class IStateKeyProvider {
public:
    virtual ~IStateKeyProvider() = default;

    [[nodiscard]] virtual Result<crypto::SecureMemoryHandle, ProtocolFailure> GetStateEncryptionKey() = 0;
};

}
