#pragma once
#include <cstdint>
namespace ecliptix::protocol {
class IProtocolEventHandler {
public:
    virtual ~IProtocolEventHandler() = default;
    virtual void OnProtocolStateChanged(uint32_t connect_id) = 0;
};
} 
