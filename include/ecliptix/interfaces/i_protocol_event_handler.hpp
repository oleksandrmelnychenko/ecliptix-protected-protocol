#pragma once
#include <cstdint>
#include <string>
namespace ecliptix::protocol {
class IProtocolEventHandler {
public:
    virtual ~IProtocolEventHandler() = default;
    virtual void OnProtocolStateChanged(uint32_t connect_id) = 0;
    virtual void OnRatchetRequired(uint32_t connect_id, const std::string& reason) = 0;
};
} 
