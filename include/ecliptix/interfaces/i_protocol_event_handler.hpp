#pragma once
#include <cstdint>
#include <string>
namespace ecliptix::protocol {
class IProtocolEventHandler {
public:
    virtual ~IProtocolEventHandler() = default;
    virtual void OnProtocolStateChanged(uint32_t connection_id) = 0;
    virtual void OnRatchetRequired(uint32_t connection_id, const std::string& reason) = 0;
};
} 
