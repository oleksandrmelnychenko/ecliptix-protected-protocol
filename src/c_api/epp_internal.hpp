#ifndef EPP_INTERNAL_HPP
#define EPP_INTERNAL_HPP

#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/protocol/handshake.hpp"
#include "ecliptix/protocol/session.hpp"
#include "ecliptix/core/result.hpp"
#include <memory>
#include <string>
#include <span>

struct EppIdentityHandle {
    std::unique_ptr<ecliptix::protocol::identity::IdentityKeys> identity_keys;
};

struct EppSessionHandle {
    std::unique_ptr<ecliptix::protocol::Session> session;
};

#ifndef EPP_SERVER_BUILD
struct EppHandshakeInitiatorHandle {
    std::unique_ptr<ecliptix::protocol::HandshakeInitiator> handshake;
};
#endif

struct EppHandshakeResponderHandle {
    std::unique_ptr<ecliptix::protocol::HandshakeResponder> handshake;
};

namespace epp::internal {

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::identity;

EppErrorCode EnsureInitialized();

void fill_error(EppError* out_error, EppErrorCode code, const std::string& message);

EppErrorCode fill_error_from_failure(EppError* out_error, const ProtocolFailure& failure);

bool validate_buffer_param(const uint8_t* data, size_t length, EppError* out_error);

bool validate_output_handle(const void* handle, EppError* out_error);

bool copy_to_buffer(std::span<const uint8_t> input, EppBuffer* out_buffer, EppError* out_error);

}

#endif
