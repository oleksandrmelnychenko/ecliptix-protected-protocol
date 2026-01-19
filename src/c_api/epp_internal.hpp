/**
 * @file epp_internal.hpp
 * @brief Internal shared types and helpers for EPP C API implementations
 *
 * This header is NOT part of the public API. It provides shared definitions
 * used by the EPP C API implementation.
 */

#ifndef EPP_INTERNAL_HPP
#define EPP_INTERNAL_HPP

#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/protocol/handshake.hpp"
#include "ecliptix/protocol/session.hpp"
#include "ecliptix/core/result.hpp"
#include <memory>
#include <string>
#include <span>

/**
 * @brief Opaque handle wrapping identity keys
 */
struct EppIdentityHandle {
    std::unique_ptr<ecliptix::protocol::identity::IdentityKeys> identity_keys;
};

/**
 * @brief Opaque handle wrapping a protocol session
 */
struct EppSessionHandle {
    std::unique_ptr<ecliptix::protocol::Session> session;
};

/**
 * @brief Opaque handle wrapping a handshake initiator
 */
struct EppHandshakeInitiatorHandle {
    std::unique_ptr<ecliptix::protocol::HandshakeInitiator> handshake;
};

/**
 * @brief Opaque handle wrapping a handshake responder
 */
struct EppHandshakeResponderHandle {
    std::unique_ptr<ecliptix::protocol::HandshakeResponder> handshake;
};

/**
 * @brief Internal helper functions for C API implementations
 *
 * These functions are shared between client and server API implementations.
 */
namespace epp::internal {

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::identity;

/**
 * @brief Ensure libsodium is initialized
 * @return EPP_SUCCESS if initialized, error code otherwise
 */
EppErrorCode EnsureInitialized();

/**
 * @brief Fill an error structure with code and message
 */
void fill_error(EppError* out_error, EppErrorCode code, const std::string& message);

/**
 * @brief Convert a ProtocolFailure to an error code and fill the error struct
 * @return The corresponding EppErrorCode
 */
EppErrorCode fill_error_from_failure(EppError* out_error, const ProtocolFailure& failure);

/**
 * @brief Validate a buffer parameter (data pointer vs length)
 * @return true if valid, false otherwise (fills out_error)
 */
bool validate_buffer_param(const uint8_t* data, size_t length, EppError* out_error);

/**
 * @brief Validate an output handle pointer is not null
 * @return true if valid, false otherwise (fills out_error)
 */
bool validate_output_handle(const void* handle, EppError* out_error);

/**
 * @brief Copy data to an output buffer (allocates memory)
 * @return true on success, false on failure (fills out_error)
 */
bool copy_to_buffer(std::span<const uint8_t> input, EppBuffer* out_buffer, EppError* out_error);

} // namespace epp::internal

#endif // EPP_INTERNAL_HPP
