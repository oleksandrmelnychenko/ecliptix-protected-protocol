/**
 * @file epp_internal.hpp
 * @brief Internal shared types and helpers for EPP C API implementations
 *
 * This header is NOT part of the public API. It provides shared definitions
 * used by both the client (epp_api.cpp) and server (epp_server_api.cpp) APIs.
 */

#ifndef EPP_INTERNAL_HPP
#define EPP_INTERNAL_HPP

#include "ecliptix/protocol/protocol_system.hpp"
#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/models/bundles/local_public_key_bundle.hpp"
#include "ecliptix/core/result.hpp"
#include "protocol/key_exchange.pb.h"
#include <memory>
#include <string>
#include <span>

// Forward declarations for internal use
namespace ecliptix::protocol {
class ProtocolSystem;
class IProtocolEventHandler;
}

namespace ecliptix::protocol::identity {
class IdentityKeys;
}

/**
 * @brief Opaque handle wrapping a ProtocolSystem instance
 */
struct ProtocolSystemHandle {
    std::unique_ptr<ecliptix::protocol::ProtocolSystem> system;
    std::shared_ptr<ecliptix::protocol::IProtocolEventHandler> event_handler;
};

/**
 * @brief Opaque handle wrapping identity keys
 */
struct EppIdentityHandle {
    std::unique_ptr<ecliptix::protocol::identity::IdentityKeys> identity_keys;
};

/**
 * @brief Internal helper functions for C API implementations
 *
 * These functions are shared between client and server API implementations.
 */
namespace epp::internal {

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::identity;
using namespace ecliptix::protocol::models;
using ecliptix::proto::protocol::PublicKeyBundle;

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

/**
 * @brief Build a LocalPublicKeyBundle from a protobuf PublicKeyBundle
 * @return Result containing the bundle or an error
 */
Result<LocalPublicKeyBundle, ProtocolFailure> build_local_bundle(const PublicKeyBundle& proto_bundle);

/**
 * @brief Event handler implementation for C API callbacks
 */
class CApiEventHandler : public IProtocolEventHandler {
public:
    CApiEventHandler(EppEventCallback callback, void* user_data);
    void OnProtocolStateChanged(uint32_t connection_id) override;
    void OnRatchetRequired(uint32_t connection_id, const std::string& reason) override;

private:
    EppEventCallback callback_;
    void* user_data_;
};

} // namespace epp::internal

#endif // EPP_INTERNAL_HPP
