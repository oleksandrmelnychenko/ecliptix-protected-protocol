#include "ecliptix/protocol/chain_step/ecliptix_protocol_chain_step.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/hkdf.hpp"

#include <algorithm>
#include <cstring>

// Protobuf generated header
#include "protocol/protocol_state.pb.h"

namespace ecliptix::protocol::chain_step {

using crypto::SodiumInterop;
using crypto::Hkdf;
using proto::protocol::ChainStepState;

// ============================================================================
// Helper: Convert SodiumFailure to EcliptixProtocolFailure
// ============================================================================

namespace {

template<typename T>
Result<T, EcliptixProtocolFailure> ConvertSodiumResult(Result<T, SodiumFailure>&& result) {
    if (result.IsOk()) {
        return Result<T, EcliptixProtocolFailure>::Ok(std::move(result).Unwrap());
    }
    return Result<T, EcliptixProtocolFailure>::Err(
        EcliptixProtocolFailure::Generic("Sodium operation failed"));
}

} // anonymous namespace

// ============================================================================
// Private Constructor
// ============================================================================

EcliptixProtocolChainStep::EcliptixProtocolChainStep(
    ChainStepType step_type,
    SecureMemoryHandle chain_key_handle,
    uint32_t initial_index,
    std::optional<SecureMemoryHandle> dh_private_key_handle,
    std::optional<std::vector<uint8_t>> dh_public_key)
    : lock_(std::make_unique<std::mutex>())
    , step_type_(step_type)
    , chain_key_handle_(std::move(chain_key_handle))
    , current_index_(initial_index)
    , dh_private_key_handle_(std::move(dh_private_key_handle))
    , dh_public_key_(std::move(dh_public_key))
    , cached_message_keys_()
    , disposed_(false) {
}

// ============================================================================
// Destructor
// ============================================================================

EcliptixProtocolChainStep::~EcliptixProtocolChainStep() {
    if (lock_) {
        std::lock_guard<std::mutex> guard(*lock_);
        disposed_ = true;

        // Wipe DH public key if present
        if (dh_public_key_.has_value()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(*dh_public_key_));
        }

        // SecureMemoryHandle and std::map<uint32_t, SecureMemoryHandle> automatically
        // wipe their contents via destructors (libsodium secure memory)
    }
}

// ============================================================================
// Factory Methods
// ============================================================================

Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> EcliptixProtocolChainStep::Create(
    ChainStepType step_type,
    std::span<const uint8_t> initial_chain_key,
    std::optional<std::span<const uint8_t>> dh_private_key,
    std::optional<std::span<const uint8_t>> dh_public_key) {

    // Validate chain key
    auto validate_result = ValidateChainKey(initial_chain_key);
    if (validate_result.IsErr()) {
        return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(validate_result.UnwrapErr());
    }

    // Allocate secure memory for chain key
    auto chain_key_result = ConvertSodiumResult(SecureMemoryHandle::Allocate(Constants::X_25519_KEY_SIZE));
    if (chain_key_result.IsErr()) {
        return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(chain_key_result.UnwrapErr());
    }
    auto chain_key_handle = std::move(chain_key_result).Unwrap();

    // Copy initial chain key to secure memory
    auto write_result = chain_key_handle.Write(initial_chain_key);
    if (write_result.IsErr()) {
        return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("Failed to write chain key to secure memory"));
    }

    // Handle DH private key (if provided)
    std::optional<SecureMemoryHandle> dh_private_key_handle;
    if (dh_private_key.has_value()) {
        if (dh_private_key->size() != Constants::X_25519_PRIVATE_KEY_SIZE) {
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("DH private key must be 32 bytes"));
        }

        auto dh_sk_result = ConvertSodiumResult(SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE));
        if (dh_sk_result.IsErr()) {
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(dh_sk_result.UnwrapErr());
        }
        auto dh_sk_handle = std::move(dh_sk_result).Unwrap();
        auto dh_write_result = dh_sk_handle.Write(*dh_private_key);
        if (dh_write_result.IsErr()) {
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to write DH private key to secure memory"));
        }
        dh_private_key_handle = std::move(dh_sk_handle);
    }

    // Handle DH public key (if provided)
    std::optional<std::vector<uint8_t>> dh_public_key_copy;
    if (dh_public_key.has_value()) {
        if (dh_public_key->size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("DH public key must be 32 bytes"));
        }

        dh_public_key_copy = std::vector<uint8_t>(dh_public_key->begin(), dh_public_key->end());
    }

    return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Ok(
        EcliptixProtocolChainStep(
            step_type,
            std::move(chain_key_handle),
            ProtocolConstants::INITIAL_INDEX,
            std::move(dh_private_key_handle),
            std::move(dh_public_key_copy)
        )
    );
}

Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> EcliptixProtocolChainStep::FromProtoState(
    ChainStepType step_type,
    const ChainStepState& proto) {

    // Extract chain key from protobuf
    if (proto.chain_key().size() != Constants::X_25519_KEY_SIZE) {
        return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput("Invalid chain key size in protobuf state"));
    }

    std::vector<uint8_t> chain_key_bytes(proto.chain_key().begin(), proto.chain_key().end());

    // Extract DH keys if present
    std::optional<std::span<const uint8_t>> dh_private_key;
    std::vector<uint8_t> dh_private_key_bytes;
    if (!proto.dh_private_key().empty()) {
        if (proto.dh_private_key().size() != Constants::X_25519_PRIVATE_KEY_SIZE) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(chain_key_bytes));
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Invalid DH private key size in protobuf state"));
        }
        dh_private_key_bytes = std::vector<uint8_t>(proto.dh_private_key().begin(), proto.dh_private_key().end());
        dh_private_key = std::span<const uint8_t>(dh_private_key_bytes);
    }

    std::optional<std::span<const uint8_t>> dh_public_key;
    std::vector<uint8_t> dh_public_key_bytes;
    if (!proto.dh_public_key().empty()) {
        if (proto.dh_public_key().size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(chain_key_bytes));
            if (!dh_private_key_bytes.empty()) {
                SodiumInterop::SecureWipe(std::span<uint8_t>(dh_private_key_bytes));
            }
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Invalid DH public key size in protobuf state"));
        }
        dh_public_key_bytes = std::vector<uint8_t>(proto.dh_public_key().begin(), proto.dh_public_key().end());
        dh_public_key = std::span<const uint8_t>(dh_public_key_bytes);
    }

    // Create chain step
    auto result = Create(step_type, chain_key_bytes, dh_private_key, dh_public_key);

    // Secure wipe temporary buffers
    SodiumInterop::SecureWipe(std::span<uint8_t>(chain_key_bytes));
    if (!dh_private_key_bytes.empty()) {
        SodiumInterop::SecureWipe(std::span<uint8_t>(dh_private_key_bytes));
    }

    if (result.IsErr()) {
        return result;
    }

    auto chain_step = std::move(result).Unwrap();

    // Set the current index from protobuf
    auto set_index_result = chain_step.SetCurrentIndex(proto.current_index());
    if (set_index_result.IsErr()) {
        return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(set_index_result.UnwrapErr());
    }

    // TODO: Restore cached message keys from proto.cached_message_keys()

    return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Ok(std::move(chain_step));
}

// ============================================================================
// Core Symmetric Ratchet Algorithm
// ============================================================================

Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::DeriveNextChainKeys(
    std::span<const uint8_t> current_chain_key,
    uint32_t index,
    std::span<uint8_t> next_chain_key,
    std::span<uint8_t> message_key) {

    if (current_chain_key.size() != Constants::X_25519_KEY_SIZE) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput("Chain key must be 32 bytes"));
    }

    if (next_chain_key.size() != Constants::X_25519_KEY_SIZE) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput("Next chain key buffer must be 32 bytes"));
    }

    if (message_key.size() != Constants::X_25519_KEY_SIZE) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput("Message key buffer must be 32 bytes"));
    }

    // Derive message key: HKDF(current_chain_key, null, "Ecliptix-Msg")
    TRY_UNIT(Hkdf::DeriveKey(
        current_chain_key,
        message_key,
        {},  // No salt (empty span)
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(ProtocolConstants::MSG_INFO.data()),
            ProtocolConstants::MSG_INFO.size()
        )
    ));

    // Derive next chain key: HKDF(current_chain_key, null, "Ecliptix-Chain")
    TRY_UNIT(Hkdf::DeriveKey(
        current_chain_key,
        next_chain_key,
        {},  // No salt (empty span)
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(ProtocolConstants::CHAIN_INFO.data()),
            ProtocolConstants::CHAIN_INFO.size()
        )
    ));

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

// ============================================================================
// IKeyProvider Interface Implementation
// ============================================================================

Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::ExecuteWithKey(
    uint32_t index,
    std::function<Result<Unit, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation) {

    std::lock_guard<std::mutex> guard(*lock_);
    TRY_UNIT(CheckDisposed());

    // Case 1: Cached key (out-of-order message or previously skipped)
    auto cached_key_opt = TakeCachedMessageKey(index);
    if (cached_key_opt.has_value()) {
        SecureMemoryHandle cached_handle = std::move(*cached_key_opt);
        auto key_bytes_result = ConvertSodiumResult(cached_handle.ReadBytes(Constants::X_25519_KEY_SIZE));
        if (key_bytes_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(key_bytes_result.UnwrapErr());
        }
        auto key_bytes = std::move(key_bytes_result).Unwrap();

        auto result = operation(key_bytes);

        // Securely wipe before returning
        SodiumInterop::SecureWipe(std::span<uint8_t>(key_bytes));

        return result;
    }

    // Case 2: Current key (most common case)
    if (index == current_index_) {
        // Read current chain key
        auto chain_key_result = ConvertSodiumResult(chain_key_handle_.ReadBytes(Constants::X_25519_KEY_SIZE));
        if (chain_key_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(chain_key_result.UnwrapErr());
        }
        auto current_chain_key = std::move(chain_key_result).Unwrap();

        // Derive message key and next chain key
        std::vector<uint8_t> message_key(Constants::X_25519_KEY_SIZE);
        std::vector<uint8_t> next_chain_key(Constants::X_25519_KEY_SIZE);

        auto derive_result = DeriveNextChainKeys(
            current_chain_key,
            index,
            next_chain_key,
            message_key
        );

        // Wipe current chain key immediately
        SodiumInterop::SecureWipe(std::span<uint8_t>(current_chain_key));

        if (derive_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(next_chain_key));
            SodiumInterop::SecureWipe(std::span<uint8_t>(message_key));
            return derive_result;
        }

        // Update chain key handle with next chain key
        auto write_result = chain_key_handle_.Write(next_chain_key);
        SodiumInterop::SecureWipe(std::span<uint8_t>(next_chain_key));

        if (write_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(message_key));
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to update chain key"));
        }

        // Increment index
        current_index_++;

        // Execute operation with message key
        auto result = operation(message_key);

        // Wipe message key before returning
        SodiumInterop::SecureWipe(std::span<uint8_t>(message_key));

        return result;
    }

    // Case 3: Future key (error - should call SkipKeysUntil first)
    if (index > current_index_) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("Cannot access future key - call SkipKeysUntil first"));
    }

    // Case 4: Past key not in cache (already used or pruned)
    return Result<Unit, EcliptixProtocolFailure>::Err(
        EcliptixProtocolFailure::Generic("Key not available - already used or pruned"));
}

// ============================================================================
// Key Access
// ============================================================================

Result<RatchetChainKey, EcliptixProtocolFailure> EcliptixProtocolChainStep::GetOrDeriveKeyFor(uint32_t index) {
    std::lock_guard<std::mutex> guard(*lock_);
    auto disposed_check = CheckDisposed();
    if (disposed_check.IsErr()) {
        return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
    }

    // If requesting future key, skip to it
    if (index > current_index_) {
        auto skip_result = SkipKeysUntil(index);
        if (skip_result.IsErr()) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(skip_result.UnwrapErr());
        }
    }

    // Return lightweight reference to this provider
    return Result<RatchetChainKey, EcliptixProtocolFailure>::Ok(
        RatchetChainKey(this, index)
    );
}

Result<std::vector<uint8_t>, EcliptixProtocolFailure> EcliptixProtocolChainStep::GetCurrentChainKey() const {
    std::lock_guard<std::mutex> guard(*lock_);
    auto disposed_check = CheckDisposed();
    if (disposed_check.IsErr()) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
    }

    auto bytes_result = ConvertSodiumResult(chain_key_handle_.ReadBytes(Constants::X_25519_KEY_SIZE));
    if (bytes_result.IsErr()) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(bytes_result.UnwrapErr());
    }
    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(std::move(bytes_result).Unwrap());
}

// ============================================================================
// Index Management
// ============================================================================

Result<uint32_t, EcliptixProtocolFailure> EcliptixProtocolChainStep::GetCurrentIndex() const {
    std::lock_guard<std::mutex> guard(*lock_);
    auto disposed_check = CheckDisposed();
    if (disposed_check.IsErr()) {
        return Result<uint32_t, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
    }

    return Result<uint32_t, EcliptixProtocolFailure>::Ok(current_index_);
}

Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::SetCurrentIndex(uint32_t new_index) {
    std::lock_guard<std::mutex> guard(*lock_);
    auto disposed_check = CheckDisposed();
    if (disposed_check.IsErr()) {
        return disposed_check;
    }

    current_index_ = new_index;
    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

// ============================================================================
// Out-of-Order Message Support
// ============================================================================

Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::SkipKeysUntil(uint32_t target_index) {
    // Note: Lock already held by caller (GetOrDeriveKeyFor)

    if (target_index <= current_index_) {
        // No need to skip
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    // Check skip limit to prevent DoS
    uint32_t skip_count = target_index - current_index_;
    if (skip_count > ProtocolConstants::MAX_SKIP_MESSAGE_KEYS) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("Skip gap too large - possible DoS attempt"));
    }

    // Read current chain key
    auto chain_key_result = ConvertSodiumResult(chain_key_handle_.ReadBytes(Constants::X_25519_KEY_SIZE));
    if (chain_key_result.IsErr()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(chain_key_result.UnwrapErr());
    }
    auto mut_chain_key = std::move(chain_key_result).Unwrap();

    // Derive and cache keys from (current_index + 1) to (target_index - 1)
    for (uint32_t i = current_index_ + 1; i < target_index; ++i) {
        std::vector<uint8_t> message_key(Constants::X_25519_KEY_SIZE);
        std::vector<uint8_t> next_chain_key(Constants::X_25519_KEY_SIZE);

        auto derive_result = DeriveNextChainKeys(mut_chain_key, i, next_chain_key, message_key);

        if (derive_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(mut_chain_key));
            SodiumInterop::SecureWipe(std::span<uint8_t>(message_key));
            SodiumInterop::SecureWipe(std::span<uint8_t>(next_chain_key));
            return derive_result;
        }

        // Cache the message key
        auto store_result = StoreMessageKey(i, message_key);
        SodiumInterop::SecureWipe(std::span<uint8_t>(message_key));

        if (store_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(mut_chain_key));
            SodiumInterop::SecureWipe(std::span<uint8_t>(next_chain_key));
            return store_result;
        }

        // Advance chain key
        mut_chain_key = std::move(next_chain_key);
    }

    // Update chain key handle with the final chain key
    auto write_result = chain_key_handle_.Write(mut_chain_key);
    SodiumInterop::SecureWipe(std::span<uint8_t>(mut_chain_key));

    if (write_result.IsErr()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("Failed to update chain key after skip"));
    }

    // Update current index
    current_index_ = target_index - 1;

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

void EcliptixProtocolChainStep::PruneOldKeys() {
    std::lock_guard<std::mutex> guard(*lock_);

    if (disposed_) {
        return;
    }

    // Only prune if cache is too large
    if (cached_message_keys_.size() <= ProtocolConstants::MESSAGE_KEY_CACHE_WINDOW) {
        return;
    }

    // Calculate cutoff index
    uint32_t cutoff_index = current_index_ > ProtocolConstants::MESSAGE_KEY_CACHE_WINDOW
        ? current_index_ - ProtocolConstants::MESSAGE_KEY_CACHE_WINDOW
        : 0;

    // Remove all keys before cutoff
    auto it = cached_message_keys_.begin();
    while (it != cached_message_keys_.end() && it->first < cutoff_index) {
        it = cached_message_keys_.erase(it);  // SecureMemoryHandle destructor wipes
    }
}

// ============================================================================
// DH Ratchet Integration
// ============================================================================

Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::UpdateKeysAfterDhRatchet(
    std::span<const uint8_t> new_chain_key,
    std::optional<std::span<const uint8_t>> new_dh_private_key,
    std::optional<std::span<const uint8_t>> new_dh_public_key) {

    std::lock_guard<std::mutex> guard(*lock_);
    auto disposed_check = CheckDisposed();
    if (disposed_check.IsErr()) {
        return disposed_check;
    }

    // Validate new chain key
    auto validate_result = ValidateChainKey(new_chain_key);
    if (validate_result.IsErr()) {
        return validate_result;
    }

    // Update chain key
    auto write_result = chain_key_handle_.Write(new_chain_key);
    if (write_result.IsErr()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("Failed to write new chain key"));
    }

    // Reset index to 0
    current_index_ = ProtocolConstants::RESET_INDEX;

    // Clear cached keys (forward secrecy)
    cached_message_keys_.clear();

    // Update DH private key if provided
    if (new_dh_private_key.has_value()) {
        if (new_dh_private_key->size() != Constants::X_25519_PRIVATE_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("DH private key must be 32 bytes"));
        }

        auto handle_result = ConvertSodiumResult(SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE));
        if (handle_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(handle_result.UnwrapErr());
        }
        auto new_handle = std::move(handle_result).Unwrap();
        auto new_write_result = new_handle.Write(*new_dh_private_key);
        if (new_write_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to write new DH private key"));
        }
        dh_private_key_handle_ = std::move(new_handle);
    }

    // Update DH public key if provided
    if (new_dh_public_key.has_value()) {
        if (new_dh_public_key->size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("DH public key must be 32 bytes"));
        }

        // Wipe old public key if present
        if (dh_public_key_.has_value()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(*dh_public_key_));
        }

        dh_public_key_ = std::vector<uint8_t>(new_dh_public_key->begin(), new_dh_public_key->end());
    }

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

// ============================================================================
// DH Key Access
// ============================================================================

Result<Option<std::vector<uint8_t>>, EcliptixProtocolFailure> EcliptixProtocolChainStep::ReadDhPublicKey() const {
    std::lock_guard<std::mutex> guard(*lock_);

    auto disposed_check = CheckDisposed();
    if (disposed_check.IsErr()) {
        return Result<Option<std::vector<uint8_t>>, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
    }

    if (!dh_public_key_.has_value()) {
        return Result<Option<std::vector<uint8_t>>, EcliptixProtocolFailure>::Ok(std::nullopt);
    }

    // Return a copy
    std::vector<uint8_t> copy(*dh_public_key_);
    return Result<Option<std::vector<uint8_t>>, EcliptixProtocolFailure>::Ok(std::move(copy));
}

Option<const SecureMemoryHandle*> EcliptixProtocolChainStep::GetDhPrivateKeyHandle() const {
    std::lock_guard<std::mutex> guard(*lock_);

    if (disposed_ || !dh_private_key_handle_.has_value()) {
        return std::nullopt;
    }

    return &(*dh_private_key_handle_);
}

// ============================================================================
// Serialization
// ============================================================================

Result<ChainStepState, EcliptixProtocolFailure> EcliptixProtocolChainStep::ToProtoState() const {
    std::lock_guard<std::mutex> guard(*lock_);

    auto disposed_check = CheckDisposed();
    if (disposed_check.IsErr()) {
        return Result<ChainStepState, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
    }

    ChainStepState proto;

    // Set current index
    proto.set_current_index(current_index_);

    // Set chain key
    auto chain_key_result = chain_key_handle_.ReadBytes(Constants::X_25519_KEY_SIZE);
    if (chain_key_result.IsErr()) {
        return Result<ChainStepState, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("Failed to read chain key for serialization"));
    }
    auto chain_key_bytes = chain_key_result.Unwrap();
    proto.set_chain_key(chain_key_bytes.data(), chain_key_bytes.size());
    SodiumInterop::SecureWipe(std::span<uint8_t>(chain_key_bytes));

    // Set DH private key if present
    if (dh_private_key_handle_.has_value()) {
        auto dh_sk_result = dh_private_key_handle_->ReadBytes(Constants::X_25519_PRIVATE_KEY_SIZE);
        if (dh_sk_result.IsErr()) {
            return Result<ChainStepState, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to read DH private key for serialization"));
        }
        auto dh_sk_bytes = dh_sk_result.Unwrap();
        proto.set_dh_private_key(dh_sk_bytes.data(), dh_sk_bytes.size());
        SodiumInterop::SecureWipe(std::span<uint8_t>(dh_sk_bytes));
    }

    // Set DH public key if present
    if (dh_public_key_.has_value()) {
        proto.set_dh_public_key(dh_public_key_->data(), dh_public_key_->size());
    }

    // TODO: Serialize cached message keys

    return Result<ChainStepState, EcliptixProtocolFailure>::Ok(std::move(proto));
}

// ============================================================================
// Helper Methods
// ============================================================================

Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::StoreMessageKey(
    uint32_t index,
    std::span<const uint8_t> message_key) {

    // Allocate secure memory for the key
    auto handle_result = ConvertSodiumResult(SecureMemoryHandle::Allocate(Constants::X_25519_KEY_SIZE));
    if (handle_result.IsErr()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(handle_result.UnwrapErr());
    }
    auto handle = std::move(handle_result).Unwrap();
    auto store_write_result = handle.Write(message_key);
    if (store_write_result.IsErr()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("Failed to store message key in cache"));
    }

    // Store in cache
    cached_message_keys_[index] = std::move(handle);

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

Option<SecureMemoryHandle> EcliptixProtocolChainStep::TakeCachedMessageKey(uint32_t index) {
    auto it = cached_message_keys_.find(index);
    if (it == cached_message_keys_.end()) {
        return std::nullopt;
    }

    // Move out and erase (single-use)
    SecureMemoryHandle handle = std::move(it->second);
    cached_message_keys_.erase(it);

    return std::move(handle);
}

Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::CheckDisposed() const {
    if (disposed_) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("ChainStep has been disposed"));
    }
    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::ValidateChainKey(
    std::span<const uint8_t> chain_key) {

    if (chain_key.size() != Constants::X_25519_KEY_SIZE) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput("Chain key must be 32 bytes"));
    }

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

} // namespace ecliptix::protocol::chain_step
