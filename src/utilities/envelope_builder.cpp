#include "ecliptix/utilities/envelope_builder.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/core/format.hpp"
#include "common/secure_envelope.pb.h"
#include <sodium.h>

namespace ecliptix::protocol::utilities {
    using Constants = Constants;
    using crypto::AesGcm;

    proto::common::EnvelopeMetadata
    EnvelopeBuilder::CreateEnvelopeMetadata(
        const uint32_t request_id,
        const std::vector<uint8_t> &nonce,
        const uint32_t ratchet_index,
        const std::vector<uint8_t> &channel_key_id,
        const proto::common::EnvelopeType envelope_type,
        const std::string &correlation_id) {
        proto::common::EnvelopeMetadata metadata;
        metadata.set_envelope_id(std::to_string(request_id));
        metadata.set_nonce(nonce.data(), nonce.size());
        metadata.set_ratchet_index(ratchet_index);
        metadata.set_envelope_type(envelope_type);
        if (channel_key_id.empty()) {
            auto generated_id = GenerateChannelKeyId();
            metadata.set_channel_key_id(generated_id.data(), generated_id.size());
        } else {
            metadata.set_channel_key_id(channel_key_id.data(), channel_key_id.size());
        }
        if (!correlation_id.empty()) {
            metadata.set_correlation_id(correlation_id);
        }
        return metadata;
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    EnvelopeBuilder::EncryptMetadata(
        const proto::common::EnvelopeMetadata &metadata,
        std::span<const uint8_t> header_encryption_key,
        std::span<const uint8_t> header_nonce,
        std::span<const uint8_t> associated_data) {
        std::vector<uint8_t> metadata_bytes;
        try {
            size_t size = metadata.ByteSizeLong();
            metadata_bytes.resize(size);
            if (!metadata.SerializeToArray(metadata_bytes.data(), static_cast<int>(size))) {
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Encode("Failed to serialize EnvelopeMetadata to protobuf"));
            }
            auto encrypt_result = AesGcm::Encrypt(
                header_encryption_key,
                header_nonce,
                metadata_bytes,
                associated_data); {
                auto __wipe = crypto::SodiumInterop::SecureWipe(std::span(metadata_bytes));
                (void) __wipe;
            }
            if (encrypt_result.IsErr()) {
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic(
                        ecliptix::compat::format("Failed to encrypt metadata: {}",
                                    encrypt_result.UnwrapErr().message)));
            }
            return encrypt_result;
        } catch (const std::exception &ex) {
            if (!metadata_bytes.empty()) {
                {
                    auto __wipe = crypto::SodiumInterop::SecureWipe(std::span(metadata_bytes));
                    (void) __wipe;
                }
            }
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    ecliptix::compat::format("Exception during metadata encryption: {}", ex.what())));
        }
    }

    Result<proto::common::EnvelopeMetadata, EcliptixProtocolFailure>
    EnvelopeBuilder::DecryptMetadata(
        std::span<const uint8_t> encrypted_metadata,
        std::span<const uint8_t> header_encryption_key,
        std::span<const uint8_t> header_nonce,
        std::span<const uint8_t> associated_data) {
        auto decrypt_result = AesGcm::Decrypt(
            header_encryption_key,
            header_nonce,
            encrypted_metadata,
            associated_data);
        if (decrypt_result.IsErr()) {
            return Result<proto::common::EnvelopeMetadata, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    ecliptix::compat::format("Failed to decrypt metadata: {}",
                                decrypt_result.UnwrapErr().message)));
        }
        auto plaintext_metadata = decrypt_result.Unwrap();
        try {
            proto::common::EnvelopeMetadata metadata;
            if (!metadata.ParseFromArray(plaintext_metadata.data(),
                                         static_cast<int>(plaintext_metadata.size()))) {
                {
                    auto __wipe = crypto::SodiumInterop::SecureWipe(std::span(plaintext_metadata));
                    (void) __wipe;
                }
                return Result<proto::common::EnvelopeMetadata, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Decode("Failed to parse decrypted metadata as protobuf"));
            } {
                auto __wipe = crypto::SodiumInterop::SecureWipe(std::span(plaintext_metadata));
                (void) __wipe;
            }
            return Result<proto::common::EnvelopeMetadata, EcliptixProtocolFailure>::Ok(
                std::move(metadata));
        } catch (const std::exception &ex) {
            {
                auto __wipe = crypto::SodiumInterop::SecureWipe(std::span(plaintext_metadata));
                (void) __wipe;
            }
            return Result<proto::common::EnvelopeMetadata, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    ecliptix::compat::format("Exception during metadata parsing: {}", ex.what())));
        }
    }

    std::vector<uint8_t> EnvelopeBuilder::GenerateChannelKeyId() {
        std::vector<uint8_t> channel_key_id(Constants::CHANNEL_KEY_ID_SIZE);
        randombytes_buf(channel_key_id.data(), channel_key_id.size());
        return channel_key_id;
    }
}
