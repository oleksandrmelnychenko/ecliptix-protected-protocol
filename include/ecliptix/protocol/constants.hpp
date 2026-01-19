#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace ecliptix::protocol {

inline constexpr uint32_t kProtocolVersion = 1;

inline constexpr size_t kX25519PublicKeyBytes = 32;
inline constexpr size_t kX25519PrivateKeyBytes = 32;
inline constexpr size_t kX25519SharedSecretBytes = 32;
inline constexpr size_t kEd25519PublicKeyBytes = 32;
inline constexpr size_t kEd25519SecretKeyBytes = 64;
inline constexpr size_t kEd25519SignatureBytes = 64;

inline constexpr size_t kKyberPublicKeyBytes = 1184;
inline constexpr size_t kKyberSecretKeyBytes = 2400;
inline constexpr size_t kKyberCiphertextBytes = 1088;
inline constexpr size_t kKyberSharedSecretBytes = 32;

inline constexpr size_t kRootKeyBytes = 32;
inline constexpr size_t kChainKeyBytes = 32;
inline constexpr size_t kMessageKeyBytes = 32;
inline constexpr size_t kMetadataKeyBytes = 32;
inline constexpr size_t kSessionIdBytes = 16;
inline constexpr size_t kHmacBytes = 32;

inline constexpr size_t kAesKeyBytes = 32;
inline constexpr size_t kAesGcmNonceBytes = 12;
inline constexpr size_t kAesGcmTagBytes = 16;

inline constexpr size_t kNoncePrefixBytes = 4;
inline constexpr size_t kNonceCounterBytes = 4;
inline constexpr size_t kNonceIndexBytes = 4;
inline constexpr uint64_t kMaxNonceCounter = 0xFFFFFFFFull;
inline constexpr uint64_t kMaxMessageIndex = 0xFFFFFFFFull;
inline constexpr uint64_t kDefaultMessagesPerChain = 1000;
inline constexpr size_t kMaxSkippedMessageKeys = 1000;
inline constexpr size_t kMaxMessagesPerChain = 10000;

inline constexpr size_t kOpaqueSessionKeyBytes = 32;

inline constexpr std::string_view kX3dhInfo = "Ecliptix-X3DH";
inline constexpr std::string_view kHybridX3dhInfo = "Ecliptix-Hybrid-X3DH";
inline constexpr std::string_view kHybridRatchetInfo = "Ecliptix-Hybrid-Ratchet";
inline constexpr std::string_view kDhRatchetInfo = "Ecliptix-DH-Ratchet";
inline constexpr std::string_view kHybridPqFallbackInfo = "Ecliptix-Hybrid-PQ-Fallback";
inline constexpr std::string_view kInitialSenderChainInfo = "Ecliptix-Initial-Sender";
inline constexpr std::string_view kInitialReceiverChainInfo = "Ecliptix-Initial-Receiver";
inline constexpr std::string_view kChainInitInfo = "Ecliptix-ChainInit";
inline constexpr std::string_view kChainInfo = "Ecliptix-Chain";
inline constexpr std::string_view kMessageInfo = "Ecliptix-Msg";
inline constexpr std::string_view kSessionIdInfo = "Ecliptix-SessionId";
inline constexpr std::string_view kMetadataKeyInfo = "Ecliptix-MetadataKey";
inline constexpr std::string_view kOpaqueRootInfo = "Ecliptix-OPAQUE-Root";
inline constexpr std::string_view kStateHmacInfo = "Ecliptix-State-HMAC";
inline constexpr std::string_view kKeyConfirmInitInfo = "Ecliptix-KeyConfirm-I";
inline constexpr std::string_view kKeyConfirmRespInfo = "Ecliptix-KeyConfirm-R";
inline constexpr std::string_view kTranscriptLabel = "Ecliptix-Handshake-Transcript";

}  // namespace ecliptix::protocol
