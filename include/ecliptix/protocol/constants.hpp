#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>
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

// X25519 RFC 7748 Clamping Masks
inline constexpr uint8_t kX25519ClampByte0 = 0xF8;      // 248: clear 3 low bits
inline constexpr uint8_t kX25519ClampByte31Low = 0x7F;  // 127: clear high bit
inline constexpr uint8_t kX25519ClampByte31High = 0x40; // 64: set second-high bit

// Kyber Hybrid Seeding Constants
inline constexpr size_t kKyberSeedKeyBytes = 32;
inline constexpr size_t kKyberSeedWithNonceBytes = 40;
inline constexpr size_t kKyberSeedNonceOffset = 32;
inline constexpr size_t kKyberSeedNonceBytes = 8;
inline constexpr size_t kChacha20BlockBytes = 64;

// Key Derivation Purpose Strings
inline constexpr std::string_view kPurposeIdentityX25519 = "identity-x25519";
inline constexpr std::string_view kPurposeSignedPreKey = "signed-pre-key";
inline constexpr std::string_view kPurposeIdentityKyber = "identity-kyber";
inline constexpr std::string_view kPurposeEphemeralX25519 = "ephemeral-x25519";

// Hybrid PQ Salt Prefix
inline constexpr std::string_view kHybridSaltPrefix = "Ecliptix-PQ-Hybrid::";

// C API Defaults
inline constexpr uint32_t kDefaultOneTimeKeyCount = 100;
inline constexpr std::string_view kDefaultMembershipId = "default";

// Protobuf Size Limits (security)
inline constexpr size_t kMaxProtobufMessageSize = static_cast<size_t>(std::numeric_limits<int>::max());
inline constexpr size_t kMaxShareSize = 65536; // 64KB max per share

}  // namespace ecliptix::protocol
