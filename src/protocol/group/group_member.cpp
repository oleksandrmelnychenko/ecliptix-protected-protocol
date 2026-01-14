#include "ecliptix/protocol/group/group_member.hpp"
#include "ecliptix/core/constants.hpp"
#include <algorithm>

namespace ecliptix::protocol::group {

namespace {
    constexpr size_t MIN_MEMBER_ID_SIZE = 16;
    constexpr size_t MIN_ACCOUNT_ID_SIZE = 16;
    constexpr size_t MIN_APP_INSTANCE_ID_SIZE = 16;
    constexpr size_t MIN_DEVICE_ID_SIZE = 16;
    constexpr size_t EXPECTED_PUBLIC_KEY_SIZE = 32;

    DeviceType ProtoDeviceTypeToEnum(const proto::group::GroupMember_DeviceType proto_type) {
        return proto_type == proto::group::GroupMember_DeviceType_MOBILE
            ? DeviceType::Mobile
            : DeviceType::Desktop;
    }

    proto::group::GroupMember_DeviceType EnumToProtoDeviceType(const DeviceType type) {
        return type == DeviceType::Mobile
            ? proto::group::GroupMember_DeviceType_MOBILE
            : proto::group::GroupMember_DeviceType_DESKTOP;
    }

    MemberRole ProtoRoleToEnum(const proto::group::GroupMember_MemberRole proto_role) {
        switch (proto_role) {
            case proto::group::GroupMember_MemberRole_MEMBER:
                return MemberRole::Member;
            case proto::group::GroupMember_MemberRole_ADMIN:
                return MemberRole::Admin;
            case proto::group::GroupMember_MemberRole_OWNER:
                return MemberRole::Owner;
            default:
                return MemberRole::Member;
        }
    }

    proto::group::GroupMember_MemberRole EnumToProtoRole(const MemberRole role) {
        switch (role) {
            case MemberRole::Member:
                return proto::group::GroupMember_MemberRole_MEMBER;
            case MemberRole::Admin:
                return proto::group::GroupMember_MemberRole_ADMIN;
            case MemberRole::Owner:
                return proto::group::GroupMember_MemberRole_OWNER;
            default:
                return proto::group::GroupMember_MemberRole_MEMBER;
        }
    }
}

GroupMember::GroupMember(
    std::vector<uint8_t> member_id,
    std::vector<uint8_t> account_id,
    std::vector<uint8_t> app_instance_id,
    std::vector<uint8_t> device_id,
    DeviceType device_type,
    std::vector<uint8_t> identity_public_key,
    std::chrono::system_clock::time_point joined_timestamp,
    MemberRole role,
    bool is_active)
    : member_id_(std::move(member_id))
    , account_id_(std::move(account_id))
    , app_instance_id_(std::move(app_instance_id))
    , device_id_(std::move(device_id))
    , device_type_(device_type)
    , identity_public_key_(std::move(identity_public_key))
    , joined_timestamp_(joined_timestamp)
    , role_(role)
    , is_active_(is_active)
{
}

Result<GroupMember, ProtocolFailure> GroupMember::Create(
    std::span<const uint8_t> member_id,
    std::span<const uint8_t> account_id,
    std::span<const uint8_t> app_instance_id,
    std::span<const uint8_t> device_id,
    const DeviceType device_type,
    std::span<const uint8_t> identity_public_key,
    const MemberRole role) {

    if (member_id.size() < MIN_MEMBER_ID_SIZE) {
        return Result<GroupMember, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Member ID too short (minimum 16 bytes)"));
    }

    if (account_id.size() < MIN_ACCOUNT_ID_SIZE) {
        return Result<GroupMember, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Account ID too short (minimum 16 bytes)"));
    }

    if (app_instance_id.size() < MIN_APP_INSTANCE_ID_SIZE) {
        return Result<GroupMember, ProtocolFailure>::Err(
            ProtocolFailure::Generic("App instance ID too short (minimum 16 bytes)"));
    }

    if (device_id.size() < MIN_DEVICE_ID_SIZE) {
        return Result<GroupMember, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Device ID too short (minimum 16 bytes)"));
    }

    if (identity_public_key.size() != EXPECTED_PUBLIC_KEY_SIZE) {
        return Result<GroupMember, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Identity public key must be 32 bytes"));
    }

    const auto now = std::chrono::system_clock::now();

    return Result<GroupMember, ProtocolFailure>::Ok(
        GroupMember(
            std::vector(member_id.begin(), member_id.end()),
            std::vector(account_id.begin(), account_id.end()),
            std::vector(app_instance_id.begin(), app_instance_id.end()),
            std::vector(device_id.begin(), device_id.end()),
            device_type,
            std::vector(identity_public_key.begin(), identity_public_key.end()),
            now,
            role,
            true
        )
    );
}

Result<GroupMember, ProtocolFailure> GroupMember::FromProto(
    const proto::group::GroupMember& proto) {

    if (proto.member_id().empty()) {
        return Result<GroupMember, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Proto member_id is empty"));
    }

    if (proto.account_id().empty()) {
        return Result<GroupMember, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Proto account_id is empty"));
    }

    if (proto.app_instance_id().empty()) {
        return Result<GroupMember, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Proto app_instance_id is empty"));
    }

    if (proto.device_id().empty()) {
        return Result<GroupMember, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Proto device_id is empty"));
    }

    if (proto.identity_public_key().empty()) {
        return Result<GroupMember, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Proto identity_public_key is empty"));
    }

    const auto member_id = reinterpret_cast<const uint8_t*>(proto.member_id().data());
    const auto account_id = reinterpret_cast<const uint8_t*>(proto.account_id().data());
    const auto app_instance_id = reinterpret_cast<const uint8_t*>(proto.app_instance_id().data());
    const auto device_id = reinterpret_cast<const uint8_t*>(proto.device_id().data());
    const auto identity_public_key = reinterpret_cast<const uint8_t*>(proto.identity_public_key().data());

    const auto joined_timestamp = std::chrono::system_clock::time_point(
        std::chrono::milliseconds(proto.joined_timestamp_ms()));

    return Result<GroupMember, ProtocolFailure>::Ok(
        GroupMember(
            std::vector(member_id, member_id + proto.member_id().size()),
            std::vector(account_id, account_id + proto.account_id().size()),
            std::vector(app_instance_id, app_instance_id + proto.app_instance_id().size()),
            std::vector(device_id, device_id + proto.device_id().size()),
            ProtoDeviceTypeToEnum(proto.device_type()),
            std::vector(identity_public_key, identity_public_key + proto.identity_public_key().size()),
            joined_timestamp,
            ProtoRoleToEnum(proto.role()),
            proto.is_active()
        )
    );
}

std::vector<uint8_t> GroupMember::GetMemberId() const {
    return member_id_;
}

std::vector<uint8_t> GroupMember::GetAccountId() const {
    return account_id_;
}

std::vector<uint8_t> GroupMember::GetAppInstanceId() const {
    return app_instance_id_;
}

std::vector<uint8_t> GroupMember::GetDeviceId() const {
    return device_id_;
}

DeviceType GroupMember::GetDeviceType() const noexcept {
    return device_type_;
}

std::vector<uint8_t> GroupMember::GetIdentityPublicKey() const {
    return identity_public_key_;
}

std::chrono::system_clock::time_point GroupMember::GetJoinedTimestamp() const noexcept {
    return joined_timestamp_;
}

MemberRole GroupMember::GetRole() const noexcept {
    return role_;
}

bool GroupMember::IsActive() const noexcept {
    return is_active_;
}

void GroupMember::SetRole(const MemberRole role) noexcept {
    role_ = role;
}

void GroupMember::SetActive(const bool is_active) noexcept {
    is_active_ = is_active;
}

proto::group::GroupMember GroupMember::ToProto() const {
    proto::group::GroupMember proto;

    proto.set_member_id(member_id_.data(), member_id_.size());
    proto.set_account_id(account_id_.data(), account_id_.size());
    proto.set_app_instance_id(app_instance_id_.data(), app_instance_id_.size());
    proto.set_device_id(device_id_.data(), device_id_.size());
    proto.set_device_type(EnumToProtoDeviceType(device_type_));
    proto.set_identity_public_key(identity_public_key_.data(), identity_public_key_.size());

    const auto timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        joined_timestamp_.time_since_epoch()).count();
    proto.set_joined_timestamp_ms(timestamp_ms);

    proto.set_role(EnumToProtoRole(role_));
    proto.set_is_active(is_active_);

    return proto;
}

}
