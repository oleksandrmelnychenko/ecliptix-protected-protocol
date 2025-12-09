#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include "group/group_state.pb.h"
#include <vector>
#include <span>
#include <chrono>

namespace ecliptix::protocol::group {

using protocol::Result;
using protocol::EcliptixProtocolFailure;

enum class DeviceType {
    Mobile = 0,
    Desktop = 1
};

enum class MemberRole {
    Member = 0,
    Admin = 1,
    Owner = 2
};

class GroupMember {
public:
    [[nodiscard]] static Result<GroupMember, EcliptixProtocolFailure> Create(
        std::span<const uint8_t> member_id,
        std::span<const uint8_t> account_id,
        std::span<const uint8_t> app_instance_id,
        std::span<const uint8_t> device_id,
        DeviceType device_type,
        std::span<const uint8_t> identity_public_key,
        MemberRole role = MemberRole::Member);

    [[nodiscard]] static Result<GroupMember, EcliptixProtocolFailure> FromProto(
        const proto::group::GroupMember& proto);

    [[nodiscard]] std::vector<uint8_t> GetMemberId() const;
    [[nodiscard]] std::vector<uint8_t> GetAccountId() const;
    [[nodiscard]] std::vector<uint8_t> GetAppInstanceId() const;
    [[nodiscard]] std::vector<uint8_t> GetDeviceId() const;
    [[nodiscard]] DeviceType GetDeviceType() const noexcept;
    [[nodiscard]] std::vector<uint8_t> GetIdentityPublicKey() const;
    [[nodiscard]] std::chrono::system_clock::time_point GetJoinedTimestamp() const noexcept;
    [[nodiscard]] MemberRole GetRole() const noexcept;
    [[nodiscard]] bool IsActive() const noexcept;

    void SetRole(MemberRole role) noexcept;
    void SetActive(bool is_active) noexcept;

    [[nodiscard]] proto::group::GroupMember ToProto() const;

    GroupMember(const GroupMember&) = default;
    GroupMember& operator=(const GroupMember&) = default;
    GroupMember(GroupMember&&) = default;
    GroupMember& operator=(GroupMember&&) = default;
    ~GroupMember() = default;

private:
    explicit GroupMember(
        std::vector<uint8_t> member_id,
        std::vector<uint8_t> account_id,
        std::vector<uint8_t> app_instance_id,
        std::vector<uint8_t> device_id,
        DeviceType device_type,
        std::vector<uint8_t> identity_public_key,
        std::chrono::system_clock::time_point joined_timestamp,
        MemberRole role,
        bool is_active);

    std::vector<uint8_t> member_id_;
    std::vector<uint8_t> account_id_;
    std::vector<uint8_t> app_instance_id_;
    std::vector<uint8_t> device_id_;
    DeviceType device_type_;
    std::vector<uint8_t> identity_public_key_;
    std::chrono::system_clock::time_point joined_timestamp_;
    MemberRole role_;
    bool is_active_;
};

}
