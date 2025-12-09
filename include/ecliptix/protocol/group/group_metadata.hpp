#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include "group/group_state.pb.h"
#include <vector>
#include <span>
#include <string>
#include <chrono>
#include <optional>

namespace ecliptix::protocol::group {

using protocol::Result;
using protocol::EcliptixProtocolFailure;

enum class GroupType {
    Private = 0,
    Public = 1,
    Broadcast = 2
};

class GroupMetadata {
public:
    [[nodiscard]] static Result<GroupMetadata, EcliptixProtocolFailure> Create(
        std::span<const uint8_t> group_id,
        std::string group_name,
        std::span<const uint8_t> creator_id,
        GroupType type = GroupType::Private,
        uint32_t max_members = 256,
        std::optional<std::string> description = std::nullopt);

    [[nodiscard]] static Result<GroupMetadata, EcliptixProtocolFailure> FromProto(
        const proto::group::GroupMetadata& proto);

    [[nodiscard]] std::vector<uint8_t> GetGroupId() const;
    [[nodiscard]] const std::string& GetGroupName() const noexcept;
    [[nodiscard]] std::vector<uint8_t> GetCreatorId() const;
    [[nodiscard]] std::chrono::system_clock::time_point GetCreatedTimestamp() const noexcept;
    [[nodiscard]] std::chrono::system_clock::time_point GetLastModifiedTimestamp() const noexcept;
    [[nodiscard]] uint32_t GetVersion() const noexcept;
    [[nodiscard]] GroupType GetType() const noexcept;
    [[nodiscard]] uint32_t GetMaxMembers() const noexcept;
    [[nodiscard]] std::optional<std::string> GetDescription() const;

    void SetGroupName(std::string name);
    void SetDescription(std::optional<std::string> description);
    void SetMaxMembers(uint32_t max_members) noexcept;
    void IncrementVersion() noexcept;

    [[nodiscard]] proto::group::GroupMetadata ToProto() const;

    GroupMetadata(const GroupMetadata&) = default;
    GroupMetadata& operator=(const GroupMetadata&) = default;
    GroupMetadata(GroupMetadata&&) = default;
    GroupMetadata& operator=(GroupMetadata&&) = default;
    ~GroupMetadata() = default;

private:
    explicit GroupMetadata(
        std::vector<uint8_t> group_id,
        std::string group_name,
        std::vector<uint8_t> creator_id,
        std::chrono::system_clock::time_point created_timestamp,
        std::chrono::system_clock::time_point last_modified_timestamp,
        uint32_t version,
        GroupType type,
        uint32_t max_members,
        std::optional<std::string> description);

    std::vector<uint8_t> group_id_;
    std::string group_name_;
    std::vector<uint8_t> creator_id_;
    std::chrono::system_clock::time_point created_timestamp_;
    std::chrono::system_clock::time_point last_modified_timestamp_;
    uint32_t version_;
    GroupType type_;
    uint32_t max_members_;
    std::optional<std::string> description_;
};

}
