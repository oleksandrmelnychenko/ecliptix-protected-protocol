#include "ecliptix/protocol/group/group_metadata.hpp"
#include "ecliptix/core/constants.hpp"

namespace ecliptix::protocol::group {

namespace {
    constexpr size_t MIN_GROUP_ID_SIZE = 16;
    constexpr size_t MIN_CREATOR_ID_SIZE = 16;
    constexpr size_t MIN_GROUP_NAME_LENGTH = 1;
    constexpr size_t MAX_GROUP_NAME_LENGTH = 255;
    constexpr size_t MAX_DESCRIPTION_LENGTH = 1024;
    constexpr uint32_t MIN_MAX_MEMBERS = 2;
    constexpr uint32_t MAX_MAX_MEMBERS = 100000;

    GroupType ProtoGroupTypeToEnum(const proto::group::GroupMetadata_GroupType proto_type) {
        switch (proto_type) {
            case proto::group::GroupMetadata_GroupType_PRIVATE:
                return GroupType::Private;
            case proto::group::GroupMetadata_GroupType_PUBLIC:
                return GroupType::Public;
            case proto::group::GroupMetadata_GroupType_BROADCAST:
                return GroupType::Broadcast;
            default:
                return GroupType::Private;
        }
    }

    proto::group::GroupMetadata_GroupType EnumToProtoGroupType(const GroupType type) {
        switch (type) {
            case GroupType::Private:
                return proto::group::GroupMetadata_GroupType_PRIVATE;
            case GroupType::Public:
                return proto::group::GroupMetadata_GroupType_PUBLIC;
            case GroupType::Broadcast:
                return proto::group::GroupMetadata_GroupType_BROADCAST;
            default:
                return proto::group::GroupMetadata_GroupType_PRIVATE;
        }
    }
}

GroupMetadata::GroupMetadata(
    std::vector<uint8_t> group_id,
    std::string group_name,
    std::vector<uint8_t> creator_id,
    std::chrono::system_clock::time_point created_timestamp,
    std::chrono::system_clock::time_point last_modified_timestamp,
    uint32_t version,
    GroupType type,
    uint32_t max_members,
    std::optional<std::string> description)
    : group_id_(std::move(group_id))
    , group_name_(std::move(group_name))
    , creator_id_(std::move(creator_id))
    , created_timestamp_(created_timestamp)
    , last_modified_timestamp_(last_modified_timestamp)
    , version_(version)
    , type_(type)
    , max_members_(max_members)
    , description_(std::move(description))
{
}

Result<GroupMetadata, ProtocolFailure> GroupMetadata::Create(
    std::span<const uint8_t> group_id,
    std::string group_name,
    std::span<const uint8_t> creator_id,
    const GroupType type,
    const uint32_t max_members,
    std::optional<std::string> description) {

    if (group_id.size() < MIN_GROUP_ID_SIZE) {
        return Result<GroupMetadata, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Group ID too short (minimum 16 bytes)"));
    }

    if (group_name.length() < MIN_GROUP_NAME_LENGTH) {
        return Result<GroupMetadata, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Group name cannot be empty"));
    }

    if (group_name.length() > MAX_GROUP_NAME_LENGTH) {
        return Result<GroupMetadata, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Group name too long (maximum 255 characters)"));
    }

    if (creator_id.size() < MIN_CREATOR_ID_SIZE) {
        return Result<GroupMetadata, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Creator ID too short (minimum 16 bytes)"));
    }

    if (max_members < MIN_MAX_MEMBERS) {
        return Result<GroupMetadata, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Group must support at least 2 members"));
    }

    if (max_members > MAX_MAX_MEMBERS) {
        return Result<GroupMetadata, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Maximum members limit exceeded (100,000)"));
    }

    if (description.has_value() && description->length() > MAX_DESCRIPTION_LENGTH) {
        return Result<GroupMetadata, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Description too long (maximum 1024 characters)"));
    }

    const auto now = std::chrono::system_clock::now();

    return Result<GroupMetadata, ProtocolFailure>::Ok(
        GroupMetadata(
            std::vector(group_id.begin(), group_id.end()),
            std::move(group_name),
            std::vector(creator_id.begin(), creator_id.end()),
            now,
            now,
            1,
            type,
            max_members,
            std::move(description)
        )
    );
}

Result<GroupMetadata, ProtocolFailure> GroupMetadata::FromProto(
    const proto::group::GroupMetadata& proto) {

    if (proto.group_id().empty()) {
        return Result<GroupMetadata, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Proto group_id is empty"));
    }

    if (proto.group_name().empty()) {
        return Result<GroupMetadata, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Proto group_name is empty"));
    }

    if (proto.creator_id().empty()) {
        return Result<GroupMetadata, ProtocolFailure>::Err(
            ProtocolFailure::Generic("Proto creator_id is empty"));
    }

    const auto group_id = reinterpret_cast<const uint8_t*>(proto.group_id().data());
    const auto creator_id = reinterpret_cast<const uint8_t*>(proto.creator_id().data());

    const auto created_timestamp = std::chrono::system_clock::time_point(
        std::chrono::milliseconds(proto.created_timestamp_ms()));
    const auto last_modified_timestamp = std::chrono::system_clock::time_point(
        std::chrono::milliseconds(proto.last_modified_timestamp_ms()));

    std::optional<std::string> description = std::nullopt;
    if (proto.has_description()) {
        description = proto.description();
    }

    return Result<GroupMetadata, ProtocolFailure>::Ok(
        GroupMetadata(
            std::vector(group_id, group_id + proto.group_id().size()),
            proto.group_name(),
            std::vector(creator_id, creator_id + proto.creator_id().size()),
            created_timestamp,
            last_modified_timestamp,
            proto.version(),
            ProtoGroupTypeToEnum(proto.type()),
            proto.max_members(),
            description
        )
    );
}

std::vector<uint8_t> GroupMetadata::GetGroupId() const {
    return group_id_;
}

const std::string& GroupMetadata::GetGroupName() const noexcept {
    return group_name_;
}

std::vector<uint8_t> GroupMetadata::GetCreatorId() const {
    return creator_id_;
}

std::chrono::system_clock::time_point GroupMetadata::GetCreatedTimestamp() const noexcept {
    return created_timestamp_;
}

std::chrono::system_clock::time_point GroupMetadata::GetLastModifiedTimestamp() const noexcept {
    return last_modified_timestamp_;
}

uint32_t GroupMetadata::GetVersion() const noexcept {
    return version_;
}

GroupType GroupMetadata::GetType() const noexcept {
    return type_;
}

uint32_t GroupMetadata::GetMaxMembers() const noexcept {
    return max_members_;
}

std::optional<std::string> GroupMetadata::GetDescription() const {
    return description_;
}

void GroupMetadata::SetGroupName(std::string name) {
    group_name_ = std::move(name);
    last_modified_timestamp_ = std::chrono::system_clock::now();
    version_++;
}

void GroupMetadata::SetDescription(std::optional<std::string> description) {
    description_ = std::move(description);
    last_modified_timestamp_ = std::chrono::system_clock::now();
    version_++;
}

void GroupMetadata::SetMaxMembers(const uint32_t max_members) noexcept {
    max_members_ = max_members;
    last_modified_timestamp_ = std::chrono::system_clock::now();
    version_++;
}

void GroupMetadata::IncrementVersion() noexcept {
    version_++;
    last_modified_timestamp_ = std::chrono::system_clock::now();
}

proto::group::GroupMetadata GroupMetadata::ToProto() const {
    proto::group::GroupMetadata proto;

    proto.set_group_id(group_id_.data(), group_id_.size());
    proto.set_group_name(group_name_);
    proto.set_creator_id(creator_id_.data(), creator_id_.size());

    const auto created_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        created_timestamp_.time_since_epoch()).count();
    proto.set_created_timestamp_ms(created_ms);

    const auto modified_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        last_modified_timestamp_.time_since_epoch()).count();
    proto.set_last_modified_timestamp_ms(modified_ms);

    proto.set_version(version_);
    proto.set_type(EnumToProtoGroupType(type_));
    proto.set_max_members(max_members_);

    if (description_.has_value()) {
        proto.set_description(*description_);
    }

    return proto;
}

}
