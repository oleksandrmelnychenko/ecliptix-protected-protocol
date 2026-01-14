#include "ecliptix/protocol/group/group_member.hpp"
#include "ecliptix/protocol/group/group_metadata.hpp"
#include <catch2/catch_test_macros.hpp>
#include "group/group_state.pb.h"

using namespace ecliptix::protocol::group;

TEST_CASE("GroupMember FromProto enforces sizes", "[group][security]") {
    ecliptix::proto::group::GroupMember proto_msg;
    proto_msg.set_member_id(std::string(8, 'a'));     // too short
    proto_msg.set_account_id(std::string(16, 'b'));
    proto_msg.set_app_instance_id(std::string(16, 'c'));
    proto_msg.set_device_id(std::string(16, 'd'));
    proto_msg.set_identity_public_key(std::string(32, 'e'));
    proto_msg.set_joined_timestamp_ms(123);
    proto_msg.set_device_type(ecliptix::proto::group::GroupMember_DeviceType_MOBILE);
    proto_msg.set_role(ecliptix::proto::group::GroupMember_MemberRole_MEMBER);

    auto result = GroupMember::FromProto(proto_msg);
    REQUIRE(result.IsErr());

    proto_msg.set_member_id(std::string(16, 'a'));
    auto valid = GroupMember::FromProto(proto_msg);
    REQUIRE(valid.IsOk());
}

TEST_CASE("GroupMetadata FromProto enforces bounds", "[group][security]") {
    ecliptix::proto::group::GroupMetadata proto_msg;
    proto_msg.set_group_id(std::string(4, 'g')); // too short
    proto_msg.set_group_name("x");
    proto_msg.set_creator_id(std::string(16, 'c'));
    proto_msg.set_version(1);
    proto_msg.set_type(ecliptix::proto::group::GroupMetadata_GroupType_PRIVATE);
    proto_msg.set_max_members(10);
    proto_msg.set_created_timestamp_ms(1);
    proto_msg.set_last_modified_timestamp_ms(1);

    auto bad = GroupMetadata::FromProto(proto_msg);
    REQUIRE(bad.IsErr());

    proto_msg.set_group_id(std::string(16, 'g'));
    proto_msg.set_description(std::string(1025, 'd'));
    auto bad_desc = GroupMetadata::FromProto(proto_msg);
    REQUIRE(bad_desc.IsErr());

    proto_msg.set_description("ok");
    auto good = GroupMetadata::FromProto(proto_msg);
    REQUIRE(good.IsOk());
}
