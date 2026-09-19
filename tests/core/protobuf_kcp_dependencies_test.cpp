#include <google/protobuf/wrappers.pb.h>
#include <ikcp.h>

#include <gtest/gtest.h>

#include <string>

namespace {

TEST(ProtobufKcpDependenciesTest, ProtobufRuntimeSerializesAndParsesMessages) {
    google::protobuf::StringValue input;
    input.set_value("protobuf runtime is linked");

    std::string wire;
    ASSERT_TRUE(input.SerializeToString(&wire));

    google::protobuf::StringValue output;
    ASSERT_TRUE(output.ParseFromString(wire));
    EXPECT_EQ(output.value(), input.value());
}

TEST(ProtobufKcpDependenciesTest, KcpCreatesAndReleasesAControlBlock) {
    constexpr IUINT32 conversation_id = 0x12345678;
    ikcpcb *control_block = ikcp_create(conversation_id, nullptr);
    ASSERT_NE(control_block, nullptr);

    EXPECT_EQ(ikcp_getconv(control_block), conversation_id);
    ikcp_release(control_block);
}

} // namespace
