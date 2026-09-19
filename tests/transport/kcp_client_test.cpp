#include <clash_native/transport/kcp_client.hpp>

#include <boost/asio/ip/udp.hpp>

#include <gtest/gtest.h>

TEST(KcpClientTest, RejectsMissingDatagramHandle) {
    const auto result = clash_native::transport::make_kcp_client_stream(
        nullptr, boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 9000));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
}

TEST(KcpClientTest, RejectsInvalidOptions) {
    clash_native::transport::KcpClientOptions options;
    options.conversation_id = 1;

    const auto result = clash_native::transport::make_kcp_client_stream(
        nullptr, boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 9000),
        options);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
}
