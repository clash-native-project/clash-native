#include <clash_native/outbound/builtin_outbound.hpp>
#include <clash_native/proxy/proxy_server.hpp>

#include <gtest/gtest.h>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <future>

TEST(ProxyServerTest, TracksLifecycle) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::proxy::ProxyServer proxy_server(runtime, {boost::asio::ip::tcp::v4(), 0});

    EXPECT_FALSE(proxy_server.running());

    ASSERT_TRUE(proxy_server.start());
    EXPECT_TRUE(proxy_server.running());
    EXPECT_NE(proxy_server.endpoint().port(), 0);

    ASSERT_TRUE(proxy_server.start());
    EXPECT_TRUE(proxy_server.running());

    proxy_server.stop();
    EXPECT_FALSE(proxy_server.running());
}

TEST(ProxyServerTest, DirectOutboundDoesNotUseTheSystemResolver) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::outbound::DirectOutbound direct(runtime);
    runtime.start();

    auto done = std::make_shared<std::promise<clash_native::core::StreamOpenResult>>();
    auto future = done->get_future();
    direct.connect_stream(
        {clash_native::core::Destination::domain("example.invalid", 443), std::nullopt},
        [done](clash_native::core::StreamOpenResult result) {
            done->set_value(std::move(result));
        });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    const auto result = future.get();
    EXPECT_EQ(result.status, clash_native::core::OpenStatus::failed);
    ASSERT_TRUE(result.error);
    EXPECT_EQ(result.error->code, clash_native::core::ErrorCode::configuration);
    runtime.stop();
}

TEST(ProxyServerTest, ReloadsTheRuntimeSnapshotForNewConnections) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    ASSERT_TRUE(proxy.start());
    runtime.start();

    auto outbounds = std::make_shared<clash_native::outbound::OutboundRegistry>();
    ASSERT_TRUE(outbounds->add_outbound(
        "direct", std::make_shared<clash_native::outbound::DirectOutbound>(runtime)));
    ASSERT_TRUE(outbounds->add_outbound(
        "reject", std::make_shared<clash_native::outbound::RejectOutbound>(runtime)));
    ASSERT_TRUE(outbounds->validate());
    auto router = std::make_shared<clash_native::router::TrafficRouter>(
        clash_native::router::RouteAction::reject());
    ASSERT_TRUE(router->validate(outbounds->ids()));
    auto snapshot = std::make_shared<const clash_native::runtime::RuntimeSnapshot>(
        clash_native::runtime::RuntimeSnapshot{0, std::move(router), outbounds->snapshot(), nullptr,
                                               nullptr});
    ASSERT_TRUE(proxy.reload(std::move(snapshot)));

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());
    const std::array<std::uint8_t, 3> method_request{5, 1, 0};
    boost::asio::write(client, boost::asio::buffer(method_request));
    std::array<std::uint8_t, 2> method_response{};
    boost::asio::read(client, boost::asio::buffer(method_response));
    ASSERT_EQ(method_response, (std::array<std::uint8_t, 2>{5, 0}));

    const std::array<std::uint8_t, 10> request{5, 1, 0, 1, 127, 0, 0, 1, 0, 1};
    boost::asio::write(client, boost::asio::buffer(request));
    std::array<std::uint8_t, 10> response{};
    boost::asio::read(client, boost::asio::buffer(response));
    EXPECT_EQ(response[0], 5);
    EXPECT_EQ(response[1], 2);

    boost::system::error_code ignored;
    client.close(ignored);
    proxy.stop();
    runtime.stop();
}
