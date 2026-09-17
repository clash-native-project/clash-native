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
    const auto outbounds_snapshot = outbounds->snapshot();

    auto first_router = std::make_shared<clash_native::router::TrafficRouter>(
        clash_native::router::RouteAction::reject());
    first_router->add_rule({"old-domain-direct", clash_native::router::RuleKind::domain, "old.test",
                            0, 0, false, clash_native::router::RouteAction::direct()});
    ASSERT_TRUE(first_router->validate(outbounds->ids()));
    auto first_fake_ip_store = std::make_shared<clash_native::dns::FakeIpStore>();
    const auto first_fake_ip = first_fake_ip_store->resolve("old.test");
    ASSERT_TRUE(first_fake_ip);
    EXPECT_EQ(first_fake_ip.value().to_string(), "198.18.0.1");
    auto first_snapshot = std::make_shared<const clash_native::runtime::RuntimeSnapshot>(
        clash_native::runtime::RuntimeSnapshot{2, first_router->snapshot(), outbounds_snapshot,
                                               nullptr, first_fake_ip_store});
    ASSERT_TRUE(proxy.reload(std::move(first_snapshot)));

    const auto connect_through_socks = [&](boost::asio::ip::address_v4 address) {
        boost::asio::ip::tcp::socket client(runtime.context());
        client.connect(proxy.endpoint());
        const std::array<std::uint8_t, 3> method_request{5, 1, 0};
        boost::asio::write(client, boost::asio::buffer(method_request));
        std::array<std::uint8_t, 2> method_response{};
        boost::asio::read(client, boost::asio::buffer(method_response));
        EXPECT_EQ(method_response, (std::array<std::uint8_t, 2>{5, 0}));

        const auto bytes = address.to_bytes();
        const std::array<std::uint8_t, 10> request{5,        1,        0,        1, bytes[0],
                                                   bytes[1], bytes[2], bytes[3], 1, 187};
        boost::asio::write(client, boost::asio::buffer(request));
        std::array<std::uint8_t, 10> response{};
        boost::asio::read(client, boost::asio::buffer(response));
        EXPECT_EQ(response[0], 5);

        boost::system::error_code ignored;
        client.close(ignored);
        return response[1];
    };

    EXPECT_EQ(connect_through_socks(first_fake_ip.value()), 1);

    auto second_router = std::make_shared<clash_native::router::TrafficRouter>(
        clash_native::router::RouteAction::reject());
    second_router->add_rule({"old-domain-direct", clash_native::router::RuleKind::domain,
                             "old.test", 0, 0, false, clash_native::router::RouteAction::direct()});
    ASSERT_TRUE(second_router->validate(outbounds->ids()));
    auto second_fake_ip_store = std::make_shared<clash_native::dns::FakeIpStore>();
    const auto second_fake_ip = second_fake_ip_store->resolve("new.test");
    ASSERT_TRUE(second_fake_ip);
    ASSERT_EQ(second_fake_ip.value(), first_fake_ip.value());
    auto second_snapshot = std::make_shared<const clash_native::runtime::RuntimeSnapshot>(
        clash_native::runtime::RuntimeSnapshot{3, second_router->snapshot(), outbounds_snapshot,
                                               nullptr, second_fake_ip_store});
    ASSERT_TRUE(proxy.reload(std::move(second_snapshot)));

    EXPECT_EQ(connect_through_socks(second_fake_ip.value()), 2);

    proxy.stop();
    runtime.stop();
}
