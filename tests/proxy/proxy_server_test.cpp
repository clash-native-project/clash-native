#include <clash_native/proxy/proxy_server.hpp>

#include <gtest/gtest.h>

#include <boost/asio/ip/tcp.hpp>

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
