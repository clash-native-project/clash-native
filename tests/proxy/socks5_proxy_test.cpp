#include <clash_native/proxy/proxy_server.hpp>

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

boost::asio::ip::address_v4 udp_test_address(boost::asio::io_context &context) {
    boost::asio::ip::udp::socket probe(context);
    boost::system::error_code error;
    probe.open(boost::asio::ip::udp::v4(), error);
    if (!error) {
        probe.connect({boost::asio::ip::make_address_v4("192.0.2.1"), 9}, error);
        if (!error) {
            const auto local = probe.local_endpoint(error).address();
            if (!error && local.is_v4() && !local.is_loopback() && !local.is_unspecified()) {
                return local.to_v4();
            }
        }
    }
    return boost::asio::ip::address_v4::loopback();
}

class EchoSession : public std::enable_shared_from_this<EchoSession> {
  public:
    explicit EchoSession(boost::asio::ip::tcp::socket socket) : socket_(std::move(socket)) {}

    void start() { read(); }

  private:
    void read() {
        auto self = shared_from_this();
        socket_.async_read_some(
            boost::asio::buffer(buffer_),
            [self](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    return;
                }

                boost::asio::async_write(
                    self->socket_, boost::asio::buffer(self->buffer_, size),
                    [self](const boost::system::error_code &write_error, std::size_t) {
                        if (!write_error) {
                            self->read();
                        }
                    });
            });
    }

    boost::asio::ip::tcp::socket socket_;
    std::array<char, 1024> buffer_{};
};

} // namespace

TEST(Socks5ProxyTest, ConnectsAndRelaysTcpData) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    boost::asio::ip::tcp::acceptor target(runtime.context(),
                                          {boost::asio::ip::address_v4::loopback(), 0});
    const auto target_endpoint = target.local_endpoint();

    auto target_socket = std::make_shared<boost::asio::ip::tcp::socket>(runtime.context());
    target.async_accept(*target_socket, [target_socket](const boost::system::error_code &error) {
        if (!error) {
            std::make_shared<EchoSession>(std::move(*target_socket))->start();
        }
    });

    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    ASSERT_TRUE(proxy.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());

    const std::array<std::uint8_t, 3> method_request{5, 1, 0};
    boost::asio::write(client, boost::asio::buffer(method_request));

    std::array<std::uint8_t, 2> method_response{};
    boost::asio::read(client, boost::asio::buffer(method_response));
    ASSERT_EQ(method_response, (std::array<std::uint8_t, 2>{5, 0}));

    const auto port = target_endpoint.port();
    const std::array<std::uint8_t, 10> connect_request{
        5,
        1,
        0,
        1,
        127,
        0,
        0,
        1,
        static_cast<std::uint8_t>(port >> 8),
        static_cast<std::uint8_t>(port & 0xff),
    };
    boost::asio::write(client, boost::asio::buffer(connect_request));

    std::array<std::uint8_t, 10> connect_response{};
    boost::asio::read(client, boost::asio::buffer(connect_response));
    ASSERT_EQ(connect_response[0], 5);
    ASSERT_EQ(connect_response[1], 0);

    const std::string payload = "clash-native";
    boost::asio::write(client, boost::asio::buffer(payload));

    std::string echoed(payload.size(), '\0');
    boost::asio::read(client, boost::asio::buffer(echoed));
    EXPECT_EQ(echoed, payload);

    boost::system::error_code ignored;
    client.close(ignored);
    proxy.stop();
    target.close(ignored);
    runtime.stop();
}

TEST(Socks5ProxyTest, ConnectsAndRelaysSocks4TcpData) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    boost::asio::ip::tcp::acceptor target(runtime.context(),
                                          {boost::asio::ip::address_v4::loopback(), 0});
    const auto target_endpoint = target.local_endpoint();

    auto target_socket = std::make_shared<boost::asio::ip::tcp::socket>(runtime.context());
    target.async_accept(*target_socket, [target_socket](const boost::system::error_code &error) {
        if (!error) {
            std::make_shared<EchoSession>(std::move(*target_socket))->start();
        }
    });

    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    ASSERT_TRUE(proxy.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());
    const auto port = target_endpoint.port();
    const std::vector<std::uint8_t> request{4,
                                            1,
                                            static_cast<std::uint8_t>(port >> 8),
                                            static_cast<std::uint8_t>(port & 0xff),
                                            127,
                                            0,
                                            0,
                                            1,
                                            'l',
                                            'e',
                                            'g',
                                            'a',
                                            'c',
                                            'y',
                                            0};
    boost::asio::write(client, boost::asio::buffer(request));

    std::array<std::uint8_t, 8> response{};
    boost::asio::read(client, boost::asio::buffer(response));
    ASSERT_EQ(response[0], 0);
    ASSERT_EQ(response[1], 0x5a);
    ASSERT_EQ(response[2], request[2]);
    ASSERT_EQ(response[3], request[3]);
    ASSERT_EQ(response[4], request[4]);
    ASSERT_EQ(response[5], request[5]);
    ASSERT_EQ(response[6], request[6]);
    ASSERT_EQ(response[7], request[7]);

    const std::string payload = "socks4";
    boost::asio::write(client, boost::asio::buffer(payload));
    std::string echoed(payload.size(), '\0');
    boost::asio::read(client, boost::asio::buffer(echoed));
    EXPECT_EQ(echoed, payload);

    boost::system::error_code ignored;
    client.close(ignored);
    proxy.stop();
    target.close(ignored);
    runtime.stop();
}

TEST(Socks5ProxyTest, ParsesSocks4aDomainRequests) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    proxy.set_default_action(clash_native::router::RouteAction::reject());
    ASSERT_TRUE(proxy.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());
    const std::vector<std::uint8_t> request{4,   1,   1,   187, 0,   0,   0, 1,
                                            'l', 'e', 'g', 'a', 'c', 'y', 0};
    const std::vector<std::uint8_t> domain{'e', 'x', 'a', 'm', 'p', 'l', 'e', '.',
                                           'i', 'n', 'v', 'a', 'l', 'i', 'd', 0};
    boost::asio::write(client, boost::asio::buffer(request));
    // Keep the USERID and SOCKS4a domain in separate TCP segments.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::asio::write(client, boost::asio::buffer(domain));

    std::array<std::uint8_t, 8> response{};
    boost::asio::read(client, boost::asio::buffer(response));
    EXPECT_EQ(response[0], 0);
    EXPECT_EQ(response[1], 0x5b);

    boost::system::error_code ignored;
    client.close(ignored);
    proxy.stop();
    runtime.stop();
}

TEST(Socks5ProxyTest, SupportsMihomoStyleUsernamePasswordAuthentication) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    boost::asio::ip::tcp::acceptor target(runtime.context(),
                                          {boost::asio::ip::address_v4::loopback(), 0});
    const auto target_endpoint = target.local_endpoint();

    auto target_socket = std::make_shared<boost::asio::ip::tcp::socket>(runtime.context());
    target.async_accept(*target_socket, [target_socket](const boost::system::error_code &error) {
        if (!error) {
            std::make_shared<EchoSession>(std::move(*target_socket))->start();
        }
    });

    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    proxy.set_socks5_users({{"proxy-user", "proxy-password"}});
    ASSERT_TRUE(proxy.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());

    const std::array<std::uint8_t, 4> method_request{5, 2, 0, 2};
    boost::asio::write(client, boost::asio::buffer(method_request));
    std::array<std::uint8_t, 2> method_response{};
    boost::asio::read(client, boost::asio::buffer(method_response));
    ASSERT_EQ(method_response, (std::array<std::uint8_t, 2>{5, 2}));

    const std::vector<std::uint8_t> auth_request{1,   10,  'p', 'r', 'o', 'x', 'y', '-', 'u',
                                                 's', 'e', 'r', 14,  'p', 'r', 'o', 'x', 'y',
                                                 '-', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    boost::asio::write(client, boost::asio::buffer(auth_request));
    std::array<std::uint8_t, 2> auth_response{};
    boost::asio::read(client, boost::asio::buffer(auth_response));
    ASSERT_EQ(auth_response, (std::array<std::uint8_t, 2>{1, 0}));

    const auto port = target_endpoint.port();
    const std::array<std::uint8_t, 10> connect_request{
        5,
        1,
        0,
        1,
        127,
        0,
        0,
        1,
        static_cast<std::uint8_t>(port >> 8),
        static_cast<std::uint8_t>(port & 0xff),
    };
    boost::asio::write(client, boost::asio::buffer(connect_request));
    std::array<std::uint8_t, 10> connect_response{};
    boost::asio::read(client, boost::asio::buffer(connect_response));
    ASSERT_EQ(connect_response[0], 5);
    ASSERT_EQ(connect_response[1], 0);

    const std::string payload = "authenticated-socks5";
    boost::asio::write(client, boost::asio::buffer(payload));
    std::string echoed(payload.size(), '\0');
    boost::asio::read(client, boost::asio::buffer(echoed));
    EXPECT_EQ(echoed, payload);

    boost::system::error_code ignored;
    client.close(ignored);
    proxy.stop();
    target.close(ignored);
    runtime.stop();
}

TEST(Socks5ProxyTest, RelaysStandaloneUdpListenerPackets) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    const auto udp_address = udp_test_address(runtime.context());
    if (udp_address.is_loopback()) {
        GTEST_SKIP() << "non-loopback UDP is unavailable in this Windows environment";
    }
    boost::asio::ip::udp::socket target(runtime.context(), {udp_address, 0});
    const auto target_endpoint = target.local_endpoint();
    auto target_buffer = std::make_shared<std::array<std::uint8_t, 1024>>();
    auto target_sender = std::make_shared<boost::asio::ip::udp::endpoint>();
    target.async_receive_from(boost::asio::buffer(*target_buffer), *target_sender,
                              [target_buffer, target_sender,
                               &target](const boost::system::error_code &error, std::size_t size) {
                                  if (!error) {
                                      target.async_send_to(
                                          boost::asio::buffer(*target_buffer, size), *target_sender,
                                          [](const boost::system::error_code &, std::size_t) {});
                                  }
                              });

    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    proxy.set_socks5_udp_endpoint({udp_address, 0});
    ASSERT_TRUE(proxy.start());
    runtime.start();

    boost::asio::ip::tcp::socket control(runtime.context());
    control.connect(proxy.endpoint());
    const std::array<std::uint8_t, 3> method_request{5, 1, 0};
    boost::asio::write(control, boost::asio::buffer(method_request));
    std::array<std::uint8_t, 2> method_response{};
    boost::asio::read(control, boost::asio::buffer(method_response));
    ASSERT_EQ(method_response, (std::array<std::uint8_t, 2>{5, 0}));

    const std::array<std::uint8_t, 10> associate_request{5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
    boost::asio::write(control, boost::asio::buffer(associate_request));
    std::array<std::uint8_t, 10> associate_response{};
    boost::asio::read(control, boost::asio::buffer(associate_response));
    ASSERT_EQ(associate_response[0], 5);
    ASSERT_EQ(associate_response[1], 0);
    ASSERT_EQ(associate_response[3], 1);
    const boost::asio::ip::udp::endpoint relay_endpoint(
        udp_address,
        static_cast<std::uint16_t>((associate_response[8] << 8) | associate_response[9]));

    boost::asio::ip::udp::socket client(runtime.context(), {udp_address, 0});
    const std::string payload = "socks5-udp";
    const auto port = target_endpoint.port();
    const auto target_bytes = udp_address.to_bytes();
    std::vector<std::uint8_t> request{0,
                                      0,
                                      0,
                                      1,
                                      target_bytes[0],
                                      target_bytes[1],
                                      target_bytes[2],
                                      target_bytes[3],
                                      static_cast<std::uint8_t>(port >> 8),
                                      static_cast<std::uint8_t>(port & 0xff)};
    request.insert(request.end(), payload.begin(), payload.end());
    client.send_to(boost::asio::buffer(request), relay_endpoint);

    std::array<std::uint8_t, 1024> response{};
    boost::asio::ip::udp::endpoint response_sender;
    const auto response_size = client.receive_from(boost::asio::buffer(response), response_sender);
    ASSERT_GE(response_size, 10U + payload.size());
    EXPECT_EQ(response[0], 0);
    EXPECT_EQ(response[1], 0);
    EXPECT_EQ(response[2], 0);
    EXPECT_EQ(response[3], 1);
    EXPECT_EQ(std::string(response.begin() + 10,
                          response.begin() + static_cast<std::ptrdiff_t>(response_size)),
              payload);

    boost::system::error_code ignored;
    control.close(ignored);
    client.close(ignored);
    proxy.stop();
    target.close(ignored);
    runtime.stop();
}
