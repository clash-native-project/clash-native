#include <clash_native/proxy/proxy_server.hpp>

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>

namespace {

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
    clash_native::runtime::AsioRuntime runtime;
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
    proxy.start();
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
