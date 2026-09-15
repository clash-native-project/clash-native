#include <clash_native/proxy/proxy_server.hpp>

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

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

struct EchoTarget {
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::endpoint endpoint;

    explicit EchoTarget(clash_native::runtime::AsioRuntime &runtime)
        : acceptor(runtime.context(), {boost::asio::ip::address_v4::loopback(), 0}),
          endpoint(acceptor.local_endpoint()) {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(runtime.context());
        acceptor.async_accept(*socket, [socket](const boost::system::error_code &error) {
            if (!error) {
                std::make_shared<EchoSession>(std::move(*socket))->start();
            }
        });
    }
};

} // namespace

TEST(Stage1ProxyTest, AcceptsHttpConnectAndRelaysBufferedData) {
    clash_native::runtime::AsioRuntime runtime;
    EchoTarget target(runtime);
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    ASSERT_TRUE(proxy.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());

    const auto authority = "127.0.0.1:" + std::to_string(target.endpoint.port());
    const std::string request =
        "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\nclash-native-http";
    boost::asio::write(client, boost::asio::buffer(request));

    boost::asio::streambuf response;
    boost::asio::read_until(client, response, "\r\n\r\n");
    const std::string response_bytes(boost::asio::buffers_begin(response.data()),
                                     boost::asio::buffers_end(response.data()));
    const auto header_end = response_bytes.find("\r\n\r\n");
    ASSERT_NE(header_end, std::string::npos);
    ASSERT_EQ(response_bytes.substr(0, response_bytes.find("\r\n")),
              "HTTP/1.1 200 Connection Established");

    const std::string payload = "clash-native-http";
    std::string echoed = response_bytes.substr(header_end + 4);
    ASSERT_LE(echoed.size(), payload.size());
    if (echoed.size() < payload.size()) {
        const auto offset = echoed.size();
        echoed.resize(payload.size());
        boost::asio::read(client,
                          boost::asio::buffer(echoed.data() + offset, payload.size() - offset));
    }
    EXPECT_EQ(echoed, payload);

    boost::system::error_code ignored;
    client.close(ignored);
    proxy.stop();
    target.acceptor.close(ignored);
    runtime.stop();
}

TEST(Stage1ProxyTest, RejectOutboundReturnsSocks5Rejection) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    proxy.set_default_action(clash_native::router::RouteAction::reject());
    ASSERT_TRUE(proxy.start());
    runtime.start();

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
