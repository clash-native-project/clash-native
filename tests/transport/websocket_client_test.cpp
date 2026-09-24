#include <clash_native/io/sender.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/transport/websocket_client.hpp>

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>

#include <stdexec/execution.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace {

class TestStream final : public clash_native::io::StreamHandle {
  public:
    explicit TestStream(boost::asio::any_io_executor executor) : executor_(std::move(executor)) {}

    clash_native::io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer) override {
        return clash_native::io::AnySender<std::optional<std::size_t>>{
            stdexec::just(std::optional<std::size_t>())};
    }

    clash_native::io::AnySender<std::size_t>
    async_write(boost::asio::const_buffer buffer) override {
        return clash_native::io::AnySender<std::size_t>{stdexec::just(buffer.size())};
    }

    boost::asio::any_io_executor executor() noexcept override { return executor_; }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        error.clear();
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        error = boost::asio::error::operation_not_supported;
    }

    void close() noexcept override { closed_ = true; }

    bool closed() const noexcept { return closed_; }

  private:
    boost::asio::any_io_executor executor_;
    bool closed_ = false;
};

} // namespace

TEST(WebSocketClientTest, RejectsMissingStream) {
    std::promise<clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>>>
        completion;
    auto future = completion.get_future();
    const auto operation = clash_native::transport::async_websocket_client_handshake(
        nullptr, {}, [&completion](auto result) { completion.set_value(std::move(result)); });

    EXPECT_FALSE(operation);
    const auto result = future.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
}

TEST(WebSocketClientTest, RejectsInvalidOptionsBeforeOpeningHandshake) {
    boost::asio::io_context context;
    auto stream = std::make_unique<TestStream>(context.get_executor());
    auto *raw_stream = stream.get();
    clash_native::transport::WebSocketClientOptions options;
    options.host = "localhost";
    options.target = "relative-target";

    std::promise<clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>>>
        completion;
    auto future = completion.get_future();
    const auto operation = clash_native::transport::async_websocket_client_handshake(
        std::move(stream), std::move(options),
        [&completion](auto result) { completion.set_value(std::move(result)); });

    ASSERT_TRUE(operation);
    context.run();
    const auto result = future.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
    EXPECT_TRUE(raw_stream->closed());
}

namespace {

// Minimal raw HTTP/WS loopback peer: captures the handshake request,
// answers 101, then exposes the byte stream.
struct RawPeer {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    boost::asio::ip::tcp::socket socket{context};

    ~RawPeer() {
        context.stop();
        if (runner_.joinable()) {
            runner_.join();
        }
    }

    // Listens for the test client's connection; call wait_accept() after
    // the client connects.
    explicit RawPeer(std::uint16_t *port_out) : acceptor_(context) {
        using boost::asio::ip::tcp;
        acceptor_.open(tcp::v4());
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
        acceptor_.bind(tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
        acceptor_.listen();
        *port_out = acceptor_.local_endpoint().port();
        acceptor_.async_accept(socket, [&](const boost::system::error_code &error) {
            EXPECT_FALSE(error);
            accepted_.set_value();
        });
        runner_ = std::thread([this] { context.run(); });
    }

    void wait_accept() {
        if (accepted_.get_future().wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
            throw std::runtime_error("peer accept timed out");
        }
        socket.non_blocking(false);
    }

    boost::asio::ip::tcp::acceptor acceptor_;
    std::promise<void> accepted_;
    std::thread runner_;

    std::string read_request() {
        boost::asio::streambuf buffer;
        boost::system::error_code error;
        boost::asio::read_until(socket, buffer, "\r\n\r\n", error);
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
        return {boost::asio::buffers_begin(buffer.data()), boost::asio::buffers_end(buffer.data())};
    }

    void write_all(const std::string &bytes) {
        boost::system::error_code error;
        boost::asio::write(socket, boost::asio::buffer(bytes), error);
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
    }

    std::vector<std::uint8_t> read_exactly(std::size_t size) {
        std::vector<std::uint8_t> out(size);
        boost::system::error_code error;
        boost::asio::read(socket, boost::asio::buffer(out), error);
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
        return out;
    }
};

std::string sec_accept_for(const std::string &request) {
    const std::string marker = "Sec-WebSocket-Key: ";
    const auto begin = request.find(marker);
    if (begin == std::string::npos) {
        throw std::runtime_error("missing Sec-WebSocket-Key");
    }
    const auto line_end = request.find("\r\n", begin);
    const auto key = request.substr(begin + marker.size(), line_end - begin - marker.size());
    const std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::array<unsigned char, 20> digest{};
    std::uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    const std::string message = key + magic;
    std::vector<std::uint8_t> padded(message.begin(), message.end());
    const auto bit_length = static_cast<std::uint64_t>(message.size()) * 8;
    padded.push_back(0x80);
    while (padded.size() % 64 != 56) {
        padded.push_back(0);
    }
    for (int shift = 56; shift >= 0; shift -= 8) {
        padded.push_back(static_cast<std::uint8_t>((bit_length >> shift) & 0xff));
    }
    const auto rotate = [](std::uint32_t value, unsigned bits) {
        return (value << bits) | (value >> (32 - bits));
    };
    for (std::size_t offset = 0; offset < padded.size(); offset += 64) {
        std::uint32_t block[80];
        for (int index = 0; index < 16; ++index) {
            block[index] = (static_cast<std::uint32_t>(padded[offset + index * 4]) << 24) |
                           (static_cast<std::uint32_t>(padded[offset + index * 4 + 1]) << 16) |
                           (static_cast<std::uint32_t>(padded[offset + index * 4 + 2]) << 8) |
                           static_cast<std::uint32_t>(padded[offset + index * 4 + 3]);
        }
        for (int index = 16; index < 80; ++index) {
            block[index] = rotate(
                block[index - 3] ^ block[index - 8] ^ block[index - 14] ^ block[index - 16], 1);
        }
        auto tuple_state = std::make_tuple(state[0], state[1], state[2], state[3], state[4]);
        auto &[a, b, c, d, e] = tuple_state;
        for (int index = 0; index < 80; ++index) {
            std::uint32_t f = 0;
            std::uint32_t k = 0;
            if (index < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (index < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (index < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            const auto temp = rotate(a, 5) + f + e + k + block[index];
            e = d;
            d = c;
            c = rotate(b, 30);
            b = a;
            a = temp;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }
    for (int index = 0; index < 5; ++index) {
        digest[index * 4] = static_cast<unsigned char>((state[index] >> 24) & 0xff);
        digest[index * 4 + 1] = static_cast<unsigned char>((state[index] >> 16) & 0xff);
        digest[index * 4 + 2] = static_cast<unsigned char>((state[index] >> 8) & 0xff);
        digest[index * 4 + 3] = static_cast<unsigned char>(state[index] & 0xff);
    }
    static constexpr char digits[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    for (std::size_t index = 0; index < digest.size(); index += 3) {
        const std::uint32_t chunk =
            static_cast<std::uint32_t>(digest[index]) << 16 |
            (index + 1 < digest.size() ? static_cast<std::uint32_t>(digest[index + 1]) << 8 : 0) |
            (index + 2 < digest.size() ? static_cast<std::uint32_t>(digest[index + 2]) : 0);
        encoded.push_back(digits[(chunk >> 18) & 0x3f]);
        encoded.push_back(digits[(chunk >> 12) & 0x3f]);
        encoded.push_back(index + 1 < digest.size() ? digits[(chunk >> 6) & 0x3f] : '=');
        encoded.push_back(index + 2 < digest.size() ? digits[chunk & 0x3f] : '=');
    }
    return encoded;
}

std::string ws_accept_response(const std::string &request) {
    return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: "
           "Upgrade\r\nSec-WebSocket-Accept: " +
           sec_accept_for(request) + "\r\n\r\n";
}

// Reads one masked client frame and returns the unmasked payload.
std::vector<std::uint8_t> read_client_frame(RawPeer &peer) {
    const auto header = peer.read_exactly(2);
    if ((header[1] & 0x80) == 0) {
        throw std::runtime_error("client frame must be masked");
    }
    std::size_t length = header[1] & 0x7f;
    if (length == 126) {
        const auto extended = peer.read_exactly(2);
        length = (static_cast<std::size_t>(extended[0]) << 8) | extended[1];
    } else if (length == 127) {
        throw std::runtime_error("overlong frame length");
    }
    const auto mask = peer.read_exactly(4);
    auto payload = peer.read_exactly(length);
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] ^= mask[index % 4];
    }
    return payload;
}

template <stdexec::sender S> auto sync_get(S &&sender) {
    auto result = stdexec::sync_wait(std::forward<S>(sender));
    if (!result) {
        throw std::runtime_error("sync_get: sender completed with set_stopped");
    }
    return std::get<0>(std::move(*result));
}

} // namespace

TEST(WebSocketClientTest, EmbedsEarlyDataInPathAndFlushesRemainder) {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    std::uint16_t port = 0;
    RawPeer peer(&port);
    boost::asio::ip::tcp::socket client(context);
    client.connect({boost::asio::ip::address_v4::loopback(), port});
    peer.wait_accept();

    clash_native::transport::WebSocketClientOptions options;
    options.host = "example.com";
    options.target = "/ws";
    options.initial_payload = {'H', 'E', 'L', 'L', 'O', '-', 'W', 'O', 'R', 'L', 'D'};
    options.max_early_data = 5;
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(client));
    std::promise<clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>>> done;
    auto future = done.get_future();
    const auto handshake = clash_native::transport::async_websocket_client_handshake(
        std::move(stream), std::move(options),
        [&done](auto result) { done.set_value(std::move(result)); });
    std::thread worker([&] { context.run(); });

    const auto request = peer.read_request();
    // First five bytes base64url-encoded into the path ("HELLO" -> "SEVMTE8").
    EXPECT_NE(request.find("GET /wsSEVMTE8 HTTP/1.1\r\n"), std::string::npos);
    peer.write_all(ws_accept_response(request));
    const auto opened = future.get();
    ASSERT_TRUE(opened);
    // Remainder ("-WORLD") arrives as the first WebSocket message.
    EXPECT_EQ(read_client_frame(peer), (std::vector<std::uint8_t>{'-', 'W', 'O', 'R', 'L', 'D'}));
    opened.value()->close();
    context.stop();
    worker.join();
}

TEST(WebSocketClientTest, TunnelsRawBytesWithHttpUpgrade) {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    std::uint16_t port = 0;
    RawPeer peer(&port);
    boost::asio::ip::tcp::socket client(context);
    client.connect({boost::asio::ip::address_v4::loopback(), port});
    peer.wait_accept();

    clash_native::transport::WebSocketClientOptions options;
    options.host = "example.com";
    options.target = "/tunnel";
    options.v2ray_http_upgrade = true;
    options.initial_payload = {'R', 'A', 'W'};
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(client));
    std::promise<clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>>> done;
    auto future = done.get_future();
    const auto handshake = clash_native::transport::async_websocket_client_handshake(
        std::move(stream), std::move(options),
        [&done](auto result) { done.set_value(std::move(result)); });
    std::thread worker([&] { context.run(); });

    const auto request = peer.read_request();
    EXPECT_EQ(request.find("Sec-WebSocket-Key"), std::string::npos);
    EXPECT_NE(request.find("GET /tunnel HTTP/1.1\r\n"), std::string::npos);
    peer.write_all("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: "
                   "Upgrade\r\n\r\n");
    const auto opened = future.get();
    ASSERT_TRUE(opened);
    // Initial payload arrives raw (no framing).
    EXPECT_EQ(peer.read_exactly(3), (std::vector<std::uint8_t>{'R', 'A', 'W'}));
    // The tunnel echoes raw bytes both ways.
    const std::vector<std::uint8_t> ping{'p', 'i', 'n', 'g'};
    EXPECT_EQ(sync_get(opened.value()->async_write(boost::asio::buffer(ping))), 4U);
    EXPECT_EQ(peer.read_exactly(4), ping);
    opened.value()->close();
    context.stop();
    worker.join();
}
