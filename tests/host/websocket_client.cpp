#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/transport/websocket_client.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace {

using namespace std::chrono_literals;
using clash_native::core::StreamHandle;

constexpr std::size_t kPayloadSize = 256 * 1024;

struct ServerAddress {
    boost::asio::ip::address address;
    std::uint16_t port = 0;
};

ServerAddress parse_address(std::string_view value) {
    const auto separator = value.rfind(':');
    if (separator == std::string_view::npos || separator == 0 || separator + 1 == value.size()) {
        throw std::runtime_error("WebSocket server must be formatted as IPv4:port");
    }
    unsigned int port = 0;
    for (const auto character : value.substr(separator + 1)) {
        if (character < '0' || character > '9') {
            throw std::runtime_error("WebSocket server port is invalid");
        }
        port = port * 10 + static_cast<unsigned int>(character - '0');
        if (port > 65535) {
            throw std::runtime_error("WebSocket server port is out of range");
        }
    }
    if (port == 0) {
        throw std::runtime_error("WebSocket server port is out of range");
    }
    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(value.substr(0, separator), error);
    if (error || !address.is_v4()) {
        throw std::runtime_error("WebSocket server must use an IPv4 address");
    }
    return {address, static_cast<std::uint16_t>(port)};
}

std::vector<std::uint8_t> make_payload() {
    std::vector<std::uint8_t> payload(kPayloadSize);
    constexpr std::string_view marker = "clash-native-websocket-interop";
    std::copy(marker.begin(), marker.end(), payload.begin());
    for (std::size_t index = marker.size(); index < payload.size(); ++index) {
        payload[index] = static_cast<std::uint8_t>((index * 31U + 17U) & 0xffU);
    }
    return payload;
}

class WebSocketProbe final : public std::enable_shared_from_this<WebSocketProbe> {
  public:
    WebSocketProbe(boost::asio::io_context &context, ServerAddress server)
        : context_(context), server_(std::move(server)), timer_(context), payload_(make_payload()) {
    }

    void start() {
        boost::asio::ip::tcp::socket socket(context_);
        boost::system::error_code error;
        socket.connect({server_.address, server_.port}, error);
        if (error) {
            fail("failed to connect to WebSocket server: " + error.message());
            return;
        }
        auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(socket));

        timer_.expires_after(20s);
        const auto self = shared_from_this();
        timer_.async_wait([self](const boost::system::error_code &timer_error) {
            if (!timer_error && !self->finished_) {
                self->fail("WebSocket interoperability probe timed out");
            }
        });

        clash_native::transport::WebSocketClientOptions options;
        options.host = server_.address.to_string() + ":" + std::to_string(server_.port);
        options.target = "/ws";
        options.headers = {{"x-test-websocket", "clash-native"}};
        options.deadline = std::chrono::steady_clock::now() + 10s;
        (void)clash_native::transport::async_websocket_client_handshake(
            std::move(stream), std::move(options),
            [self](clash_native::core::Result<std::unique_ptr<StreamHandle>> result) {
                if (!result) {
                    self->fail("WebSocket handshake failed: " + result.error().context);
                    return;
                }
                self->stream_ = std::move(result.value());
                self->write_payload();
            });
    }

    bool succeeded() const noexcept { return finished_ && error_.empty(); }
    const std::string &error() const noexcept { return error_; }

  private:
    void write_payload() {
        const auto self = shared_from_this();
        stream_->async_write(boost::asio::buffer(payload_),
                             [self](const boost::system::error_code &error, std::size_t size) {
                                 if (error) {
                                     self->fail("WebSocket write failed: " + error.message());
                                     return;
                                 }
                                 if (size != self->payload_.size()) {
                                     self->fail(
                                         "WebSocket write completed with an unexpected size");
                                     return;
                                 }
                                 self->read_next();
                             });
    }

    void read_next() {
        if (finished_) {
            return;
        }
        const auto self = shared_from_this();
        stream_->async_read_some(
            boost::asio::buffer(read_buffer_),
            [self](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    self->fail("WebSocket read failed: " + error.message());
                    return;
                }
                if (size == 0 || self->received_ + size > self->payload_.size() ||
                    !std::equal(self->read_buffer_.begin(), self->read_buffer_.begin() + size,
                                self->payload_.begin() + self->received_)) {
                    self->fail("WebSocket echo payload did not match");
                    return;
                }
                self->received_ += size;
                if (self->received_ == self->payload_.size()) {
                    self->finish_success();
                    return;
                }
                self->read_next();
            });
    }

    void finish_success() {
        if (finished_) {
            return;
        }
        finished_ = true;
        timer_.cancel();
        if (stream_) {
            stream_->close();
        }
        spdlog::info("WEBSOCKET_OK");
        context_.stop();
    }

    void fail(std::string message) {
        if (finished_) {
            return;
        }
        finished_ = true;
        error_ = std::move(message);
        timer_.cancel();
        if (stream_) {
            stream_->close();
        }
        spdlog::error("{}", error_);
        context_.stop();
    }

    boost::asio::io_context &context_;
    ServerAddress server_;
    boost::asio::steady_timer timer_;
    std::unique_ptr<StreamHandle> stream_;
    std::vector<std::uint8_t> payload_;
    std::array<std::uint8_t, 16 * 1024> read_buffer_{};
    std::size_t received_ = 0;
    std::string error_;
    bool finished_ = false;
};

} // namespace

int main(int argc, char **argv) {
    auto logger = spdlog::stdout_color_mt("clash-native-websocket-client");
    logger->set_pattern("%v");
    logger->set_level(spdlog::level::info);
    logger->flush_on(spdlog::level::info);
    spdlog::set_default_logger(std::move(logger));

    if (argc != 2) {
        spdlog::error("usage: clash-native-websocket-client IPv4:port");
        return EXIT_FAILURE;
    }

    try {
        const auto server = parse_address(argv[1]);
        boost::asio::io_context context;
        const auto probe = std::make_shared<WebSocketProbe>(context, server);
        probe->start();
        context.run();
        return probe->succeeded() ? EXIT_SUCCESS : EXIT_FAILURE;
    } catch (const std::exception &error) {
        spdlog::error("{}", error.what());
        return EXIT_FAILURE;
    }
}
