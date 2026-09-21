#include <clash_native/net/udp_stream.hpp>
#include <clash_native/transport/kcp_client.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
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

constexpr std::size_t kPayloadSize = 256 * 1024;

struct ServerAddress {
    boost::asio::ip::address address;
    std::uint16_t port = 0;
};

ServerAddress parse_address(std::string_view value) {
    const auto separator = value.rfind(':');
    if (separator == std::string_view::npos || separator == 0 || separator + 1 == value.size()) {
        throw std::runtime_error("KCP server must be formatted as IPv4:port");
    }

    unsigned int port = 0;
    for (const auto character : value.substr(separator + 1)) {
        if (character < '0' || character > '9') {
            throw std::runtime_error("KCP server port is invalid");
        }
        port = port * 10 + static_cast<unsigned int>(character - '0');
        if (port > 65535) {
            throw std::runtime_error("KCP server port is out of range");
        }
    }
    if (port == 0) {
        throw std::runtime_error("KCP server port is out of range");
    }

    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(value.substr(0, separator), error);
    if (error || !address.is_v4()) {
        throw std::runtime_error("KCP server must use an IPv4 address");
    }
    return {address, static_cast<std::uint16_t>(port)};
}

std::vector<std::uint8_t> make_payload() {
    std::vector<std::uint8_t> payload(kPayloadSize);
    constexpr std::string_view marker = "clash-native-kcp-interop";
    std::copy(marker.begin(), marker.end(), payload.begin());
    for (std::size_t index = marker.size(); index < payload.size(); ++index) {
        payload[index] = static_cast<std::uint8_t>((index * 31U + 17U) & 0xffU);
    }
    return payload;
}

class KcpProbe final : public std::enable_shared_from_this<KcpProbe> {
  public:
    KcpProbe(boost::asio::io_context &context, ServerAddress server)
        : context_(context), server_(std::move(server)), timer_(context), payload_(make_payload()) {
    }

    void start() {
        auto datagram = std::make_unique<clash_native::net::UdpStream>(context_.get_executor());
        boost::system::error_code error;
        datagram->open(boost::asio::ip::udp::v4(), error);
        if (!error) {
            datagram->bind({boost::asio::ip::address_v4::any(), 0}, error);
        }
        if (error) {
            fail("failed to open KCP UDP socket: " + error.message());
            return;
        }

        clash_native::transport::KcpClientOptions options;
        options.conversation_id = 0x4b435031U;
        auto result = clash_native::transport::make_kcp_client_stream(
            std::move(datagram), {server_.address, server_.port}, options);
        if (!result) {
            fail("failed to create KCP stream: " + result.error().context);
            return;
        }
        stream_ = std::move(result.value());

        timer_.expires_after(20s);
        const auto self = shared_from_this();
        timer_.async_wait([self](const boost::system::error_code &timer_error) {
            if (!timer_error && !self->finished_) {
                self->fail("KCP interoperability probe timed out");
            }
        });

        stream_->async_write(
            boost::asio::buffer(payload_),
            [self](const boost::system::error_code &write_error, std::size_t size) {
                if (write_error) {
                    self->fail("KCP write failed: " + write_error.message());
                    return;
                }
                if (size != self->payload_.size()) {
                    self->fail("KCP write completed with an unexpected size");
                    return;
                }
                self->read_next();
            });
    }

    bool succeeded() const noexcept { return finished_ && error_.empty(); }
    const std::string &error() const noexcept { return error_; }

  private:
    void read_next() {
        if (finished_) {
            return;
        }
        const auto self = shared_from_this();
        stream_->async_read_some(
            boost::asio::buffer(read_buffer_),
            [self](const boost::system::error_code &read_error, std::size_t size) {
                if (read_error) {
                    self->fail("KCP read failed: " + read_error.message());
                    return;
                }
                if (size == 0 || self->received_ + size > self->payload_.size() ||
                    !std::equal(self->read_buffer_.begin(), self->read_buffer_.begin() + size,
                                self->payload_.begin() + self->received_)) {
                    self->fail("KCP echo payload did not match");
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
        finished_ = true;
        timer_.cancel();
        stream_->close();
        spdlog::info("KCP_OK");
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
    std::unique_ptr<clash_native::core::StreamHandle> stream_;
    std::vector<std::uint8_t> payload_;
    std::array<std::uint8_t, 16 * 1024> read_buffer_{};
    std::size_t received_ = 0;
    std::string error_;
    bool finished_ = false;
};

} // namespace

int main(int argc, char **argv) {
    auto logger = spdlog::stdout_color_mt("clash-native-kcp-client");
    logger->set_pattern("%v");
    logger->set_level(spdlog::level::info);
    logger->flush_on(spdlog::level::info);
    spdlog::set_default_logger(std::move(logger));

    if (argc != 2) {
        spdlog::error("usage: clash-native-kcp-client IPv4:port");
        return EXIT_FAILURE;
    }

    try {
        const auto server = parse_address(argv[1]);
        boost::asio::io_context context;
        const auto probe = std::make_shared<KcpProbe>(context, server);
        probe->start();
        context.run();
        return probe->succeeded() ? EXIT_SUCCESS : EXIT_FAILURE;
    } catch (const std::exception &error) {
        spdlog::error("{}", error.what());
        return EXIT_FAILURE;
    }
}
