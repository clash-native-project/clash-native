#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/net/udp_stream.hpp>
#include <clash_native/transport/http_sessions.hpp>
#include <clash_native/transport/quic_client.hpp>
#include <clash_native/transport/tls_client.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace {

using namespace std::chrono_literals;
using clash_native::io::ExchangeField;
using clash_native::io::ExchangeSession;
using clash_native::io::StreamHandle;
using clash_native::io::StreamingExchangeRequest;
using clash_native::io::StreamingExchangeResponse;

constexpr std::size_t kStreamingBodySize = 2 * 1024 * 1024;
constexpr std::size_t kStreamingReadSize = 32 * 1024;

std::vector<std::uint8_t> make_streaming_payload(std::string_view marker, unsigned int index) {
    std::vector<std::uint8_t> payload(kStreamingBodySize);
    const auto marker_size = std::min(marker.size(), payload.size());
    std::copy_n(marker.begin(), marker_size, payload.begin());
    for (std::size_t offset = marker_size; offset < payload.size(); ++offset) {
        payload[offset] = static_cast<std::uint8_t>((offset * 31 + index * 17) & 0xffU);
    }
    return payload;
}

class TestBodyStream final : public clash_native::io::ExchangeBodyStream,
                             public std::enable_shared_from_this<TestBodyStream> {
  public:
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    TestBodyStream(boost::asio::any_io_executor executor, std::vector<std::uint8_t> payload,
                   std::string trailer_value)
        : executor_(std::move(executor)), payload_(std::move(payload)),
          trailers_{{"X-Request-Trailer", std::move(trailer_value)}} {}

    clash_native::io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return clash_native::io::AnySender<std::optional<std::size_t>>{
            clash_native::async::callback_sender<Signatures>(
                [self = shared_from_this(), buffer](auto terminal) mutable {
                    self->read_some(buffer, std::move(terminal));
                },
                [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                    if (!error) {
                        stdexec::set_value(std::move(receiver), std::optional<std::size_t>{size});
                        return;
                    }
                    if (error == boost::asio::error::eof) {
                        stdexec::set_value(std::move(receiver), std::optional<std::size_t>{});
                        return;
                    }
                    if (error == boost::asio::error::operation_aborted) {
                        stdexec::set_stopped(std::move(receiver));
                        return;
                    }
                    stdexec::set_error(std::move(receiver),
                                       std::make_exception_ptr(clash_native::core::Error{
                                           clash_native::core::ErrorCode::transport_io,
                                           "test body read failed", error}));
                })};
    }

    void read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        const auto self = shared_from_this();
        boost::asio::post(executor_, [self, buffer, handler = std::move(handler)]() mutable {
            if (self->cancelled_.load()) {
                handler(boost::asio::error::operation_aborted, 0);
                return;
            }
            if (self->offset_ == self->payload_.size()) {
                handler(boost::asio::error::eof, 0);
                return;
            }
            const auto amount =
                std::min(boost::asio::buffer_size(buffer), self->payload_.size() - self->offset_);
            if (amount == 0) {
                handler(boost::asio::error::invalid_argument, 0);
                return;
            }
            std::memcpy(buffer.data(), self->payload_.data() + self->offset_, amount);
            self->offset_ += amount;
            handler({}, amount);
        });
    }

    std::vector<ExchangeField> trailers() const override { return trailers_; }

    void cancel() noexcept override { cancelled_.store(true); }

  private:
    boost::asio::any_io_executor executor_;
    std::vector<std::uint8_t> payload_;
    std::vector<ExchangeField> trailers_;
    std::size_t offset_ = 0;
    std::atomic_bool cancelled_ = false;
};

struct ServerAddress {
    boost::asio::ip::address address;
    std::uint16_t port = 0;
};

ServerAddress parse_address(std::string_view value) {
    const auto separator = value.rfind(':');
    if (separator == std::string_view::npos || separator == 0 || separator + 1 == value.size()) {
        throw std::runtime_error("server must be formatted as IPv4:port");
    }
    unsigned int port = 0;
    for (const char character : value.substr(separator + 1)) {
        if (character < '0' || character > '9') {
            throw std::runtime_error("server port is invalid");
        }
        port = port * 10 + static_cast<unsigned int>(character - '0');
        if (port > 65535) {
            throw std::runtime_error("server port is out of range");
        }
    }
    if (port == 0) {
        throw std::runtime_error("server port is out of range");
    }
    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(value.substr(0, separator), error);
    if (error || !address.is_v4()) {
        throw std::runtime_error("server must use an IPv4 address");
    }
    return {address, static_cast<std::uint16_t>(port)};
}

class TunnelProbe final : public std::enable_shared_from_this<TunnelProbe> {
  public:
    TunnelProbe(boost::asio::io_context &context, std::string mode)
        : context_(context), mode_(std::move(mode)), timer_(context) {}

    void start(std::shared_ptr<ExchangeSession> session, unsigned int expected_status) {
        session_ = std::move(session);
        expected_status_ = expected_status;
        timer_.expires_after(12s);
        const auto self = shared_from_this();
        timer_.async_wait([self](const boost::system::error_code &error) {
            if (!error) {
                self->finish("HTTP tunnel probe timed out");
            }
        });
        clash_native::io::StreamUpgradeRequest request;
        request.authority = "tunnel.test:443";
        if (mode_ == "upgrade") {
            request.mode = clash_native::io::StreamUpgradeMode::upgrade;
            request.scheme = "http";
            request.target = "/ws";
            request.protocol = "websocket";
            request.headers = {{"sec-websocket-version", "13"},
                               {"sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="},
                               {"x-test-extended-connect", "1"}};
        }
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        struct TunnelReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<TunnelProbe> self;
            void set_value(clash_native::io::StreamUpgradeResponse result) && noexcept {
                self->on_tunnel(std::move(result));
            }
            void set_error(std::exception_ptr error) && noexcept {
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const clash_native::core::Error &failure) {
                    self->finish("open_tunnel failed: " + failure.context);
                } catch (...) {
                    self->finish("open_tunnel failed");
                }
            }
            void set_stopped() && noexcept { self->finish("open_tunnel stopped"); }
        };
        clash_native::async::start_with_receiver(
            session_->open_tunnel(std::move(request), deadline), TunnelReceiver{self});
    }

    void on_tunnel(clash_native::io::StreamUpgradeResponse result) {
        if (!result.stream) {
            finish("server rejected the HTTP tunnel with status " +
                   std::to_string(result.response.status));
            return;
        }
        if (result.response.status != expected_status_) {
            finish("unexpected HTTP tunnel response status " +
                   std::to_string(result.response.status));
            return;
        }
        stream_ = std::move(result.stream);
        write_payload();
    }

    bool succeeded() const noexcept { return error_.empty(); }
    const std::string &error() const noexcept { return error_; }
    void fail(std::string error) { finish(std::move(error)); }

  private:
    void write_payload() {
        struct WriteReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<TunnelProbe> self;
            void set_value(std::size_t size) && noexcept {
                if (size != self->payload_.size()) {
                    self->finish("failed to write the tunnel payload");
                    return;
                }
                self->read_payload();
            }
            void set_error(std::exception_ptr) && noexcept {
                self->finish("failed to write the tunnel payload");
            }
            void set_stopped() && noexcept { self->finish("tunnel write stopped"); }
        };
        const auto self = shared_from_this();
        auto sender = stream_->async_write(boost::asio::buffer(payload_));
        clash_native::async::start_with_receiver(std::move(sender), WriteReceiver{self});
    }

    void read_payload() {
        struct ReadReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<TunnelProbe> self;
            void set_value(std::optional<std::size_t> size) && noexcept {
                self->on_tunnel_read(size ? boost::system::error_code{} : boost::asio::error::eof,
                                     size.value_or(0));
            }
            void set_error(std::exception_ptr error) && noexcept {
                self->on_tunnel_read(clash_native::net::unpack_error(std::move(error)), 0);
            }
            void set_stopped() && noexcept {
                self->on_tunnel_read(boost::asio::error::operation_aborted, 0);
            }
        };
        const auto self = shared_from_this();
        auto sender = stream_->async_read_some(boost::asio::buffer(read_buffer_));
        clash_native::async::start_with_receiver(std::move(sender), ReadReceiver{self});
    }

    void on_tunnel_read(const boost::system::error_code &error, std::size_t size) {
        const auto self = shared_from_this();
        {
            if (size != 0) {
                if (size > self->payload_.size() - self->received_.size()) {
                    self->finish("tunnel echoed more bytes than were written");
                    return;
                }
                self->received_.append(reinterpret_cast<const char *>(self->read_buffer_.data()),
                                       size);
                if (self->received_.size() == self->payload_.size() && !self->send_half_closed_) {
                    boost::system::error_code shutdown_error;
                    self->stream_->shutdown_send(shutdown_error);
                    if (shutdown_error) {
                        self->finish("failed to half-close the tunnel send side");
                        return;
                    }
                    self->send_half_closed_ = true;
                }
            }
            if (error) {
                if (error == boost::asio::error::eof && self->send_half_closed_ &&
                    self->received_ == self->payload_) {
                    self->finish({});
                } else {
                    self->finish("tunnel read failed: " + error.message());
                }
                return;
            }
            if (self->send_half_closed_) {
                self->read_payload();
            } else if (self->received_ != self->payload_) {
                self->read_payload();
            }
        }
    }

    void finish(std::string error) {
        if (finished_) {
            return;
        }
        finished_ = true;
        error_ = std::move(error);
        (void)timer_.cancel();
        if (stream_) {
            stream_->close();
            stream_.reset();
        }
        if (session_) {
            session_->stop();
            session_.reset();
        }
        context_.stop();
    }

    boost::asio::io_context &context_;
    std::string mode_;
    unsigned int expected_status_ = 200;
    boost::asio::steady_timer timer_;
    std::shared_ptr<ExchangeSession> session_;
    std::unique_ptr<StreamHandle> stream_;
    const std::string payload_ = "clash-native-http-full-duplex-tunnel";
    std::array<std::uint8_t, 1024> read_buffer_{};
    std::string received_;
    std::string error_;
    bool send_half_closed_ = false;
    bool finished_ = false;
};

class StreamingProbe final : public std::enable_shared_from_this<StreamingProbe> {
  public:
    StreamingProbe(boost::asio::io_context &context, bool declare_request_trailers)
        : context_(context), delay_timer_(context),
          declare_request_trailers_(declare_request_trailers) {}

    void start(std::shared_ptr<ExchangeSession> session) {
        session_ = std::move(session);
        timeout_timer_.emplace(context_);
        timeout_timer_->expires_after(45s);
        const auto self = shared_from_this();
        timeout_timer_->async_wait([self](const boost::system::error_code &error) {
            if (!error) {
                self->finish("HTTP streaming probe timed out");
            }
        });

        for (std::size_t index = 0; index < exchanges_.size(); ++index) {
            auto request = make_request(index);
            struct StreamingReceiver {
                using receiver_concept = stdexec::receiver_tag;
                std::shared_ptr<StreamingProbe> self;
                std::size_t index;
                void set_value(StreamingExchangeResponse result) && noexcept {
                    self->on_response(index, std::move(result));
                }
                void set_error(std::exception_ptr error) && noexcept {
                    try {
                        std::rethrow_exception(std::move(error));
                    } catch (const clash_native::core::Error &failure) {
                        self->on_response(index, clash_native::core::fail(failure));
                    } catch (...) {
                        self->on_response(index, clash_native::core::fail(clash_native::core::Error{
                                                     clash_native::core::ErrorCode::transport_io,
                                                     "exchange failed"}));
                    }
                }
                void set_stopped() && noexcept {
                    self->on_response(
                        index, clash_native::core::fail(clash_native::core::Error{
                                   clash_native::core::ErrorCode::cancelled, "exchange stopped"}));
                }
            };
            auto sender = session_->exchange_streaming(std::move(request),
                                                       std::chrono::steady_clock::now() + 40s);
            clash_native::async::start_with_receiver(std::move(sender),
                                                     StreamingReceiver{self, index});
        }
    }

    bool succeeded() const noexcept { return finished_ && error_.empty(); }
    const std::string &error() const noexcept { return error_; }
    void fail(std::string error) { finish(std::move(error)); }

  private:
    struct Exchange {
        std::string id;
        std::shared_ptr<clash_native::io::ExchangeBodyStream> request_body;
        std::shared_ptr<clash_native::io::ExchangeBodyStream> response_body;
        std::vector<std::uint8_t> received;
        std::array<std::uint8_t, kStreamingReadSize> read_buffer{};
        bool response_ready = false;
        bool reading = false;
        bool complete = false;
    };

    StreamingExchangeRequest make_request(std::size_t index) {
        auto &exchange = exchanges_[index];
        exchange.id = index == 0 ? "A" : "B";
        exchange.received.reserve(kStreamingBodySize);

        StreamingExchangeRequest request;
        request.request.method = "POST";
        request.request.scheme = "http";
        request.request.authority = "localhost";
        request.request.target = "/stream/" + exchange.id;
        request.request.headers.push_back({"X-Test-Id", exchange.id});
        if (declare_request_trailers_) {
            request.request.headers.push_back({"Trailer", "X-Request-Trailer"});
        }
        request.body = std::make_shared<TestBodyStream>(
            context_.get_executor(), make_streaming_payload("UPLOAD-" + exchange.id, index),
            "request-done-" + exchange.id);
        exchange.request_body = request.body;
        return request;
    }

    static std::string find_header(const std::vector<ExchangeField> &headers,
                                   std::string_view expected_name) {
        for (const auto &header : headers) {
            if (header.name.size() == expected_name.size() &&
                std::equal(header.name.begin(), header.name.end(), expected_name.begin(),
                           [](char left, char right) {
                               if (left >= 'A' && left <= 'Z') {
                                   left = static_cast<char>(left - 'A' + 'a');
                               }
                               if (right >= 'A' && right <= 'Z') {
                                   right = static_cast<char>(right - 'A' + 'a');
                               }
                               return left == right;
                           })) {
                return header.value;
            }
        }
        return {};
    }

    void
    on_response(std::size_t index,
                clash_native::core::Result<clash_native::io::StreamingExchangeResponse> result) {
        if (finished_) {
            return;
        }
        if (!result) {
            finish("exchange " + exchanges_[index].id + " failed: " + result.error().context);
            return;
        }
        if (result->response.status != 200 ||
            find_header(result->response.headers, "x-test-id") != exchanges_[index].id ||
            !result->body) {
            finish("exchange " + exchanges_[index].id + " returned unexpected response headers: " +
                   "status=" + std::to_string(result->response.status) +
                   ", x-test-id=" + find_header(result->response.headers, "x-test-id") +
                   ", x-test-error=" + find_header(result->response.headers, "x-test-error") +
                   ", body=" + (result->body ? "present" : "missing"));
            return;
        }
        exchanges_[index].response_body = std::move(result->body);
        exchanges_[index].response_ready = true;
        schedule_delayed_reads();
    }

    void schedule_delayed_reads() {
        if (delay_armed_ || finished_) {
            return;
        }
        delay_armed_ = true;
        // Let the peer send well beyond a normal HTTP/2 window before returning body credit.
        delay_timer_.expires_after(400ms);
        const auto self = shared_from_this();
        delay_timer_.async_wait([self](const boost::system::error_code &error) {
            self->delay_armed_ = false;
            if (error || self->finished_) {
                return;
            }
            for (std::size_t index = 0; index < self->exchanges_.size(); ++index) {
                if (self->exchanges_[index].response_ready && !self->exchanges_[index].reading) {
                    self->read_response(index);
                }
            }
        });
    }

    void read_response(std::size_t index) {
        auto &exchange = exchanges_[index];
        if (finished_ || exchange.complete) {
            return;
        }
        exchange.reading = true;
        struct BodyReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<StreamingProbe> self;
            std::size_t index;
            void set_value(std::optional<std::size_t> size) && noexcept {
                if (size) {
                    self->on_body_read(index, {}, *size);
                } else {
                    self->on_body_read(index, boost::asio::error::eof, 0);
                }
            }
            void set_error(std::exception_ptr error) && noexcept {
                self->on_body_read(index, clash_native::net::unpack_error(std::move(error)), 0);
            }
            void set_stopped() && noexcept {
                self->on_body_read(index, boost::asio::error::operation_aborted, 0);
            }
        };
        const auto self = shared_from_this();
        auto sender =
            exchange.response_body->async_read_some(boost::asio::buffer(exchange.read_buffer));
        clash_native::async::start_with_receiver(std::move(sender), BodyReceiver{self, index});
    }

    void on_body_read(std::size_t index, const boost::system::error_code &error, std::size_t size) {
        if (finished_) {
            return;
        }
        auto &exchange = exchanges_[index];
        if (size > kStreamingBodySize - std::min(exchange.received.size(), kStreamingBodySize)) {
            finish("exchange " + exchange.id + " response exceeded 2 MiB");
            return;
        }
        exchange.received.insert(exchange.received.end(), exchange.read_buffer.begin(),
                                 exchange.read_buffer.begin() + static_cast<std::ptrdiff_t>(size));
        if (error == boost::asio::error::eof) {
            const auto expected = make_streaming_payload("DOWNLOAD-" + exchange.id, index);
            const auto trailers = exchange.response_body->trailers();
            if (exchange.received != expected ||
                find_header(trailers, "x-response-trailer") != "response-done-" + exchange.id) {
                finish("exchange " + exchange.id + " response body or trailer did not match");
                return;
            }
            exchange.complete = true;
            ++completed_;
            if (completed_ == exchanges_.size()) {
                finish({});
            }
            return;
        }
        if (error) {
            finish("exchange " + exchange.id + " response read failed: " + error.message());
            return;
        }
        if (size == 0) {
            finish("exchange " + exchange.id + " response body read made no progress");
            return;
        }
        read_response(index);
    }

    void finish(std::string error) {
        if (finished_) {
            return;
        }
        finished_ = true;
        error_ = std::move(error);
        (void)delay_timer_.cancel();
        if (timeout_timer_) {
            (void)timeout_timer_->cancel();
        }
        for (auto &exchange : exchanges_) {
            if (exchange.request_body) {
                exchange.request_body->cancel();
                exchange.request_body.reset();
            }
            if (exchange.response_body) {
                exchange.response_body->cancel();
                exchange.response_body.reset();
            }
        }
        if (session_) {
            session_->stop();
            session_.reset();
        }
        context_.stop();
    }

    boost::asio::io_context &context_;
    boost::asio::steady_timer delay_timer_;
    std::optional<boost::asio::steady_timer> timeout_timer_;
    std::array<Exchange, 2> exchanges_;
    std::shared_ptr<ExchangeSession> session_;
    bool declare_request_trailers_ = false;
    bool delay_armed_ = false;
    bool finished_ = false;
    std::size_t completed_ = 0;
    std::string error_;
};

class RawQuicProbe final : public std::enable_shared_from_this<RawQuicProbe> {
  public:
    explicit RawQuicProbe(boost::asio::io_context &context)
        : context_(context), timeout_timer_(context) {}

    void start(std::shared_ptr<clash_native::transport::QuicClientConnection> connection) {
        connection_ = std::move(connection);
        timeout_timer_.expires_after(15s);
        const auto self = shared_from_this();
        timeout_timer_.async_wait([self](const boost::system::error_code &error) {
            if (!error) {
                self->finish("raw QUIC carrier probe timed out");
            }
        });

        clash_native::transport::QuicClientEvents events;
        events.ready = [self](std::string) { self->open_carrier_capabilities(); };
        events.failed = [self](clash_native::core::Error error) {
            self->finish("raw QUIC carrier failed: " + error.context);
        };
        connection_->set_events(std::move(events));
    }

    bool succeeded() const noexcept { return finished_ && error_.empty(); }
    const std::string &error() const noexcept { return error_; }

  private:
    static constexpr std::size_t kStreamCount = 4;

    void open_carrier_capabilities() {
        if (finished_ || opened_) {
            return;
        }
        opened_ = true;
        const auto maximum = connection_->max_concurrent_streams();
        if (!maximum || *maximum < kStreamCount) {
            finish("QUIC peer did not advertise enough bidirectional stream capacity");
            return;
        }
        datagram_ = connection_->open_datagram();
        if (!datagram_ || datagram_->max_datagram_size() == 0) {
            finish("QUIC DATAGRAM capability is unavailable after handshake");
            return;
        }

        datagram_buffer_.fill(0);
        const auto self = shared_from_this();
        struct DatagramReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<RawQuicProbe> self;
            void set_value(clash_native::io::DatagramPacket packet) && noexcept {
                if (std::string(reinterpret_cast<const char *>(self->datagram_buffer_.data()),
                                packet.size) != self->datagram_payload_) {
                    self->finish("QUIC DATAGRAM echo failed");
                    return;
                }
                self->datagram_done_ = true;
                self->maybe_finish();
            }
            void set_error(std::exception_ptr) && noexcept {
                self->finish("QUIC DATAGRAM echo failed");
            }
            void set_stopped() && noexcept { self->finish("QUIC DATAGRAM echo stopped"); }
        };
        auto receive_sender = datagram_->async_receive_from(boost::asio::buffer(datagram_buffer_));
        clash_native::async::start_with_receiver(std::move(receive_sender), DatagramReceiver{self});
        const auto payload =
            std::vector<std::uint8_t>(datagram_payload_.begin(), datagram_payload_.end());
        struct SendReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<RawQuicProbe> self;
            void set_value(std::size_t size) && noexcept {
                if (size != self->datagram_payload_.size()) {
                    self->finish("QUIC DATAGRAM send failed");
                }
            }
            void set_error(std::exception_ptr) && noexcept {
                self->finish("QUIC DATAGRAM send failed");
            }
            void set_stopped() && noexcept { self->finish("QUIC DATAGRAM send stopped"); }
        };
        auto send_sender = datagram_->async_send_to(
            boost::asio::buffer(payload),
            clash_native::io::DatagramAddress::from_endpoint(connection_->remote_endpoint()));
        clash_native::async::start_with_receiver(std::move(send_sender), SendReceiver{self});

        stream_handles_.resize(kStreamCount);
        stream_payloads_.resize(kStreamCount);
        for (std::size_t index = 0; index < kStreamCount; ++index) {
            stream_payloads_[index] = "quic-stream-" + std::to_string(index);
            clash_native::io::MultiplexedStreamRequest request;
            struct OpenReceiver {
                using receiver_concept = stdexec::receiver_tag;
                std::shared_ptr<RawQuicProbe> self;
                std::size_t index;
                void set_value(std::unique_ptr<clash_native::io::StreamHandle> stream) && noexcept {
                    self->stream_handles_[index] = std::move(stream);
                    ++self->streams_opened_;
                    if (self->streams_opened_ == kStreamCount &&
                        self->connection_->active_streams() < kStreamCount) {
                        self->finish("QUIC multiplexed session lost an active stream");
                        return;
                    }
                    self->write_stream(index);
                }
                void set_error(std::exception_ptr error) && noexcept {
                    try {
                        std::rethrow_exception(std::move(error));
                    } catch (const clash_native::core::Error &failure) {
                        self->finish("QUIC multiplexed stream open failed: " + failure.context);
                    } catch (...) {
                        self->finish("QUIC multiplexed stream open failed");
                    }
                }
                void set_stopped() && noexcept {
                    self->finish("QUIC multiplexed stream open stopped");
                }
            };
            auto sender = connection_->open_stream(request, std::chrono::steady_clock::now() + 10s);
            clash_native::async::start_with_receiver(std::move(sender), OpenReceiver{self, index});
        }
    }

    void write_stream(std::size_t index) {
        struct WriteReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<RawQuicProbe> self;
            std::size_t index;
            void set_value(std::size_t size) && noexcept {
                if (size != self->stream_payloads_[index].size()) {
                    self->finish("QUIC multiplexed stream write failed");
                    return;
                }
                self->read_stream(index);
            }
            void set_error(std::exception_ptr) && noexcept {
                self->finish("QUIC multiplexed stream write failed");
            }
            void set_stopped() && noexcept {
                self->finish("QUIC multiplexed stream write stopped");
            }
        };
        const auto self = shared_from_this();
        auto sender =
            stream_handles_[index]->async_write(boost::asio::buffer(stream_payloads_[index]));
        clash_native::async::start_with_receiver(std::move(sender), WriteReceiver{self, index});
    }

    void read_stream(std::size_t index) {
        struct ReadReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<RawQuicProbe> self;
            std::size_t index;
            std::shared_ptr<std::array<std::uint8_t, 128>> buffer;
            void set_value(std::optional<std::size_t> size) && noexcept {
                if (!size) {
                    self->finish("QUIC multiplexed stream echo read failed: eof");
                    return;
                }
                if (std::string(reinterpret_cast<const char *>(buffer->data()), *size) !=
                    self->stream_payloads_[index]) {
                    self->finish("QUIC multiplexed stream echo mismatch");
                    return;
                }
                self->stream_handles_[index]->close();
                self->stream_handles_[index].reset();
                ++self->streams_done_;
                self->maybe_finish();
            }
            void set_error(std::exception_ptr error) && noexcept {
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const clash_native::core::Error &failure) {
                    self->finish("QUIC multiplexed stream echo read failed: " + failure.context);
                } catch (...) {
                    self->finish("QUIC multiplexed stream echo read failed");
                }
            }
            void set_stopped() && noexcept {
                self->finish("QUIC multiplexed stream echo read stopped");
            }
        };
        const auto self = shared_from_this();
        auto buffer = std::make_shared<std::array<std::uint8_t, 128>>();
        stream_buffers_[index] = buffer;
        auto sender = stream_handles_[index]->async_read_some(boost::asio::buffer(*buffer));
        clash_native::async::start_with_receiver(std::move(sender),
                                                 ReadReceiver{self, index, buffer});
    }

    void maybe_finish() {
        if (streams_done_ == kStreamCount && datagram_done_) {
            finish({});
        }
    }

    void finish(std::string error) {
        if (finished_) {
            return;
        }
        finished_ = true;
        error_ = std::move(error);
        (void)timeout_timer_.cancel();
        for (auto &stream : stream_handles_) {
            if (stream) {
                stream->close();
                stream.reset();
            }
        }
        if (datagram_) {
            datagram_->close();
            datagram_.reset();
        }
        if (connection_) {
            connection_->close();
            connection_.reset();
        }
        context_.stop();
    }

    boost::asio::io_context &context_;
    boost::asio::steady_timer timeout_timer_;
    std::shared_ptr<clash_native::transport::QuicClientConnection> connection_;
    std::unique_ptr<clash_native::io::DatagramHandle> datagram_;
    std::vector<std::unique_ptr<clash_native::io::StreamHandle>> stream_handles_;
    std::vector<std::string> stream_payloads_;
    std::vector<std::shared_ptr<std::array<std::uint8_t, 128>>> stream_buffers_ =
        std::vector<std::shared_ptr<std::array<std::uint8_t, 128>>>(kStreamCount);
    std::array<std::uint8_t, 128> datagram_buffer_{};
    const std::string datagram_payload_ = "quic-datagram";
    std::string error_;
    std::size_t streams_opened_ = 0;
    std::size_t streams_done_ = 0;
    bool datagram_done_ = false;
    bool opened_ = false;
    bool finished_ = false;
};

std::unique_ptr<clash_native::io::StreamHandle> connect_tcp(boost::asio::io_context &context,
                                                            const ServerAddress &server) {
    boost::asio::ip::tcp::socket socket(context);
    socket.connect({server.address, server.port});
    return std::make_unique<clash_native::net::TcpStream>(std::move(socket));
}

int run_http1(const ServerAddress &server, const std::string &mode) {
    boost::asio::io_context context;
    auto session =
        clash_native::transport::make_http1_exchange_session(connect_tcp(context, server));
    if (mode == "streaming") {
        auto probe = std::make_shared<StreamingProbe>(context, true);
        boost::asio::post(context, [probe, session = std::move(session)]() mutable {
            probe->start(std::move(session));
        });
        context.run();
        if (!probe->succeeded()) {
            spdlog::error("{}", probe->error());
            return 1;
        }
        return 0;
    }
    const auto expected_status = mode == "upgrade" ? 101U : 200U;
    auto probe = std::make_shared<TunnelProbe>(context, mode);
    boost::asio::post(context, [probe, session = std::move(session), expected_status]() mutable {
        probe->start(std::move(session), expected_status);
    });
    context.run();
    if (!probe->succeeded()) {
        spdlog::error("{}", probe->error());
        return 1;
    }
    return 0;
}

int run_http2(const ServerAddress &server, const std::string &mode) {
    boost::asio::io_context context;
    const auto is_streaming = mode == "streaming";
    auto tunnel_probe = is_streaming ? std::shared_ptr<TunnelProbe>{}
                                     : std::make_shared<TunnelProbe>(context, mode);
    auto streaming_probe = is_streaming ? std::make_shared<StreamingProbe>(context, true)
                                        : std::shared_ptr<StreamingProbe>{};
    const auto fail_probe = [tunnel_probe, streaming_probe](std::string error) {
        if (streaming_probe) {
            streaming_probe->fail(std::move(error));
        } else {
            tunnel_probe->fail(std::move(error));
        }
    };
    clash_native::transport::TlsClientOptions options;
    options.server_name = "localhost";
    options.verify_peer = false;
    options.alpn_protocols = {"h2"};
    options.deadline = std::chrono::steady_clock::now() + 10s;
    struct TlsReceiver {
        using receiver_concept = stdexec::receiver_tag;
        using FailProbe = decltype(fail_probe);
        std::shared_ptr<TunnelProbe> tunnel_probe;
        std::shared_ptr<StreamingProbe> streaming_probe;
        FailProbe fail_probe;
        void set_value(clash_native::transport::TlsClientConnection connection) && noexcept {
            if (connection.negotiated_alpn != "h2") {
                fail_probe("TLS server did not negotiate HTTP/2");
                return;
            }
            auto session =
                clash_native::transport::make_http2_exchange_session(std::move(connection.stream));
            if (!session) {
                fail_probe("failed to create HTTP/2 client session");
                return;
            }
            if (streaming_probe) {
                streaming_probe->start(std::move(session));
            } else {
                tunnel_probe->start(std::move(session), 200);
            }
        }
        void set_error(std::exception_ptr error) && noexcept {
            try {
                std::rethrow_exception(std::move(error));
            } catch (const clash_native::core::Error &failure) {
                fail_probe("HTTP/2 TLS handshake failed: " + failure.context);
            } catch (...) {
                fail_probe("HTTP/2 TLS handshake failed");
            }
        }
        void set_stopped() && noexcept { fail_probe("HTTP/2 TLS handshake stopped"); }
    };
    clash_native::async::start_with_receiver(
        clash_native::transport::async_tls_client_handshake(connect_tcp(context, server),
                                                            std::move(options)),
        TlsReceiver{tunnel_probe, streaming_probe, fail_probe});
    context.run();
    const auto success = streaming_probe ? streaming_probe->succeeded() : tunnel_probe->succeeded();
    if (!success) {
        spdlog::error("{}", streaming_probe ? streaming_probe->error() : tunnel_probe->error());
        return 1;
    }
    return 0;
}

int run_http3(const ServerAddress &server, const std::string &mode) {
    boost::asio::io_context context;
    const auto is_streaming = mode == "streaming";
    auto tunnel_probe = is_streaming ? std::shared_ptr<TunnelProbe>{}
                                     : std::make_shared<TunnelProbe>(context, mode);
    auto streaming_probe = is_streaming ? std::make_shared<StreamingProbe>(context, true)
                                        : std::shared_ptr<StreamingProbe>{};
    auto datagram = std::make_unique<clash_native::net::UdpStream>(context.get_executor());
    boost::system::error_code error;
    datagram->open(boost::asio::ip::udp::v4(), error);
    if (!error) {
        datagram->bind({boost::asio::ip::address_v4::loopback(), 0}, error);
    }
    if (error) {
        throw std::system_error(error, "failed to open QUIC UDP socket");
    }
    clash_native::transport::QuicClientOptions options;
    options.server_name = "localhost";
    options.verify_peer = false;
    options.alpn_protocols = {"h3"};
    options.handshake_timeout = 10s;
    const auto connection = clash_native::transport::make_quic_client_connection(
        context.get_executor(), std::move(datagram), {server.address, server.port},
        std::move(options), {});
    if (!connection) {
        spdlog::error("failed to create QUIC client connection");
        return 1;
    }
    const auto session = clash_native::transport::make_http3_exchange_session(
        connection, [tunnel_weak = std::weak_ptr<TunnelProbe>(tunnel_probe),
                     streaming_weak = std::weak_ptr<StreamingProbe>(streaming_probe)](
                        clash_native::core::Error error) {
            if (const auto locked = streaming_weak.lock()) {
                locked->fail("HTTP/3 session failed: " + error.context);
            } else if (const auto locked = tunnel_weak.lock()) {
                locked->fail("HTTP/3 session failed: " + error.context);
            }
        });
    boost::asio::post(context, [tunnel_probe, streaming_probe, session] {
        if (streaming_probe) {
            streaming_probe->start(session);
        } else {
            tunnel_probe->start(session, 200);
        }
    });
    context.run();
    const auto success = streaming_probe ? streaming_probe->succeeded() : tunnel_probe->succeeded();
    if (!success) {
        spdlog::error("{}", streaming_probe ? streaming_probe->error() : tunnel_probe->error());
        return 1;
    }
    return 0;
}

int run_raw_quic(const ServerAddress &server) {
    boost::asio::io_context context;
    auto datagram = std::make_unique<clash_native::net::UdpStream>(context.get_executor());
    boost::system::error_code error;
    datagram->open(boost::asio::ip::udp::v4(), error);
    if (!error) {
        datagram->bind({boost::asio::ip::address_v4::loopback(), 0}, error);
    }
    if (error) {
        throw std::system_error(error, "failed to open QUIC UDP socket");
    }
    clash_native::transport::QuicClientOptions options;
    options.server_name = "localhost";
    options.verify_peer = false;
    options.alpn_protocols = {"raw-quic"};
    options.handshake_timeout = 10s;
    const auto connection = clash_native::transport::make_quic_client_connection(
        context.get_executor(), std::move(datagram), {server.address, server.port},
        std::move(options), {});
    if (!connection) {
        spdlog::error("failed to create QUIC client connection");
        return 1;
    }
    const auto probe = std::make_shared<RawQuicProbe>(context);
    probe->start(connection);
    context.run();
    if (!probe->succeeded()) {
        spdlog::error("{}", probe->error());
        return 1;
    }
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    auto logger = spdlog::stdout_color_mt("clash-native-http-tunnel-client");
    logger->set_pattern("%v");
    logger->set_level(spdlog::level::info);
    logger->flush_on(spdlog::level::info);
    spdlog::set_default_logger(std::move(logger));

    if (argc < 3 || argc > 4) {
        spdlog::error("usage: clash-native-http-tunnel-client <http1|http2|http3|quic> "
                      "<IPv4:port> [connect|upgrade|streaming]");
        return 2;
    }
    try {
        const auto server = parse_address(argv[2]);
        const std::string protocol(argv[1]);
        const std::string mode = argc > 3 ? argv[3] : "connect";
        if (protocol == "http1" &&
            (mode == "connect" || mode == "upgrade" || mode == "streaming")) {
            return run_http1(server, mode);
        }
        if (protocol == "http2" &&
            (mode == "connect" || mode == "upgrade" || mode == "streaming")) {
            return run_http2(server, mode);
        }
        if (protocol == "http3" &&
            (mode == "connect" || mode == "upgrade" || mode == "streaming")) {
            return run_http3(server, mode);
        }
        if (protocol == "quic" && argc == 3) {
            return run_raw_quic(server);
        }
        spdlog::error("unsupported protocol/mode combination");
        return 2;
    } catch (const std::exception &error) {
        spdlog::error("{}", error.what());
        return 1;
    }
}
