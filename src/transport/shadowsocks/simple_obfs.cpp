#include <clash_native/transport/shadowsocks/simple_obfs.hpp>

#include <clash_native/core/base64.hpp>
#include <clash_native/transport/proxy/crypto.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kMaxResponseHeaderSize = 64 * 1024;
constexpr std::size_t kTlsObfsChunkSize = 1 << 14;
constexpr std::size_t kMaxTlsObfsRecordSize = 0xffff;

std::error_code to_std_error(const boost::system::error_code &error) {
    return {error.value(), std::system_category()};
}

core::Error io_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context), to_std_error(error)};
}

core::Error protocol_error(std::string context) {
    return {core::ErrorCode::carrier_handshake, std::move(context), {}};
}

bool has_invalid_header_value(std::string_view value) {
    return value.find_first_of("\r\n") != std::string_view::npos;
}

void append_u16(std::vector<std::uint8_t> &output, std::size_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append_u32(std::vector<std::uint8_t> &output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 24));
    output.push_back(static_cast<std::uint8_t>(value >> 16));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value));
}

std::uint16_t read_u16(std::span<const std::uint8_t> input) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(input[0]) << 8) | input[1]);
}

std::vector<std::uint8_t>
make_tls_client_hello_impl(std::span<const std::uint8_t> payload, std::string_view server_name,
                           std::span<const std::uint8_t> requested_session_id) {
    if (server_name.empty() || server_name.size() > 0xff ||
        payload.size() > std::numeric_limits<std::uint16_t>::max() ||
        server_name.size() + payload.size() > 0xff00) {
        return {};
    }
    std::array<std::uint8_t, 28> random_bytes_buffer{};
    std::array<std::uint8_t, 32> session_id{};
    if (!transport::proxy::random_bytes(random_bytes_buffer) ||
        (requested_session_id.empty() ? !transport::proxy::random_bytes(session_id)
                                      : requested_session_id.size() != session_id.size())) {
        return {};
    }
    if (!requested_session_id.empty()) {
        std::copy(requested_session_id.begin(), requested_session_id.end(), session_id.begin());
    }

    const auto body_length = 212 + payload.size() + server_name.size();
    const auto handshake_length = 208 + payload.size() + server_name.size();
    if (body_length > std::numeric_limits<std::uint16_t>::max() ||
        handshake_length > std::numeric_limits<std::uint16_t>::max()) {
        return {};
    }
    std::vector<std::uint8_t> output;
    output.reserve(5 + body_length);
    output.push_back(0x16);
    output.push_back(0x03);
    output.push_back(0x01);
    append_u16(output, body_length);
    output.push_back(0x01);
    output.push_back(0x00);
    append_u16(output, handshake_length);
    output.push_back(0x03);
    output.push_back(0x03);
    append_u32(output,
               static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count()));
    output.insert(output.end(), random_bytes_buffer.begin(), random_bytes_buffer.end());
    output.push_back(32);
    output.insert(output.end(), session_id.begin(), session_id.end());
    append_u16(output, 0x0038);
    output.insert(output.end(),
                  {0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa,
                   0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b,
                   0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39,
                   0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
                   0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff});
    output.insert(output.end(), {0x01, 0x00});
    append_u16(output, 79 + payload.size() + server_name.size());
    output.insert(output.end(), {0x00, 0x23});
    append_u16(output, payload.size());
    output.insert(output.end(), payload.begin(), payload.end());
    output.insert(output.end(), {0x00, 0x00});
    append_u16(output, server_name.size() + 5);
    append_u16(output, server_name.size() + 3);
    output.push_back(0);
    append_u16(output, server_name.size());
    output.insert(output.end(), server_name.begin(), server_name.end());
    output.insert(output.end(), {0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02});
    output.insert(output.end(), {0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00,
                                 0x19, 0x00, 0x18});
    output.insert(output.end(),
                  {0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03,
                   0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03,
                   0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03});
    output.insert(output.end(), {0x00, 0x16, 0x00, 0x00});
    output.insert(output.end(), {0x00, 0x17, 0x00, 0x00});
    return output;
}

std::vector<std::uint8_t> make_tls_records(std::span<const std::uint8_t> payload) {
    std::vector<std::uint8_t> output;
    output.reserve(payload.size() + (payload.size() / kTlsObfsChunkSize + 1) * 5);
    for (std::size_t offset = 0; offset < payload.size();) {
        const auto size = std::min(kTlsObfsChunkSize, payload.size() - offset);
        output.insert(output.end(), {0x17, 0x03, 0x03});
        append_u16(output, size);
        output.insert(output.end(), payload.begin() + static_cast<std::ptrdiff_t>(offset),
                      payload.begin() + static_cast<std::ptrdiff_t>(offset + size));
        offset += size;
    }
    return output;
}

class TlsObfsWrite final : public std::enable_shared_from_this<TlsObfsWrite> {
  public:
    TlsObfsWrite(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                 std::vector<std::uint8_t> wire, TlsObfsRequestHandler handler)
        : socket_(std::move(socket)), wire_(std::move(wire)), handler_(std::move(handler)) {}

    void start() {
        auto self = shared_from_this();
        boost::asio::async_write(*socket_, boost::asio::buffer(wire_),
                                 [self](const boost::system::error_code &error, std::size_t) {
                                     if (error) {
                                         self->finish(core::fail(io_error(
                                             "failed to write Shadowsocks TLS obfs", error)));
                                     } else {
                                         self->finish({});
                                     }
                                 });
    }

  private:
    void finish(core::Status result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::vector<std::uint8_t> wire_;
    TlsObfsRequestHandler handler_;
    bool completed_ = false;
};

class TlsObfsRead final : public std::enable_shared_from_this<TlsObfsRead> {
  public:
    TlsObfsRead(std::shared_ptr<boost::asio::ip::tcp::socket> socket, bool first_response,
                TlsObfsResponseHandler handler)
        : socket_(std::move(socket)), first_response_(first_response),
          handler_(std::move(handler)) {}

    void start() { read_discard(); }

  private:
    void read_discard() {
        const auto discard_size = first_response_ ? std::size_t(105) : std::size_t(3);
        discard_buffer_.resize(discard_size);
        auto self = shared_from_this();
        boost::asio::async_read(
            *socket_, boost::asio::buffer(discard_buffer_),
            [self](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    self->finish(
                        core::fail(io_error("failed to read Shadowsocks TLS obfs", error)));
                    return;
                }
                const auto expected_type = self->first_response_ ? 0x16 : 0x17;
                const auto expected_version = self->first_response_ ? 0x01 : 0x03;
                if (self->discard_buffer_.size() < 3 || self->discard_buffer_[0] != expected_type ||
                    self->discard_buffer_[1] != 0x03 ||
                    self->discard_buffer_[2] != expected_version) {
                    self->finish(
                        core::fail(protocol_error("invalid Shadowsocks TLS obfs record header")));
                    return;
                }
                self->read_length();
            });
    }

    void read_length() {
        auto self = shared_from_this();
        boost::asio::async_read(
            *socket_, boost::asio::buffer(length_buffer_),
            [self](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    self->finish(
                        core::fail(io_error("failed to read Shadowsocks TLS obfs length", error)));
                    return;
                }
                const auto length = read_u16(self->length_buffer_);
                if (length == 0 || length > kMaxTlsObfsRecordSize) {
                    self->finish(core::fail(
                        protocol_error("invalid Shadowsocks TLS obfs application record length")));
                    return;
                }
                self->payload_.resize(length);
                self->read_payload();
            });
    }

    void read_payload() {
        auto self = shared_from_this();
        boost::asio::async_read(*socket_, boost::asio::buffer(payload_),
                                [self](const boost::system::error_code &error, std::size_t) {
                                    if (error) {
                                        self->finish(core::fail(io_error(
                                            "failed to read Shadowsocks TLS obfs payload", error)));
                                        return;
                                    }
                                    self->finish(std::move(self->payload_));
                                });
    }

    void finish(core::Result<std::vector<std::uint8_t>> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    bool first_response_;
    TlsObfsResponseHandler handler_;
    std::vector<std::uint8_t> discard_buffer_;
    std::array<std::uint8_t, 2> length_buffer_{};
    std::vector<std::uint8_t> payload_;
    bool completed_ = false;
};

class HttpObfsRequest final : public std::enable_shared_from_this<HttpObfsRequest> {
  public:
    HttpObfsRequest(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                    std::vector<std::uint8_t> initial_payload, HttpObfsClientOptions options,
                    HttpObfsRequestHandler handler)
        : socket_(std::move(socket)), initial_payload_(std::move(initial_payload)),
          options_(std::move(options)), handler_(std::move(handler)) {}

    void start() {
        if (options_.host.empty() || options_.port == 0 ||
            has_invalid_header_value(options_.host)) {
            finish(core::fail(protocol_error("invalid Shadowsocks HTTP obfs host")));
            return;
        }

        std::array<std::uint8_t, 16> key_bytes{};
        if (!transport::proxy::random_bytes(key_bytes)) {
            finish(core::fail({core::ErrorCode::authentication,
                               "failed to generate HTTP obfs handshake key",
                               {}}));
            return;
        }

        const auto key = core::base64_encode(
            std::string_view(reinterpret_cast<const char *>(key_bytes.data()), key_bytes.size()));
        const auto authority = options_.host + ':' + std::to_string(options_.port);
        auto request = std::make_shared<std::string>();
        request->reserve(256 + initial_payload_.size());
        *request += "GET http://" + options_.host + "/ HTTP/1.1\r\n";
        *request += "Host: " + authority + "\r\n";
        *request += "User-Agent: curl/7.54.1\r\n";
        *request += "Upgrade: websocket\r\n";
        *request += "Connection: Upgrade\r\n";
        *request += "Sec-WebSocket-Key: " + key + "\r\n";
        *request += "Content-Length: " + std::to_string(initial_payload_.size()) + "\r\n";
        *request += "\r\n";

        auto wire = std::make_shared<std::vector<std::uint8_t>>();
        wire->reserve(request->size() + initial_payload_.size());
        wire->insert(wire->end(), request->begin(), request->end());
        wire->insert(wire->end(), initial_payload_.begin(), initial_payload_.end());
        auto self = shared_from_this();
        boost::asio::async_write(
            *socket_, boost::asio::buffer(*wire),
            [self, wire](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    self->finish(core::fail(io_error("failed to write HTTP obfs request", error)));
                    return;
                }
                self->finish({});
            });
    }

  private:
    void finish(core::Status result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::vector<std::uint8_t> initial_payload_;
    HttpObfsClientOptions options_;
    HttpObfsRequestHandler handler_;
    bool completed_ = false;
};

class HttpObfsResponse final : public std::enable_shared_from_this<HttpObfsResponse> {
  public:
    HttpObfsResponse(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                     HttpObfsResponseHandler handler)
        : socket_(std::move(socket)), handler_(std::move(handler)) {}

    void start() { read_response(); }

  private:
    void read_response() {
        auto self = shared_from_this();
        socket_->async_read_some(
            boost::asio::buffer(read_buffer_),
            [self](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    self->finish(core::fail(io_error("failed to read HTTP obfs response", error)));
                    return;
                }
                self->response_.insert(self->response_.end(), self->read_buffer_.begin(),
                                       self->read_buffer_.begin() + size);
                if (self->response_.size() > kMaxResponseHeaderSize) {
                    self->finish(
                        core::fail(protocol_error("HTTP obfs response headers are too large")));
                    return;
                }
                const std::array<std::uint8_t, 4> delimiter{'\r', '\n', '\r', '\n'};
                const auto it = std::search(self->response_.begin(), self->response_.end(),
                                            delimiter.begin(), delimiter.end());
                if (it == self->response_.end()) {
                    self->read_response();
                    return;
                }
                const auto header_end =
                    static_cast<std::size_t>(std::distance(self->response_.begin(), it)) +
                    delimiter.size();
                const std::string_view headers(
                    reinterpret_cast<const char *>(self->response_.data()), header_end);
                const auto line_end = headers.find("\r\n");
                if (line_end == std::string_view::npos ||
                    headers.substr(0, line_end).find("HTTP/1.1 101") != 0) {
                    self->finish(core::fail(
                        protocol_error("HTTP obfs server did not return 101 Switching Protocols")));
                    return;
                }
                std::vector<std::uint8_t> remainder(self->response_.begin() +
                                                        static_cast<std::ptrdiff_t>(header_end),
                                                    self->response_.end());
                self->finish(std::move(remainder));
            });
    }

    void finish(core::Result<std::vector<std::uint8_t>> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    HttpObfsResponseHandler handler_;
    std::array<std::uint8_t, 8192> read_buffer_{};
    std::vector<std::uint8_t> response_;
    bool completed_ = false;
};

} // namespace

std::vector<std::uint8_t> make_tls_client_hello(std::span<const std::uint8_t> payload,
                                                std::string_view server_name,
                                                std::span<const std::uint8_t> session_id) {
    return make_tls_client_hello_impl(payload, server_name, session_id);
}

void async_write_http_obfs_request(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                   std::vector<std::uint8_t> initial_payload,
                                   HttpObfsClientOptions options, HttpObfsRequestHandler handler) {
    std::make_shared<HttpObfsRequest>(std::move(socket), std::move(initial_payload),
                                      std::move(options), std::move(handler))
        ->start();
}

void async_read_http_obfs_response(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                   HttpObfsResponseHandler handler) {
    std::make_shared<HttpObfsResponse>(std::move(socket), std::move(handler))->start();
}

void async_write_tls_obfs_request(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                  std::vector<std::uint8_t> initial_payload,
                                  std::string server_name, TlsObfsRequestHandler handler) {
    if (server_name.empty() || has_invalid_header_value(server_name)) {
        if (handler) {
            boost::asio::post(socket->get_executor(), [handler = std::move(handler)]() mutable {
                handler(core::fail(protocol_error("invalid Shadowsocks TLS obfs server name")));
            });
        }
        return;
    }
    auto wire = make_tls_client_hello(initial_payload, server_name);
    if (wire.empty()) {
        if (handler) {
            boost::asio::post(socket->get_executor(), [handler = std::move(handler)]() mutable {
                handler(core::fail({core::ErrorCode::authentication,
                                    "failed to generate Shadowsocks TLS obfs ClientHello",
                                    {}}));
            });
        }
        return;
    }
    std::make_shared<TlsObfsWrite>(std::move(socket), std::move(wire), std::move(handler))->start();
}

void async_write_tls_obfs_records(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                  std::vector<std::uint8_t> payload,
                                  TlsObfsRequestHandler handler) {
    if (payload.empty()) {
        if (handler) {
            boost::asio::post(socket->get_executor(),
                              [handler = std::move(handler)]() mutable { handler({}); });
        }
        return;
    }
    auto wire = make_tls_records(payload);
    std::make_shared<TlsObfsWrite>(std::move(socket), std::move(wire), std::move(handler))->start();
}

void async_read_tls_obfs_response(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                  TlsObfsResponseHandler handler) {
    std::make_shared<TlsObfsRead>(std::move(socket), true, std::move(handler))->start();
}

void async_read_tls_obfs_record(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                TlsObfsResponseHandler handler) {
    std::make_shared<TlsObfsRead>(std::move(socket), false, std::move(handler))->start();
}

} // namespace clash_native::transport::shadowsocks
