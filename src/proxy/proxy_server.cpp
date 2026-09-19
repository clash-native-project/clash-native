#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/net/udp_stream.hpp>
#include <clash_native/proxy/proxy_server.hpp>
#include <clash_native/proxy/tcp_relay.hpp>
#include <clash_native/transport/http_client.hpp>

#include "outbound/outbound_utils.hpp"
#include "outbound/proxy_address.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <semaphore>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace clash_native::proxy {

namespace {

namespace http = boost::beast::http;

template <class StringView> std::string_view as_std_view(const StringView &value) {
    return {value.data(), value.size()};
}

template <class StringView> std::string copy_view(const StringView &value) {
    return std::string(value.data(), value.size());
}

constexpr std::uint8_t kSocksVersion = 0x05;
constexpr std::uint8_t kNoAuthentication = 0x00;
constexpr std::uint8_t kNoAcceptableMethods = 0xff;
constexpr std::uint8_t kConnectCommand = 0x01;
constexpr std::uint8_t kUdpAssociateCommand = 0x03;
constexpr auto kHandshakeTimeout = std::chrono::seconds(10);
constexpr std::size_t kMaxUdpPathsPerAssociation = 128;

core::Error listener_error(std::string_view operation, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, fmt::format("failed to {} proxy listener", operation),
            std::error_code(error.value(), std::system_category())};
}

std::optional<std::uint16_t> parse_port(std::string_view value) {
    if (value.empty()) {
        return std::nullopt;
    }

    unsigned int parsed = 0;
    const auto *begin = value.data();
    const auto *end = begin + value.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end || parsed == 0 || parsed > 65535) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(parsed);
}

std::optional<core::Destination> parse_http_authority(std::string_view authority) {
    std::string_view host;
    std::string_view port_text;

    if (!authority.empty() && authority.front() == '[') {
        const auto closing_bracket = authority.find(']');
        if (closing_bracket == std::string_view::npos || closing_bracket + 1 >= authority.size() ||
            authority[closing_bracket + 1] != ':') {
            return std::nullopt;
        }
        host = authority.substr(1, closing_bracket - 1);
        port_text = authority.substr(closing_bracket + 2);
    } else {
        const auto separator = authority.rfind(':');
        if (separator == std::string_view::npos || authority.find(':') != separator) {
            return std::nullopt;
        }
        host = authority.substr(0, separator);
        port_text = authority.substr(separator + 1);
    }

    const auto port = parse_port(port_text);
    if (!port || host.empty()) {
        return std::nullopt;
    }

    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(host, error);
    if (!error) {
        return core::Destination::address(address, *port);
    }
    return core::Destination::domain(std::string(host), *port);
}

struct ParsedHttpTarget {
    core::Destination destination;
    std::string authority;
    std::string origin_target;
    bool empty_path_and_query = false;
};

bool is_http_token_character(unsigned char character) {
    constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
    return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9') ||
           punctuation.find(static_cast<char>(character)) != std::string_view::npos;
}

bool is_http_token(std::string_view value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return is_http_token_character(character);
    });
}

std::string lowercase_ascii(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

bool is_http_header(std::string_view name, std::string_view expected) {
    return name.size() == expected.size() &&
           std::equal(name.begin(), name.end(), expected.begin(),
                      [](unsigned char actual, unsigned char wanted) {
                          return static_cast<unsigned char>(std::tolower(actual)) == wanted;
                      });
}

std::string_view trim_http_whitespace(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

bool collect_connection_options(const http::fields &fields,
                                std::unordered_set<std::string> &options) {
    for (const auto &field : fields) {
        if (!is_http_header(as_std_view(field.name_string()), "connection")) {
            continue;
        }
        auto value = as_std_view(field.value());
        while (true) {
            const auto comma = value.find(',');
            const auto option = trim_http_whitespace(value.substr(0, comma));
            if (!is_http_token(option)) {
                return false;
            }
            options.emplace(lowercase_ascii(option));
            if (comma == std::string_view::npos) {
                break;
            }
            value.remove_prefix(comma + 1);
        }
    }
    return true;
}

bool is_hop_by_hop_or_proxy_header(std::string_view name,
                                   const std::unordered_set<std::string> &connection_options) {
    if (connection_options.contains(lowercase_ascii(name))) {
        return true;
    }
    constexpr std::array<std::string_view, 8> names{
        "connection",          "keep-alive", "proxy-connection",  "proxy-authenticate",
        "proxy-authorization", "te",         "transfer-encoding", "upgrade"};
    return std::any_of(names.begin(), names.end(), [name](std::string_view expected) {
        return is_http_header(name, expected);
    });
}

bool is_forbidden_trailer_field(std::string_view name) {
    constexpr std::array<std::string_view, 17> names{"authorization",
                                                     "connection",
                                                     "content-encoding",
                                                     "content-length",
                                                     "content-range",
                                                     "content-type",
                                                     "host",
                                                     "keep-alive",
                                                     "proxy-authenticate",
                                                     "proxy-authorization",
                                                     "te",
                                                     "trailer",
                                                     "transfer-encoding",
                                                     "upgrade",
                                                     "www-authenticate",
                                                     "cache-control",
                                                     "expect"};
    return std::any_of(names.begin(), names.end(), [name](std::string_view expected) {
        return is_http_header(name, expected);
    });
}

bool collect_declared_trailers(const http::fields &fields,
                               const std::unordered_set<std::string> &connection_options,
                               std::unordered_set<std::string> &declared_trailers,
                               std::vector<std::string> &trailer_names) {
    for (const auto &field : fields) {
        if (!is_http_header(as_std_view(field.name_string()), "trailer")) {
            continue;
        }
        auto value = as_std_view(field.value());
        while (true) {
            const auto comma = value.find(',');
            const auto name = trim_http_whitespace(value.substr(0, comma));
            if (!is_http_token(name)) {
                return false;
            }
            const auto normalized = lowercase_ascii(name);
            if (is_forbidden_trailer_field(normalized) || connection_options.contains(normalized)) {
                return false;
            }
            if (declared_trailers.emplace(normalized).second) {
                trailer_names.push_back(normalized);
            }
            if (comma == std::string_view::npos) {
                break;
            }
            value.remove_prefix(comma + 1);
        }
    }
    return true;
}

std::optional<ParsedHttpTarget> parse_http_absolute_target(std::string_view target) {
    if (target.size() < 7 || target.find_first_of("\\\r\n\t ") != std::string_view::npos ||
        target.find('#') != std::string_view::npos) {
        return std::nullopt;
    }

    const auto scheme_end = target.find("://");
    if (scheme_end == std::string_view::npos ||
        lowercase_ascii(target.substr(0, scheme_end)) != "http") {
        return std::nullopt;
    }
    target.remove_prefix(scheme_end + 3);
    const auto target_end = target.find_first_of("/?");
    const auto authority = target.substr(0, target_end);
    if (authority.empty() || authority.find('@') != std::string_view::npos ||
        authority.find_first_of("\\\r\n\t ") != std::string_view::npos) {
        return std::nullopt;
    }

    std::string_view host;
    std::string_view port_text;
    bool explicit_port = false;
    if (authority.front() == '[') {
        const auto closing = authority.find(']');
        if (closing == std::string_view::npos || closing == 1) {
            return std::nullopt;
        }
        host = authority.substr(1, closing - 1);
        if (closing + 1 < authority.size()) {
            if (authority[closing + 1] != ':') {
                return std::nullopt;
            }
            explicit_port = true;
            port_text = authority.substr(closing + 2);
        }
    } else {
        const auto colon = authority.find(':');
        if (colon != std::string_view::npos) {
            if (authority.find(':', colon + 1) != std::string_view::npos) {
                return std::nullopt;
            }
            host = authority.substr(0, colon);
            explicit_port = true;
            port_text = authority.substr(colon + 1);
        } else {
            host = authority;
        }
    }
    if (host.empty() || host.find_first_of("[]@%") != std::string_view::npos) {
        return std::nullopt;
    }

    std::uint16_t port = 80;
    if (explicit_port) {
        const auto parsed_port = parse_port(port_text);
        if (!parsed_port) {
            return std::nullopt;
        }
        port = *parsed_port;
    }

    boost::system::error_code address_error;
    const auto address = boost::asio::ip::make_address(host, address_error);
    auto destination = address_error ? core::Destination::domain(std::string(host), port)
                                     : core::Destination::address(address, port);

    std::string origin_target;
    if (target_end == std::string_view::npos) {
        origin_target = "/";
    } else {
        const auto suffix = target.substr(target_end);
        if (suffix.front() == '?') {
            origin_target.reserve(suffix.size() + 1);
            origin_target.push_back('/');
            origin_target.append(suffix);
        } else {
            origin_target.assign(suffix);
        }
    }
    if (origin_target.empty() || origin_target.front() != '/') {
        return std::nullopt;
    }
    for (std::size_t index = 0; index < origin_target.size(); ++index) {
        if (origin_target[index] == '%' &&
            (index + 2 >= origin_target.size() ||
             !std::isxdigit(static_cast<unsigned char>(origin_target[index + 1])) ||
             !std::isxdigit(static_cast<unsigned char>(origin_target[index + 2])))) {
            return std::nullopt;
        }
    }
    return ParsedHttpTarget{std::move(destination), std::string(authority),
                            std::move(origin_target), target_end == std::string_view::npos};
}

class ProxyRequestBodyStream final : public transport::HttpBodyStream,
                                     public std::enable_shared_from_this<ProxyRequestBodyStream> {
  public:
    using Parser = http::request_parser<http::buffer_body>;
    using ByteHandler = std::function<void(std::size_t)>;

    ProxyRequestBodyStream(boost::asio::ip::tcp::socket &socket, boost::beast::flat_buffer &buffer,
                           std::shared_ptr<Parser> parser, std::size_t initial_header_count,
                           std::unordered_set<std::string> declared_trailers,
                           ByteHandler byte_handler)
        : socket_(socket), buffer_(buffer), parser_(std::move(parser)),
          executor_(socket_.get_executor()), initial_header_count_(initial_header_count),
          declared_trailers_(std::move(declared_trailers)), byte_handler_(std::move(byte_handler)) {
    }

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        const auto self = shared_from_this();
        boost::asio::dispatch(executor_, [self, buffer, handler = std::move(handler)]() mutable {
            if (self->cancelled_) {
                self->post_read(std::move(handler), boost::asio::error::operation_aborted, 0);
                return;
            }
            if (self->reading_) {
                self->post_read(std::move(handler), boost::asio::error::already_started, 0);
                return;
            }
            if (self->parser_->is_done()) {
                self->post_read(std::move(handler), boost::asio::error::eof, 0);
                return;
            }
            if (buffer.size() == 0) {
                self->post_read(std::move(handler), {}, 0);
                return;
            }

            self->reading_ = true;
            auto &body = self->parser_->get().body();
            body.data = buffer.data();
            body.size = buffer.size();
            http::async_read_some(
                self->socket_, self->buffer_, *self->parser_,
                [self, buffer, handler = std::move(handler)](const boost::system::error_code &error,
                                                             std::size_t) mutable {
                    self->reading_ = false;
                    auto &parsed_body = self->parser_->get().body();
                    const auto size = buffer.size() - parsed_body.size;
                    if (size != 0 && self->byte_handler_) {
                        self->byte_handler_(size);
                    }
                    if (error == http::error::need_buffer) {
                        if (size != 0) {
                            self->post_read(std::move(handler), {}, size);
                        } else {
                            self->retry_read(buffer, std::move(handler));
                        }
                    } else if (error) {
                        spdlog::warn("HTTP forward proxy request body parse failed: {}",
                                     error.message());
                        self->post_read(std::move(handler), error, 0);
                    } else if (size != 0) {
                        self->post_read(std::move(handler), {}, size);
                    } else if (self->parser_->is_done()) {
                        self->post_read(std::move(handler), boost::asio::error::eof, 0);
                    } else {
                        self->retry_read(buffer, std::move(handler));
                    }
                });
        });
    }

    std::vector<transport::HttpHeader> trailers() const override {
        std::vector<transport::HttpHeader> result;
        if (!parser_->is_done()) {
            return result;
        }
        const auto &fields = parser_->get().base();
        auto field = fields.begin();
        for (std::size_t index = 0; index < initial_header_count_ && field != fields.end();
             ++index, ++field) {
        }
        for (; field != fields.end(); ++field) {
            const auto name = as_std_view(field->name_string());
            const auto normalized = lowercase_ascii(name);
            if (!declared_trailers_.contains(normalized) ||
                is_forbidden_trailer_field(normalized)) {
                continue;
            }
            result.push_back({copy_view(field->name_string()), copy_view(field->value())});
        }
        return result;
    }

    void cancel() noexcept override {
        const auto self = shared_from_this();
        boost::asio::dispatch(executor_, [self] {
            if (self->cancelled_) {
                return;
            }
            self->cancelled_ = true;
            boost::system::error_code ignored;
            self->socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ignored);
        });
    }

  private:
    void retry_read(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        auto self = shared_from_this();
        boost::asio::post(executor_, [self, buffer, handler = std::move(handler)]() mutable {
            self->async_read_some(buffer, std::move(handler));
        });
    }

    void post_read(ReadHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    boost::asio::ip::tcp::socket &socket_;
    boost::beast::flat_buffer &buffer_;
    std::shared_ptr<Parser> parser_;
    boost::asio::any_io_executor executor_;
    std::size_t initial_header_count_ = 0;
    std::unordered_set<std::string> declared_trailers_;
    ByteHandler byte_handler_;
    bool reading_ = false;
    bool cancelled_ = false;
};

std::uint8_t socks_error_code(const std::optional<core::Error> &error) {
    if (!error) {
        return 0x01;
    }
    switch (error->code) {
    case core::ErrorCode::resolution:
        return 0x04;
    case core::ErrorCode::rejected:
        return 0x02;
    case core::ErrorCode::endpoint_connection:
    case core::ErrorCode::transport_io:
        return 0x05;
    default:
        return 0x01;
    }
}

} // namespace

class ProxyServer::Session : public std::enable_shared_from_this<Session> {
  public:
    using CloseHandler = std::function<void(const std::shared_ptr<Session> &)>;

    Session(ProxyServer &owner, boost::asio::ip::tcp::socket client, CloseHandler close_handler)
        : owner_(owner), client_(std::move(client)), handshake_timer_(client_.get_executor()),
          close_handler_(std::move(close_handler)) {}

    void start() {
        reset_handshake_timer();
        read_protocol_byte();
    }

    void stop() noexcept { close(); }

  private:
    struct UdpPath {
        std::string key;
        std::shared_ptr<core::DatagramHandle> handle;
        boost::asio::ip::udp::endpoint target;
        boost::asio::ip::udp::endpoint response_source;
        std::vector<std::uint8_t> receive_buffer;
    };

    enum class Protocol {
        socks5,
        http,
    };

    void reset_handshake_timer() {
        handshake_timer_.expires_after(kHandshakeTimeout);
        auto self = shared_from_this();
        handshake_timer_.async_wait([self](const boost::system::error_code &error) {
            if (!error) {
                self->close();
            }
        });
    }

    void cancel_handshake_timer() noexcept { handshake_timer_.cancel(); }

    void read_protocol_byte() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(protocol_byte_),
                                [self](const boost::system::error_code &error, std::size_t) {
                                    if (error) {
                                        self->close();
                                        return;
                                    }

                                    if (self->protocol_byte_[0] == kSocksVersion) {
                                        self->protocol_ = Protocol::socks5;
                                        self->method_header_[0] = self->protocol_byte_[0];
                                        self->read_method_count();
                                        return;
                                    }

                                    self->protocol_ = Protocol::http;
                                    auto prepared = self->http_buffer_.prepare(1);
                                    boost::asio::buffer_copy(
                                        prepared, boost::asio::buffer(self->protocol_byte_));
                                    self->http_buffer_.commit(1);
                                    self->read_http_headers();
                                });
    }

    void read_method_count() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(method_header_.data() + 1, 1),
                                [self](const boost::system::error_code &error, std::size_t) {
                                    if (error) {
                                        self->close();
                                        return;
                                    }

                                    self->methods_.resize(self->method_header_[1]);
                                    if (self->methods_.empty()) {
                                        self->send_method_response(kNoAcceptableMethods);
                                        return;
                                    }

                                    self->read_methods();
                                });
    }

    void read_methods() {
        auto self = shared_from_this();
        boost::asio::async_read(
            client_, boost::asio::buffer(methods_),
            [self](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    self->close();
                    return;
                }

                const auto method =
                    std::find(self->methods_.begin(), self->methods_.end(), kNoAuthentication);
                self->send_method_response(method == self->methods_.end() ? kNoAcceptableMethods
                                                                          : kNoAuthentication);
            });
    }

    void send_method_response(std::uint8_t method) {
        method_response_ = {kSocksVersion, method};

        auto self = shared_from_this();
        boost::asio::async_write(
            client_, boost::asio::buffer(method_response_),
            [self, method](const boost::system::error_code &error, std::size_t) {
                if (error || method != kNoAuthentication) {
                    self->close();
                    return;
                }

                self->read_request_header();
            });
    }

    void read_request_header() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(request_header_),
                                [self](const boost::system::error_code &error, std::size_t) {
                                    if (error || self->request_header_[0] != kSocksVersion) {
                                        self->close();
                                        return;
                                    }

                                    if (self->request_header_[1] != kConnectCommand &&
                                        self->request_header_[1] != kUdpAssociateCommand) {
                                        self->send_socks_reply(0x07, false);
                                        return;
                                    }

                                    switch (self->request_header_[3]) {
                                    case 0x01:
                                        self->request_body_.resize(6);
                                        self->read_request_body();
                                        break;
                                    case 0x03:
                                        self->read_domain_length();
                                        break;
                                    case 0x04:
                                        self->request_body_.resize(18);
                                        self->read_request_body();
                                        break;
                                    default:
                                        self->send_socks_reply(0x08, false);
                                        break;
                                    }
                                });
    }

    void read_domain_length() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(domain_length_),
                                [self](const boost::system::error_code &error, std::size_t) {
                                    if (error || self->domain_length_[0] == 0) {
                                        self->close();
                                        return;
                                    }

                                    self->request_body_.resize(self->domain_length_[0] + 2);
                                    self->read_request_body();
                                });
    }

    void read_request_body() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(request_body_),
                                [self](const boost::system::error_code &error, std::size_t) {
                                    if (error) {
                                        self->close();
                                        return;
                                    }

                                    self->open_socks_target();
                                });
    }

    std::uint16_t request_port() const noexcept {
        const auto size = request_body_.size();
        return static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(request_body_[size - 2]) << 8) | request_body_[size - 1]);
    }

    void open_socks_target() {
        if (request_header_[1] == kUdpAssociateCommand) {
            open_socks_udp_association();
            return;
        }

        const auto port = request_port();
        switch (request_header_[3]) {
        case 0x01: {
            boost::asio::ip::address_v4::bytes_type bytes{};
            std::copy_n(request_body_.begin(), bytes.size(), bytes.begin());
            open_target(core::Destination::address(boost::asio::ip::address_v4(bytes), port));
            return;
        }
        case 0x04: {
            boost::asio::ip::address_v6::bytes_type bytes{};
            std::copy_n(request_body_.begin(), bytes.size(), bytes.begin());
            open_target(core::Destination::address(boost::asio::ip::address_v6(bytes), port));
            return;
        }
        case 0x03: {
            const auto host_size = request_body_.size() - 2;
            open_target(core::Destination::domain(
                std::string(request_body_.begin(), request_body_.begin() + host_size), port));
            return;
        }
        default:
            send_socks_reply(0x08, false);
            return;
        }
    }

    void read_http_headers() {
        http_request_parser_ = std::make_shared<ProxyRequestBodyStream::Parser>();
        http_request_parser_->header_limit(64 * 1024);
        http_request_parser_->body_limit((std::numeric_limits<std::uint64_t>::max)());
        http_request_parser_->merge_all_trailers(true);
        auto self = shared_from_this();
        http::async_read_header(
            client_, http_buffer_, *http_request_parser_,
            [self](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    const auto status = error == http::error::header_limit ? 431 : 400;
                    self->send_http_forward_response(
                        status, status == 431 ? "Request Header Fields Too Large" : "Bad Request");
                    return;
                }

                const auto &request = self->http_request_parser_->get();
                const auto method = copy_view(request.method_string());
                if (method != "CONNECT") {
                    self->begin_http_forward();
                    return;
                }
                if (request.version() != 10 && request.version() != 11) {
                    self->send_http_forward_response(400, "Bad Request");
                    return;
                }

                const auto authority = copy_view(request.target());
                const auto destination = parse_http_authority(authority);
                if (!destination) {
                    self->send_http_forward_response(400, "Bad Request");
                    return;
                }

                const auto buffered = self->http_buffer_.size();
                self->http_initial_data_.resize(buffered);
                if (buffered != 0) {
                    boost::asio::buffer_copy(boost::asio::buffer(self->http_initial_data_),
                                             self->http_buffer_.data());
                    self->http_buffer_.consume(buffered);
                }
                self->open_target(*destination);
            });
    }

    void begin_http_forward() {
        const auto &request = http_request_parser_->get();
        if (request.version() != 11) {
            send_http_forward_response(505, "HTTP Version Not Supported");
            return;
        }

        const auto target_text = copy_view(request.target());
        if (target_text == "*" && request.method() == http::verb::options) {
            send_http_forward_response(200, "OK", "Allow: CONNECT, OPTIONS\r\n");
            return;
        }
        const auto parsed_target = parse_http_absolute_target(target_text);
        if (!parsed_target) {
            const auto scheme_end = target_text.find("://");
            if (scheme_end != std::string::npos &&
                lowercase_ascii(std::string_view(target_text).substr(0, scheme_end)) != "http") {
                send_http_forward_response(501, "Not Implemented");
            } else {
                send_http_forward_response(400, "Bad Request");
            }
            return;
        }

        std::unordered_set<std::string> connection_options;
        if (!collect_connection_options(request.base(), connection_options)) {
            send_http_forward_response(400, "Bad Request");
            return;
        }
        for (const auto &option : connection_options) {
            if (option == "content-length" || option == "host" || option == "transfer-encoding") {
                send_http_forward_response(400, "Bad Request");
                return;
            }
        }

        std::unordered_set<std::string> declared_trailers;
        std::vector<std::string> trailer_names;
        if (!collect_declared_trailers(request.base(), connection_options, declared_trailers,
                                       trailer_names)) {
            send_http_forward_response(400, "Bad Request");
            return;
        }

        bool expects_continue = false;
        for (const auto &field : request.base()) {
            if (is_http_header(as_std_view(field.name_string()), "expect")) {
                if (lowercase_ascii(trim_http_whitespace(as_std_view(field.value()))) !=
                    "100-continue") {
                    send_http_forward_response(417, "Expectation Failed");
                    return;
                }
                expects_continue = true;
            }
        }

        bool has_upgrade = false;
        for (const auto &field : request.base()) {
            if (is_http_header(as_std_view(field.name_string()), "upgrade") &&
                !field.value().empty()) {
                has_upgrade = true;
            }
        }
        if (has_upgrade || connection_options.contains("upgrade")) {
            send_http_forward_response(501, "Not Implemented");
            return;
        }

        http_forward_request_ = {};
        http_forward_request_.request.method = copy_view(request.method_string());
        http_forward_request_method_ = http_forward_request_.request.method;
        http_forward_request_.request.scheme = "http";
        http_forward_request_.request.authority = parsed_target->authority;
        http_forward_request_.request.target = parsed_target->origin_target;
        if (request.method() == http::verb::options && parsed_target->empty_path_and_query) {
            http_forward_request_.request.target = "*";
        }
        http_forward_request_.request.keep_alive = false;
        if (const auto content_length = http_request_parser_->content_length()) {
            http_forward_request_.content_length = *content_length;
        }
        if (http_request_parser_->is_done()) {
            http_forward_request_.content_length = 0;
        } else {
            const auto header_count = static_cast<std::size_t>(
                std::distance(request.base().begin(), request.base().end()));
            http_request_body_ = std::make_shared<ProxyRequestBodyStream>(
                client_, http_buffer_, http_request_parser_, header_count,
                std::move(declared_trailers),
                [this](std::size_t size) { http_forward_request_bytes_ += size; });
            http_forward_request_.body = http_request_body_;
        }

        for (const auto &field : request.base()) {
            const auto name = as_std_view(field.name_string());
            if (is_http_header(name, "host") || is_http_header(name, "content-length") ||
                is_http_header(name, "expect") || is_http_header(name, "trailer") ||
                is_hop_by_hop_or_proxy_header(name, connection_options)) {
                continue;
            }
            http_forward_request_.request.headers.push_back(
                {std::string(name), copy_view(field.value())});
        }
        http_forward_request_.request.headers.push_back({"Host", parsed_target->authority});

        if (http_forward_request_.body && !trailer_names.empty()) {
            std::string value;
            for (const auto &name : trailer_names) {
                if (!value.empty()) {
                    value.append(", ");
                }
                value.append(name);
            }
            http_forward_request_.request.headers.push_back({"Trailer", std::move(value)});
        }

        if (expects_continue) {
            auto self = shared_from_this();
            interim_http_response_ = "HTTP/1.1 100 Continue\r\n\r\n";
            boost::asio::async_write(
                client_, boost::asio::buffer(interim_http_response_),
                [self, destination = parsed_target->destination](
                    const boost::system::error_code &error, std::size_t) mutable {
                    if (error) {
                        self->close();
                        return;
                    }
                    self->open_http_forward_target(std::move(destination));
                });
            return;
        }
        open_http_forward_target(parsed_target->destination);
    }

    void open_http_forward_target(core::Destination destination) {
        http_forward_ = true;
        open_target(std::move(destination));
    }

    void open_target(core::Destination destination) {
        if (closed_.load(std::memory_order_acquire)) {
            return;
        }
        boost::system::error_code source_error;
        const auto source = client_.remote_endpoint(source_error);
        std::optional<boost::asio::ip::tcp::endpoint> source_endpoint;
        if (!source_error) {
            source_endpoint = source;
        }

        core::ConnectionMetadata metadata{core::Network::tcp,
                                          source_endpoint,
                                          std::move(destination),
                                          protocol_ == Protocol::socks5 ? "socks5" : "http",
                                          protocol_ == Protocol::socks5 ? "socks5" : "http",
                                          {},
                                          {}};
        if (owner_.connection_registry_) {
            connection_id_ = owner_.connection_registry_->add(metadata, {});
        }
        auto self = shared_from_this();
        owner_.open_stream(
            std::move(metadata), connection_id_,
            [self](core::StreamOpenResult result) { self->handle_open_result(std::move(result)); });
    }

    void open_socks_udp_association() {
        if (closed_.load(std::memory_order_acquire)) {
            return;
        }
        udp_snapshot_ = owner_.snapshot_store_->load();
        if (!udp_snapshot_) {
            send_socks_reply(0x01, false);
            return;
        }

        boost::system::error_code error;
        const auto peer = client_.remote_endpoint(error);
        if (error) {
            send_socks_reply(0x01, false);
            return;
        }
        udp_control_peer_ = peer.address();
        if (request_body_.size() >= 2) {
            expected_udp_client_port_ = request_port();
        }

        auto local = client_.local_endpoint(error);
        if (error) {
            send_socks_reply(0x01, false);
            return;
        }
        auto bind_address = local.address();
        if (bind_address.is_unspecified()) {
            bind_address = peer.address().is_v4()
                               ? boost::asio::ip::address(boost::asio::ip::address_v4::any())
                               : boost::asio::ip::address(boost::asio::ip::address_v6::any());
        }

        udp_relay_socket_ =
            std::make_shared<net::UdpStream>(owner_.runtime_.context().get_executor());
        udp_relay_socket_->open(
            bind_address.is_v4() ? boost::asio::ip::udp::v4() : boost::asio::ip::udp::v6(), error);
        if (!error) {
            udp_relay_socket_->bind({bind_address, 0}, error);
        }
        if (error) {
            udp_relay_socket_.reset();
            send_socks_reply(0x01, false);
            return;
        }

        send_socks_udp_associate_reply(udp_relay_socket_->local_endpoint(error));
        if (error) {
            close();
        }
    }

    void send_socks_udp_associate_reply(const boost::asio::ip::udp::endpoint &endpoint) {
        if (closed_.load(std::memory_order_acquire)) {
            return;
        }
        reply_[0] = kSocksVersion;
        reply_[1] = 0x00;
        reply_[2] = 0x00;
        std::size_t reply_size = 0;
        if (endpoint.address().is_v4()) {
            reply_[3] = 0x01;
            const auto bytes = endpoint.address().to_v4().to_bytes();
            std::copy(bytes.begin(), bytes.end(), reply_.begin() + 4);
            reply_[8] = static_cast<std::uint8_t>(endpoint.port() >> 8);
            reply_[9] = static_cast<std::uint8_t>(endpoint.port() & 0xff);
            reply_size = 10;
        } else {
            reply_[3] = 0x04;
            const auto bytes = endpoint.address().to_v6().to_bytes();
            std::copy(bytes.begin(), bytes.end(), reply_.begin() + 4);
            reply_[20] = static_cast<std::uint8_t>(endpoint.port() >> 8);
            reply_[21] = static_cast<std::uint8_t>(endpoint.port() & 0xff);
            reply_size = 22;
        }

        auto self = shared_from_this();
        boost::asio::async_write(client_, boost::asio::buffer(reply_.data(), reply_size),
                                 [self](const boost::system::error_code &error, std::size_t) {
                                     if (error) {
                                         self->close();
                                         return;
                                     }
                                     self->cancel_handshake_timer();
                                     self->read_udp_control();
                                     self->read_socks_udp_packet();
                                 });
    }

    void read_udp_control() {
        auto self = shared_from_this();
        client_.async_read_some(
            boost::asio::buffer(udp_control_probe_),
            [self](const boost::system::error_code &, std::size_t) { self->close(); });
    }

    void read_socks_udp_packet() {
        if (closed_.load(std::memory_order_acquire) || !udp_relay_socket_) {
            return;
        }
        auto self = shared_from_this();
        udp_relay_socket_->async_receive_from(
            boost::asio::buffer(udp_receive_buffer_),
            [self](const boost::system::error_code &error, std::size_t size,
                   boost::asio::ip::udp::endpoint sender) {
                if (error) {
                    if (error != boost::asio::error::operation_aborted) {
                        self->close();
                    }
                    return;
                }
                if (!self->accept_udp_sender(sender)) {
                    self->read_socks_udp_packet();
                    return;
                }
                self->process_socks_udp_packet(size);
                self->read_socks_udp_packet();
            });
    }

    bool accept_udp_sender(const boost::asio::ip::udp::endpoint &sender) {
        if (sender.address() != udp_control_peer_) {
            return false;
        }
        if (!udp_client_endpoint_) {
            if (expected_udp_client_port_ != 0 && sender.port() != expected_udp_client_port_) {
                return false;
            }
            udp_client_endpoint_ = sender;
            return true;
        }
        return *udp_client_endpoint_ == sender;
    }

    void process_socks_udp_packet(std::size_t size) {
        if (size < 4 || udp_receive_buffer_[0] != 0 || udp_receive_buffer_[1] != 0 ||
            udp_receive_buffer_[2] != 0) {
            return;
        }
        const auto packet = std::span<const std::uint8_t>(udp_receive_buffer_.data(), size);
        auto decoded = outbound::detail::decode_proxy_address(packet, 3);
        if (!decoded || decoded.value().destination.port() == 0) {
            return;
        }
        const auto payload_offset = 3 + decoded.value().size;
        auto payload = std::make_shared<std::vector<std::uint8_t>>(
            udp_receive_buffer_.begin() + static_cast<std::ptrdiff_t>(payload_offset),
            udp_receive_buffer_.begin() + static_cast<std::ptrdiff_t>(size));
        auto key_bytes = outbound::detail::encode_proxy_address(decoded.value().destination);
        if (!key_bytes) {
            return;
        }
        const std::string key(reinterpret_cast<const char *>(key_bytes.value().data()),
                              key_bytes.value().size());
        const auto existing = udp_paths_.find(key);
        if (existing != udp_paths_.end()) {
            send_udp_payload(existing->second, std::move(payload));
            return;
        }

        auto pending = pending_udp_packets_.find(key);
        if (pending != pending_udp_packets_.end()) {
            pending->second.push_back(std::move(payload));
            return;
        }
        if (udp_paths_.size() + pending_udp_packets_.size() >= kMaxUdpPathsPerAssociation) {
            return;
        }
        pending_udp_packets_.emplace(
            key, std::vector<std::shared_ptr<std::vector<std::uint8_t>>>{payload});

        const auto sender = *udp_client_endpoint_;
        core::ConnectionMetadata metadata{
            core::Network::udp,
            boost::asio::ip::tcp::endpoint(sender.address(), sender.port()),
            decoded.value().destination,
            "socks5",
            "socks5",
            {},
            {}};
        auto self = shared_from_this();
        owner_.open_datagram(udp_snapshot_, std::move(metadata),
                             [self, key](core::DatagramOpenResult result,
                                         boost::asio::ip::udp::endpoint target) mutable {
                                 if (self->closed_.load(std::memory_order_acquire)) {
                                     if (result.handle) {
                                         result.handle->close();
                                     }
                                     return;
                                 }
                                 auto packets = self->pending_udp_packets_.find(key);
                                 if (packets == self->pending_udp_packets_.end()) {
                                     if (result.handle) {
                                         result.handle->close();
                                     }
                                     return;
                                 }
                                 auto payloads = std::move(packets->second);
                                 self->pending_udp_packets_.erase(packets);
                                 if (!result.succeeded()) {
                                     return;
                                 }
                                 auto path = std::make_shared<UdpPath>();
                                 path->key = key;
                                 path->handle = std::shared_ptr<core::DatagramHandle>(
                                     std::move(result.handle));
                                 path->target = target;
                                 path->receive_buffer.resize(path->handle->max_datagram_size());
                                 self->udp_paths_.emplace(key, path);
                                 self->receive_udp_response(path);
                                 for (auto &packet : payloads) {
                                     self->send_udp_payload(path, std::move(packet));
                                 }
                             });
    }

    void send_udp_payload(const std::shared_ptr<UdpPath> &path,
                          std::shared_ptr<std::vector<std::uint8_t>> payload) {
        auto self = shared_from_this();
        const auto payload_buffer = boost::asio::buffer(*payload);
        path->handle->async_send_to(
            payload_buffer, path->target,
            [self, path, payload](const boost::system::error_code &error, std::size_t) {
                if (error && error != boost::asio::error::operation_aborted &&
                    !self->closed_.load(std::memory_order_acquire)) {
                    if (error == boost::asio::error::message_size) {
                        spdlog::warn(
                            "Proxy outbound UDP datagram exceeds the supported size limit");
                    }
                    const auto found = self->udp_paths_.find(path->key);
                    if (found != self->udp_paths_.end() && found->second == path) {
                        path->handle->close();
                        self->udp_paths_.erase(found);
                    }
                }
            });
    }

    void receive_udp_response(const std::shared_ptr<UdpPath> &path) {
        if (closed_.load(std::memory_order_acquire)) {
            return;
        }
        auto self = shared_from_this();
        path->handle->async_receive_from(
            boost::asio::buffer(path->receive_buffer),
            [self, path](const boost::system::error_code &error, std::size_t size,
                         boost::asio::ip::udp::endpoint source) {
                if (error) {
                    if (error != boost::asio::error::operation_aborted &&
                        !self->closed_.load(std::memory_order_acquire)) {
                        const auto found = self->udp_paths_.find(path->key);
                        if (found != self->udp_paths_.end() && found->second == path) {
                            self->udp_paths_.erase(found);
                        }
                    }
                    return;
                }
                self->send_socks_udp_response(
                    source, std::span<const std::uint8_t>(path->receive_buffer.data(), size));
                self->receive_udp_response(path);
            });
    }

    void send_socks_udp_response(boost::asio::ip::udp::endpoint source,
                                 std::span<const std::uint8_t> payload) {
        if (closed_.load(std::memory_order_acquire) || !udp_client_endpoint_) {
            return;
        }
        auto address = outbound::detail::encode_proxy_address(
            core::Destination::address(source.address(), source.port()));
        if (!address) {
            return;
        }
        auto packet = std::make_shared<std::vector<std::uint8_t>>();
        packet->reserve(3 + address.value().size() + payload.size());
        packet->insert(packet->end(), {0, 0, 0});
        packet->insert(packet->end(), address.value().begin(), address.value().end());
        packet->insert(packet->end(), payload.begin(), payload.end());
        auto self = shared_from_this();
        udp_relay_socket_->async_send_to(
            boost::asio::buffer(*packet), *udp_client_endpoint_,
            [self, packet](const boost::system::error_code &, std::size_t) {});
    }

    void handle_open_result(core::StreamOpenResult result) {
        if (closed_.load(std::memory_order_acquire)) {
            return;
        }
        cancel_handshake_timer();
        if (!result.succeeded()) {
            if (result.error) {
                spdlog::warn("Proxy outbound stream open failed ({}): {}{}",
                             core::to_string(result.error->code), result.error->context,
                             result.error->cause
                                 ? fmt::format(": {}", result.error->cause.message())
                                 : std::string{});
            }
            if (protocol_ == Protocol::socks5) {
                send_socks_reply(socks_error_code(result.error), false);
            } else if (http_forward_) {
                const auto status =
                    result.error && result.error->code == core::ErrorCode::rejected ? 403 : 502;
                send_http_forward_response(status, status == 403 ? "Forbidden" : "Bad Gateway");
            } else {
                const auto status =
                    result.error && result.error->code == core::ErrorCode::rejected ? 403 : 502;
                send_http_response(status, status == 403 ? "Forbidden" : "Bad Gateway", false);
            }
            return;
        }

        remote_ = std::move(result.handle);
        if (protocol_ == Protocol::socks5) {
            send_socks_reply(0x00, true);
        } else if (http_forward_) {
            start_http_forward_exchange();
        } else {
            send_http_response(200, "Connection Established", true);
        }
    }

    void start_http_forward_exchange() {
        http_session_ = transport::make_http1_client_session(std::move(remote_));
        if (!http_session_) {
            send_http_forward_response(502, "Bad Gateway");
            return;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(5);
        auto self = shared_from_this();
        http_exchange_id_ = http_session_->exchange_streaming(
            std::move(http_forward_request_), deadline,
            [self](core::Result<transport::HttpStreamingResponse> result) mutable {
                self->handle_http_forward_response(std::move(result));
            });
    }

    void handle_http_forward_response(core::Result<transport::HttpStreamingResponse> result) {
        if (closed_.load(std::memory_order_acquire)) {
            return;
        }
        if (!result) {
            const auto status = result.error().code == core::ErrorCode::rejected ? 403 : 502;
            send_http_forward_response(status, status == 403 ? "Forbidden" : "Bad Gateway");
            return;
        }

        http_forward_response_ = std::move(result.value());
        const auto status = http_forward_response_.response.status;
        if (status < 200 || status == 101 || status > 599) {
            send_http_forward_response(502, "Bad Gateway");
            return;
        }

        const bool has_body = !http_forward_request_method_is("HEAD") && status != 204 &&
                              status != 205 && status != 304 &&
                              static_cast<bool>(http_forward_response_.body);
        http_response_ =
            build_http_forward_response_headers(http_forward_response_.response, has_body);
        auto self = shared_from_this();
        boost::asio::async_write(
            client_, boost::asio::buffer(http_response_),
            [self, has_body](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    self->close();
                    return;
                }
                self->http_forward_response_bytes_ += size;
                if (!has_body) {
                    if (self->http_forward_response_.body) {
                        self->http_forward_response_.body->cancel();
                    }
                    self->finish_http_forward();
                    return;
                }
                self->read_http_forward_response_body();
            });
    }

    bool http_forward_request_method_is(std::string_view method) const noexcept {
        return http_forward_request_method_ == method;
    }

    std::string build_http_forward_response_headers(const transport::HttpResponse &response,
                                                    bool has_body) {
        std::unordered_set<std::string> connection_options;
        for (const auto &header : response.headers) {
            if (!is_http_header(header.name, "connection")) {
                continue;
            }
            std::string_view value(header.value);
            while (true) {
                const auto comma = value.find(',');
                const auto option = trim_http_whitespace(value.substr(0, comma));
                if (is_http_token(option)) {
                    connection_options.emplace(lowercase_ascii(option));
                }
                if (comma == std::string_view::npos) {
                    break;
                }
                value.remove_prefix(comma + 1);
            }
        }

        const auto reason = http::obsolete_reason(static_cast<http::status>(response.status));
        std::string output = fmt::format("HTTP/1.1 {} {}\r\n", response.status, copy_view(reason));
        const bool preserve_content_length =
            http_forward_request_method_is("HEAD") || response.status == 304;
        for (const auto &header : response.headers) {
            if (is_hop_by_hop_or_proxy_header(header.name, connection_options) ||
                (is_http_header(header.name, "content-length") && !preserve_content_length)) {
                continue;
            }
            output.append(header.name);
            output.append(": ");
            output.append(header.value);
            output.append("\r\n");
        }
        if (has_body) {
            output.append("Transfer-Encoding: chunked\r\n");
        }
        output.append("Connection: close\r\nProxy-Agent: clash-native\r\n\r\n");
        return output;
    }

    void read_http_forward_response_body() {
        if (closed_.load(std::memory_order_acquire) || !http_forward_response_.body) {
            finish_http_forward();
            return;
        }
        auto self = shared_from_this();
        http_forward_response_.body->async_read_some(
            boost::asio::buffer(http_forward_response_buffer_),
            [self](const boost::system::error_code &error, std::size_t size) {
                if (self->closed_.load(std::memory_order_acquire)) {
                    return;
                }
                if (error == boost::asio::error::eof) {
                    self->write_http_forward_response_trailers();
                    return;
                }
                if (error) {
                    spdlog::warn("HTTP forward proxy upstream response body read failed: {}",
                                 error.message());
                    self->close();
                    return;
                }
                if (size == 0) {
                    boost::asio::post(self->client_.get_executor(),
                                      [self] { self->read_http_forward_response_body(); });
                    return;
                }

                auto framed = std::make_shared<std::vector<std::uint8_t>>();
                const auto chunk_size = fmt::format("{:x}\r\n", size);
                framed->reserve(chunk_size.size() + size + 2);
                framed->insert(framed->end(), chunk_size.begin(), chunk_size.end());
                framed->insert(framed->end(), self->http_forward_response_buffer_.begin(),
                               self->http_forward_response_buffer_.begin() + size);
                framed->insert(framed->end(), {'\r', '\n'});
                boost::asio::async_write(
                    self->client_, boost::asio::buffer(*framed),
                    [self, framed](const boost::system::error_code &write_error,
                                   std::size_t written) {
                        if (write_error) {
                            self->close();
                            return;
                        }
                        self->http_forward_response_bytes_ += written;
                        self->read_http_forward_response_body();
                    });
            });
    }

    void write_http_forward_response_trailers() {
        std::string final_chunk = "0\r\n";
        if (http_forward_response_.body) {
            std::unordered_set<std::string> no_connection_options;
            for (const auto &trailer : http_forward_response_.body->trailers()) {
                if (!is_http_token(trailer.name) ||
                    is_hop_by_hop_or_proxy_header(trailer.name, no_connection_options) ||
                    is_http_header(trailer.name, "content-length") ||
                    is_http_header(trailer.name, "host")) {
                    continue;
                }
                final_chunk.append(trailer.name);
                final_chunk.append(": ");
                final_chunk.append(trailer.value);
                final_chunk.append("\r\n");
            }
        }
        final_chunk.append("\r\n");
        http_response_ = std::move(final_chunk);
        auto self = shared_from_this();
        boost::asio::async_write(client_, boost::asio::buffer(http_response_),
                                 [self](const boost::system::error_code &error, std::size_t size) {
                                     if (error) {
                                         self->close();
                                         return;
                                     }
                                     self->http_forward_response_bytes_ += size;
                                     self->finish_http_forward();
                                 });
    }

    void finish_http_forward() {
        if (connection_id_ && owner_.connection_registry_) {
            owner_.connection_registry_->update_stats(*connection_id_, http_forward_request_bytes_,
                                                      http_forward_response_bytes_);
        }
        close();
    }

    void send_http_forward_response(int status, std::string_view reason,
                                    std::string_view extra_headers = {}) {
        if (closed_.load(std::memory_order_acquire)) {
            return;
        }
        http_response_ =
            fmt::format("HTTP/1.1 {} {}\r\n{}Content-Length: 0\r\nConnection: close\r\n"
                        "Proxy-Agent: clash-native\r\n\r\n",
                        status, reason, extra_headers);
        auto self = shared_from_this();
        boost::asio::async_write(
            client_, boost::asio::buffer(http_response_),
            [self](const boost::system::error_code &, std::size_t) { self->close(); });
    }

    void send_socks_reply(std::uint8_t reply, bool start_relay) {
        if (closed_.load(std::memory_order_acquire)) {
            return;
        }
        std::size_t reply_size = 10;
        reply_[0] = kSocksVersion;
        reply_[1] = reply;
        reply_[2] = 0x00;
        reply_[3] = 0x01;
        std::fill(reply_.begin() + 4, reply_.end(), 0);

        if (reply == 0x00 && remote_) {
            boost::system::error_code error;
            const auto endpoint = remote_->local_endpoint(error);
            if (!error && endpoint.address().is_v6()) {
                reply_[3] = 0x04;
                const auto bytes = endpoint.address().to_v6().to_bytes();
                std::copy(bytes.begin(), bytes.end(), reply_.begin() + 4);
                reply_[20] = static_cast<std::uint8_t>(endpoint.port() >> 8);
                reply_[21] = static_cast<std::uint8_t>(endpoint.port() & 0xff);
                reply_size = 22;
            } else if (!error) {
                const auto bytes = endpoint.address().to_v4().to_bytes();
                std::copy(bytes.begin(), bytes.end(), reply_.begin() + 4);
                reply_[8] = static_cast<std::uint8_t>(endpoint.port() >> 8);
                reply_[9] = static_cast<std::uint8_t>(endpoint.port() & 0xff);
            }
        }

        auto self = shared_from_this();
        boost::asio::async_write(
            client_, boost::asio::buffer(reply_.data(), reply_size),
            [self, start_relay](const boost::system::error_code &error, std::size_t) {
                if (error || !start_relay) {
                    self->close();
                    return;
                }
                self->start_relay();
            });
    }

    void send_http_response(int status, std::string_view reason, bool start_relay) {
        if (closed_.load(std::memory_order_acquire)) {
            return;
        }
        http_response_ =
            fmt::format("HTTP/1.1 {} {}\r\nProxy-Agent: clash-native\r\n\r\n", status, reason);
        auto self = shared_from_this();
        boost::asio::async_write(
            client_, boost::asio::buffer(http_response_),
            [self, start_relay](const boost::system::error_code &error, std::size_t) {
                if (error || !start_relay) {
                    self->close();
                    return;
                }
                self->start_relay();
            });
    }

    void start_relay() {
        if (closed_.load(std::memory_order_acquire)) {
            return;
        }
        cancel_handshake_timer();
        if (!remote_) {
            close();
            return;
        }

        auto self = shared_from_this();
        relay_ = TcpRelay::start(
            std::make_unique<net::TcpStream>(std::move(client_)), std::move(remote_),
            [self](RelayStats stats) {
                if (self->connection_id_ && self->owner_.connection_registry_) {
                    self->owner_.connection_registry_->update_stats(*self->connection_id_,
                                                                    stats.left_to_right_bytes,
                                                                    stats.right_to_left_bytes);
                }
                self->close();
            },
            std::move(http_initial_data_));
    }

    void close() noexcept {
        if (closed_.exchange(true)) {
            return;
        }

        if (relay_) {
            relay_->stop();
        }
        cancel_handshake_timer();
        if (remote_) {
            remote_->close();
        }
        if (http_request_body_) {
            http_request_body_->cancel();
            http_request_body_.reset();
        }
        if (http_forward_response_.body) {
            http_forward_response_.body->cancel();
            http_forward_response_.body.reset();
        }
        if (http_session_) {
            if (http_exchange_id_ != 0) {
                http_session_->cancel(http_exchange_id_);
            }
            http_session_->stop();
            http_session_.reset();
        }
        if (udp_relay_socket_) {
            udp_relay_socket_->close();
            udp_relay_socket_.reset();
        }
        for (auto &[key, path] : udp_paths_) {
            (void)key;
            path->handle->close();
        }
        udp_paths_.clear();
        pending_udp_packets_.clear();
        udp_snapshot_.reset();

        if (connection_id_ && owner_.connection_registry_) {
            owner_.connection_registry_->remove(*connection_id_);
            connection_id_.reset();
        }

        boost::system::error_code ignored;
        client_.cancel(ignored);
        client_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
        client_.close(ignored);

        if (close_handler_) {
            close_handler_(shared_from_this());
        }
    }

    ProxyServer &owner_;
    boost::asio::ip::tcp::socket client_;
    boost::asio::steady_timer handshake_timer_;
    std::unique_ptr<core::StreamHandle> remote_;
    std::shared_ptr<TcpRelay> relay_;
    CloseHandler close_handler_;
    std::optional<observability::ConnectionRegistry::ConnectionId> connection_id_;
    std::atomic_bool closed_{false};
    Protocol protocol_ = Protocol::socks5;
    bool http_forward_ = false;

    std::array<std::uint8_t, 1> protocol_byte_{};
    std::array<std::uint8_t, 2> method_header_{};
    std::array<std::uint8_t, 2> method_response_{};
    std::vector<std::uint8_t> methods_;
    std::array<std::uint8_t, 4> request_header_{};
    std::array<std::uint8_t, 1> domain_length_{};
    std::vector<std::uint8_t> request_body_;
    std::array<std::uint8_t, 22> reply_{};
    boost::beast::flat_buffer http_buffer_;
    std::shared_ptr<ProxyRequestBodyStream::Parser> http_request_parser_;
    std::shared_ptr<ProxyRequestBodyStream> http_request_body_;
    transport::HttpStreamingRequest http_forward_request_;
    std::string http_forward_request_method_;
    std::shared_ptr<transport::HttpClientSession> http_session_;
    transport::HttpClientSession::ExchangeId http_exchange_id_ = 0;
    transport::HttpStreamingResponse http_forward_response_;
    std::array<std::uint8_t, 16 * 1024> http_forward_response_buffer_{};
    std::uint64_t http_forward_request_bytes_ = 0;
    std::uint64_t http_forward_response_bytes_ = 0;
    std::string interim_http_response_;
    std::vector<std::uint8_t> http_initial_data_;
    std::string http_response_;
    std::shared_ptr<net::UdpStream> udp_relay_socket_;
    boost::asio::ip::address udp_control_peer_ = boost::asio::ip::address_v4::any();
    std::optional<boost::asio::ip::udp::endpoint> udp_client_endpoint_;
    std::uint16_t expected_udp_client_port_ = 0;
    std::array<std::uint8_t, 1> udp_control_probe_{};
    std::array<std::uint8_t, 65507> udp_receive_buffer_{};
    runtime::RuntimeSnapshotPtr udp_snapshot_;
    std::unordered_map<std::string, std::shared_ptr<UdpPath>> udp_paths_;
    std::unordered_map<std::string, std::vector<std::shared_ptr<std::vector<std::uint8_t>>>>
        pending_udp_packets_;
};

ProxyServer::ProxyServer(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint)
    : runtime_(runtime), acceptor_(runtime.context()), endpoint_(endpoint), router_(),
      direct_outbound_(std::make_shared<outbound::DirectOutbound>(runtime)),
      reject_outbound_(std::make_shared<outbound::RejectOutbound>(runtime)),
      outbound_registry_(std::make_shared<outbound::OutboundRegistry>()),
      connection_registry_(std::make_shared<observability::ConnectionRegistry>()),
      snapshot_store_(std::make_shared<runtime::RuntimeSnapshotStore>()),
      callback_gate_(std::make_shared<std::atomic_bool>(false)) {
    if (!outbound_registry_->add_outbound("direct", direct_outbound_) ||
        !outbound_registry_->add_outbound("reject", reject_outbound_)) {
        throw std::logic_error("failed to initialize proxy built-in outbounds");
    }
}

ProxyServer::~ProxyServer() { stop(); }

void ProxyServer::set_endpoint(boost::asio::ip::tcp::endpoint endpoint) {
    if (running()) {
        throw std::logic_error("Cannot change a running proxy endpoint");
    }

    endpoint_ = endpoint;
}

void ProxyServer::set_default_action(router::RouteAction action) {
    if (running()) {
        throw std::logic_error("Cannot change routing on a running proxy");
    }
    router_.set_default_action(std::move(action));
}

void ProxyServer::add_rule(router::TrafficRule rule) {
    if (running()) {
        throw std::logic_error("Cannot change routing on a running proxy");
    }
    router_.add_rule(std::move(rule));
}

void ProxyServer::set_resolver(std::shared_ptr<dns::ResolverService> resolver) {
    if (running()) {
        throw std::logic_error("Cannot change the resolver on a running proxy");
    }
    resolver_ = std::move(resolver);
    direct_outbound_->set_resolver(resolver_);
}

void ProxyServer::set_fake_ip_store(std::shared_ptr<dns::FakeIpStore> store) {
    if (running()) {
        throw std::logic_error("Cannot change FakeIP configuration on a running proxy");
    }
    fake_ip_store_ = std::move(store);
}

void ProxyServer::set_fake_ip_filter(std::function<bool(std::string_view)> filter) {
    if (running()) {
        throw std::logic_error("Cannot change FakeIP configuration on a running proxy");
    }
    fake_ip_filter_ = std::move(filter);
}

void ProxyServer::set_outbound_registry(std::shared_ptr<outbound::OutboundRegistry> registry) {
    if (running()) {
        throw std::logic_error("Cannot change outbound registry on a running proxy");
    }
    outbound_registry_ = std::move(registry);
}

void ProxyServer::set_connection_registry(
    std::shared_ptr<observability::ConnectionRegistry> registry) {
    if (running()) {
        throw std::logic_error("Cannot change the connection registry on a running proxy");
    }
    connection_registry_ = std::move(registry);
}

core::Status ProxyServer::start() {
    if (running_.exchange(true)) {
        spdlog::debug("Proxy server start requested while already running");
        return {};
    }

    if (!outbound_registry_) {
        spdlog::error("Proxy server cannot start without an outbound registry");
        running_ = false;
        return core::fail({core::ErrorCode::configuration, "proxy outbound registry is missing"});
    }
    if (const auto result = outbound_registry_->validate(); !result) {
        spdlog::error("Proxy server outbound registry validation failed: {}",
                      result.error().context);
        running_ = false;
        return result;
    }
    const auto outbound_ids = outbound_registry_->ids();
    if (const auto result = router_.validate(outbound_ids); !result) {
        spdlog::error("Proxy server routing validation failed: {}", result.error().context);
        running_ = false;
        return result;
    }

    auto snapshot = std::make_shared<const runtime::RuntimeSnapshot>(runtime::RuntimeSnapshot{
        next_snapshot_generation_++, router_.snapshot(), outbound_registry_->snapshot(), resolver_,
        fake_ip_store_, fake_ip_filter_});
    if (const auto result = snapshot_store_->publish(snapshot); !result) {
        spdlog::error("Proxy server runtime snapshot validation failed: {}",
                      result.error().context);
        running_ = false;
        return result;
    }

    boost::system::error_code error;
    acceptor_.open(endpoint_.protocol(), error);
    if (!error) {
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true), error);
    }
    if (!error) {
        acceptor_.bind(endpoint_, error);
    }
    if (!error) {
        acceptor_.listen(boost::asio::socket_base::max_listen_connections, error);
    }

    if (error) {
        spdlog::error("Proxy server failed to open listener: {}", error.message());
        running_ = false;
        acceptor_.close();
        return core::fail(listener_error("open, bind, or listen", error));
    }

    endpoint_ = acceptor_.local_endpoint(error);
    if (error) {
        spdlog::error("Proxy server failed to query listener endpoint: {}", error.message());
        running_ = false;
        acceptor_.close();
        return core::fail(listener_error("query", error));
    }

    callback_gate_ = std::make_shared<std::atomic_bool>(true);
    spdlog::info("Proxy server listening on {}:{}", endpoint_.address().to_string(),
                 endpoint_.port());
    accept();
    return {};
}

void ProxyServer::stop() noexcept {
    if (!running_.exchange(false)) {
        spdlog::debug("Proxy server stop requested while already stopped");
        return;
    }

    spdlog::debug("Stopping proxy server");
    callback_gate_->store(false, std::memory_order_release);
    if (!runtime_.running()) {
        stop_on_owner();
        return;
    }

    std::binary_semaphore completed(0);
    boost::asio::dispatch(runtime_.context(), [this, &completed] {
        stop_on_owner();
        completed.release();
    });
    completed.acquire();
}

void ProxyServer::stop_on_owner() noexcept {
    if (resolver_) {
        for (const auto request_id : resolver_requests_) {
            resolver_->cancel(request_id);
        }
    }
    resolver_requests_.clear();

    boost::system::error_code ignored;
    acceptor_.cancel(ignored);
    acceptor_.close(ignored);

    std::vector<SessionPtr> sessions;
    {
        std::lock_guard lock(sessions_mutex_);
        sessions.reserve(sessions_.size());
        for (const auto &session : sessions_) {
            sessions.push_back(session);
        }
        sessions_.clear();
    }

    for (const auto &session : sessions) {
        session->stop();
    }
    spdlog::debug("Proxy server stopped");
}

core::Status ProxyServer::reload(runtime::RuntimeSnapshotPtr snapshot) {
    if (!snapshot) {
        return core::fail({core::ErrorCode::configuration, "proxy runtime snapshot is required"});
    }
    if (snapshot->generation == 0) {
        auto replacement = std::make_shared<runtime::RuntimeSnapshot>(*snapshot);
        replacement->generation = next_snapshot_generation_++;
        snapshot = std::move(replacement);
    }
    if (const auto result = snapshot_store_->publish(std::move(snapshot)); !result) {
        return result;
    }
    spdlog::info("Proxy server published runtime snapshot generation {}",
                 snapshot_store_->load()->generation);
    return {};
}

std::shared_ptr<runtime::RuntimeSnapshotStore>
ProxyServer::runtime_snapshot_store() const noexcept {
    return snapshot_store_;
}

bool ProxyServer::running() const noexcept { return running_.load(); }

boost::asio::ip::tcp::endpoint ProxyServer::endpoint() const noexcept { return endpoint_; }

void ProxyServer::accept() {
    if (!running()) {
        return;
    }

    auto client = std::make_shared<boost::asio::ip::tcp::socket>(runtime_.context());
    const auto gate = callback_gate_;
    acceptor_.async_accept(*client, [this, gate, client](const boost::system::error_code &error) {
        if (!gate->load(std::memory_order_acquire)) {
            return;
        }
        if (!error && running()) {
            auto session = std::make_shared<Session>(
                *this, std::move(*client), [this, gate](const SessionPtr &closed_session) {
                    if (gate->load(std::memory_order_acquire)) {
                        remove_session(closed_session);
                    }
                });
            bool accepted_session = false;
            {
                std::lock_guard lock(sessions_mutex_);
                if (running()) {
                    sessions_.insert(session);
                    accepted_session = true;
                }
            }
            if (accepted_session) {
                session->start();
            } else {
                session->stop();
            }
        }

        if (gate->load(std::memory_order_acquire)) {
            accept();
        }
    });
}

void ProxyServer::open_stream(
    core::ConnectionMetadata metadata,
    std::optional<observability::ConnectionRegistry::ConnectionId> connection_id,
    core::StreamOpenHandler handler) {
    const auto snapshot = snapshot_store_->load();
    if (!snapshot) {
        handler(core::StreamOpenResult::failed(
            {core::ErrorCode::configuration, "proxy runtime snapshot is not published"}));
        return;
    }
    if (snapshot->fake_ip_store && metadata.destination.is_address() &&
        metadata.destination.address().is_v4()) {
        if (const auto domain =
                snapshot->fake_ip_store->reverse(metadata.destination.address().to_v4())) {
            metadata.destination = core::Destination::domain(*domain, metadata.destination.port());
        }
    }
    route_stream(snapshot, std::move(metadata), {}, 0, connection_id, std::move(handler));
}

void ProxyServer::route_stream(
    runtime::RuntimeSnapshotPtr snapshot, core::ConnectionMetadata metadata,
    router::RoutingContext context, std::size_t start,
    std::optional<observability::ConnectionRegistry::ConnectionId> connection_id,
    core::StreamOpenHandler handler) {
    const auto evaluation = snapshot->router->evaluate(metadata, context, start);
    if (const auto *need = std::get_if<router::NeedMetadata>(&evaluation)) {
        if (need->need != router::MetadataNeed::destination_ip ||
            !metadata.destination.is_domain() || !snapshot->resolver) {
            handler(core::StreamOpenResult::failed(
                {core::ErrorCode::resolution, "destination IP enrichment is not configured"}));
            return;
        }

        context.destination_lookup = router::LookupState::in_progress;
        const auto resolver = snapshot->resolver;
        const auto gate = callback_gate_;
        auto self = this;
        const auto request_id = std::make_shared<dns::ResolverService::RequestId>();
        *request_id = resolver->resolve(
            {metadata.destination.domain(), dns::DnsRecordType::a, 1},
            [self, gate, resolver, request_id, snapshot, connection_id,
             metadata = std::move(metadata), context = std::move(context), start = need->rule_index,
             handler = std::move(handler)](core::Result<dns::DnsAnswer> result) mutable {
                if (!gate->load(std::memory_order_acquire)) {
                    return;
                }
                self->resolver_requests_.erase(*request_id);
                auto addresses = std::make_shared<std::vector<boost::asio::ip::address>>();
                if (result) {
                    addresses->insert(addresses->end(), result.value().addresses.begin(),
                                      result.value().addresses.end());
                }
                const auto ipv6_request_id = std::make_shared<dns::ResolverService::RequestId>();
                *ipv6_request_id = resolver->resolve(
                    {metadata.destination.domain(), dns::DnsRecordType::aaaa, 1},
                    [self, gate, snapshot, ipv6_request_id, metadata = std::move(metadata),
                     context = std::move(context), start, connection_id,
                     handler = std::move(handler),
                     addresses](core::Result<dns::DnsAnswer> ipv6_result) mutable {
                        if (!gate->load(std::memory_order_acquire)) {
                            return;
                        }
                        self->resolver_requests_.erase(*ipv6_request_id);
                        if (ipv6_result) {
                            addresses->insert(addresses->end(),
                                              ipv6_result.value().addresses.begin(),
                                              ipv6_result.value().addresses.end());
                        }
                        if (!addresses->empty()) {
                            context.destination_lookup = router::LookupState::resolved;
                            context.destination_addresses = std::move(*addresses);
                            context.destination_address = context.destination_addresses.front();
                        } else {
                            context.destination_lookup = router::LookupState::failed;
                            context.destination_addresses.clear();
                            context.destination_address.reset();
                        }
                        self->route_stream(snapshot, std::move(metadata), std::move(context), start,
                                           connection_id, std::move(handler));
                    },
                    self->runtime_.scheduler());
                self->resolver_requests_.insert(*ipv6_request_id);
            },
            runtime_.scheduler());
        resolver_requests_.insert(*request_id);
        return;
    }

    const auto *matched = std::get_if<router::Matched>(&evaluation);
    if (!matched) {
        handler(core::StreamOpenResult::failed(
            {core::ErrorCode::resolution, "routing requires destination IP enrichment"}));
        return;
    }

    switch (matched->decision.action.kind) {
    case router::RouteActionKind::direct:
        if (connection_id && connection_registry_) {
            connection_registry_->update_outbound(*connection_id, "direct");
        }
        if (metadata.destination.is_domain() && !context.destination_address &&
            snapshot->resolver) {
            const auto gate = callback_gate_;
            auto destination = metadata.destination;
            const auto domain = destination.domain();
            outbound::detail::resolve_host(
                runtime_, snapshot->resolver, domain,
                [this, gate, destination = std::move(destination), handler = std::move(handler)](
                    core::Result<outbound::detail::AddressList> result) mutable {
                    if (!gate->load(std::memory_order_acquire)) {
                        return;
                    }
                    if (!result || result.value().empty()) {
                        handler(core::StreamOpenResult::failed(
                            result ? core::Error{core::ErrorCode::resolution,
                                                 "direct destination resolved to no addresses"}
                                   : result.error()));
                        return;
                    }
                    direct_outbound_->connect_stream(
                        {std::move(destination), result.value().front()}, std::move(handler));
                });
            return;
        }
        direct_outbound_->connect_stream(
            {std::move(metadata.destination), context.destination_address}, std::move(handler));
        return;
    case router::RouteActionKind::reject:
        if (connection_id && connection_registry_) {
            connection_registry_->update_outbound(*connection_id, "reject");
        }
        reject_outbound_->connect_stream(
            {std::move(metadata.destination), context.destination_address}, std::move(handler));
        return;
    case router::RouteActionKind::named:
        if (!snapshot->outbounds) {
            handler(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration, "proxy outbound registry is missing"}));
            return;
        }
        {
            const auto selected = snapshot->outbounds->select(matched->decision.action.target);
            if (!selected) {
                handler(core::StreamOpenResult::failed(selected.error()));
                return;
            }
            if (connection_id && connection_registry_) {
                connection_registry_->update_outbound(*connection_id,
                                                      selected.value()->descriptor().id);
            }
            selected.value()->connect_stream(
                {std::move(metadata.destination), context.destination_address}, std::move(handler));
        }
        return;
    }
}

void ProxyServer::open_datagram(runtime::RuntimeSnapshotPtr snapshot,
                                core::ConnectionMetadata metadata, DatagramRouteHandler handler) {
    if (!snapshot) {
        handler(core::DatagramOpenResult::failed(
                    {core::ErrorCode::configuration, "proxy runtime snapshot is not published"}),
                {});
        return;
    }
    if (snapshot->fake_ip_store && metadata.destination.is_address() &&
        metadata.destination.address().is_v4()) {
        if (const auto domain =
                snapshot->fake_ip_store->reverse(metadata.destination.address().to_v4())) {
            metadata.destination = core::Destination::domain(*domain, metadata.destination.port());
        }
    }

    router::RoutingContext context;
    if (metadata.destination.is_address()) {
        context.destination_lookup = router::LookupState::resolved;
        context.destination_address = metadata.destination.address();
        context.destination_addresses.push_back(metadata.destination.address());
        route_datagram(std::move(snapshot), std::move(metadata), std::move(context),
                       std::move(handler));
        return;
    }

    const auto gate = callback_gate_;
    const auto domain = metadata.destination.domain();
    auto resolver = snapshot->resolver;
    outbound::detail::resolve_host(
        runtime_, std::move(resolver), domain,
        [this, gate, snapshot = std::move(snapshot), metadata = std::move(metadata),
         handler = std::move(handler)](core::Result<outbound::detail::AddressList> result) mutable {
            if (!gate->load(std::memory_order_acquire)) {
                return;
            }
            if (!result || result.value().empty()) {
                handler(core::DatagramOpenResult::failed(
                            result ? core::Error{core::ErrorCode::resolution,
                                                 "UDP destination resolved to no addresses"}
                                   : result.error()),
                        {});
                return;
            }
            router::RoutingContext context;
            context.destination_lookup = router::LookupState::resolved;
            context.destination_addresses = std::move(result.value());
            context.destination_address = context.destination_addresses.front();
            route_datagram(std::move(snapshot), std::move(metadata), std::move(context),
                           std::move(handler));
        });
}

void ProxyServer::route_datagram(runtime::RuntimeSnapshotPtr snapshot,
                                 core::ConnectionMetadata metadata, router::RoutingContext context,
                                 DatagramRouteHandler handler) {
    const auto evaluation = snapshot->router->evaluate(metadata, context);
    const auto *matched = std::get_if<router::Matched>(&evaluation);
    if (!matched) {
        handler(
            core::DatagramOpenResult::failed(
                {core::ErrorCode::resolution, "UDP routing requires destination IP enrichment"}),
            {});
        return;
    }

    const auto destination_address =
        context.destination_address
            ? context.destination_address
            : (metadata.destination.is_address()
                   ? std::optional<boost::asio::ip::address>(metadata.destination.address())
                   : std::nullopt);
    if (!destination_address) {
        handler(core::DatagramOpenResult::failed(
                    {core::ErrorCode::resolution, "UDP destination has no resolved address"}),
                {});
        return;
    }
    const boost::asio::ip::udp::endpoint target(*destination_address, metadata.destination.port());
    const core::DatagramRequest request{
        core::Destination::address(target.address(), target.port())};
    std::shared_ptr<core::Outbound> outbound;
    switch (matched->decision.action.kind) {
    case router::RouteActionKind::direct:
        outbound = direct_outbound_;
        break;
    case router::RouteActionKind::reject:
        outbound = reject_outbound_;
        break;
    case router::RouteActionKind::named:
        if (!snapshot->outbounds) {
            handler(core::DatagramOpenResult::failed(
                        {core::ErrorCode::configuration, "proxy outbound registry is missing"}),
                    target);
            return;
        }
        {
            const auto selected = snapshot->outbounds->select(matched->decision.action.target);
            if (!selected) {
                handler(core::DatagramOpenResult::failed(selected.error()), target);
                return;
            }
            outbound = selected.value();
        }
        break;
    }
    outbound->open_datagram(
        request, [handler = std::move(handler), target](core::DatagramOpenResult result) mutable {
            handler(std::move(result), target);
        });
}

void ProxyServer::remove_session(const SessionPtr &session) noexcept {
    std::lock_guard lock(sessions_mutex_);
    sessions_.erase(session);
}

} // namespace clash_native::proxy
