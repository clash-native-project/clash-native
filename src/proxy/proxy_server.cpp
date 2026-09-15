#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/proxy/proxy_server.hpp>
#include <clash_native/proxy/tcp_relay.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <fmt/format.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::proxy {

namespace {

constexpr std::uint8_t kSocksVersion = 0x05;
constexpr std::uint8_t kNoAuthentication = 0x00;
constexpr std::uint8_t kNoAcceptableMethods = 0xff;
constexpr std::uint8_t kConnectCommand = 0x01;
constexpr auto kHandshakeTimeout = std::chrono::seconds(10);

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

                                    if (self->protocol_byte_[0] == 'C') {
                                        self->protocol_ = Protocol::http;
                                        self->http_buffer_.sputc(
                                            static_cast<char>(self->protocol_byte_[0]));
                                        self->read_http_headers();
                                        return;
                                    }

                                    self->close();
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

                                    if (self->request_header_[1] != kConnectCommand) {
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
        auto self = shared_from_this();
        boost::asio::async_read_until(
            client_, http_buffer_, "\r\n\r\n",
            [self](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    self->close();
                    return;
                }

                const std::string request(boost::asio::buffers_begin(self->http_buffer_.data()),
                                          boost::asio::buffers_end(self->http_buffer_.data()));
                self->http_buffer_.consume(self->http_buffer_.size());

                const auto header_end = request.find("\r\n\r\n");
                const auto line_end = request.find("\r\n");
                if (header_end == std::string::npos || line_end == std::string::npos) {
                    self->send_http_response(400, "Bad Request", false);
                    return;
                }

                std::istringstream line(request.substr(0, line_end));
                std::string method;
                std::string authority;
                std::string version;
                line >> method >> authority >> version;
                if (method != "CONNECT") {
                    self->send_http_response(405, "Method Not Allowed", false);
                    return;
                }
                if (version != "HTTP/1.1" && version != "HTTP/1.0") {
                    self->send_http_response(400, "Bad Request", false);
                    return;
                }

                const auto destination = parse_http_authority(authority);
                if (!destination) {
                    self->send_http_response(400, "Bad Request", false);
                    return;
                }

                const auto body_offset = header_end + 4;
                self->http_initial_data_.assign(request.begin() + body_offset, request.end());
                self->open_target(*destination);
            });
    }

    void open_target(core::Destination destination) {
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
        auto self = shared_from_this();
        owner_.open_stream(std::move(metadata), [self](core::StreamOpenResult result) {
            self->handle_open_result(std::move(result));
        });
    }

    void handle_open_result(core::StreamOpenResult result) {
        cancel_handshake_timer();
        if (!result.succeeded()) {
            if (protocol_ == Protocol::socks5) {
                send_socks_reply(socks_error_code(result.error), false);
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
        } else {
            send_http_response(200, "Connection Established", true);
        }
    }

    void send_socks_reply(std::uint8_t reply, bool start_relay) {
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
        cancel_handshake_timer();
        if (!remote_) {
            close();
            return;
        }

        auto self = shared_from_this();
        relay_ = TcpRelay::start(
            std::make_unique<net::TcpStream>(std::move(client_)), std::move(remote_),
            [self](RelayStats) { self->close(); }, std::move(http_initial_data_));
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
    std::atomic_bool closed_{false};
    Protocol protocol_ = Protocol::socks5;

    std::array<std::uint8_t, 1> protocol_byte_{};
    std::array<std::uint8_t, 2> method_header_{};
    std::array<std::uint8_t, 2> method_response_{};
    std::vector<std::uint8_t> methods_;
    std::array<std::uint8_t, 4> request_header_{};
    std::array<std::uint8_t, 1> domain_length_{};
    std::vector<std::uint8_t> request_body_;
    std::array<std::uint8_t, 22> reply_{};
    boost::asio::streambuf http_buffer_;
    std::vector<std::uint8_t> http_initial_data_;
    std::string http_response_;
};

ProxyServer::ProxyServer(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint)
    : runtime_(runtime), acceptor_(runtime.context()), endpoint_(endpoint), router_(),
      direct_outbound_(std::make_shared<outbound::DirectOutbound>(runtime)),
      reject_outbound_(std::make_shared<outbound::RejectOutbound>(runtime)) {}

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
}

core::Status ProxyServer::start() {
    if (running_.exchange(true)) {
        return {};
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
        running_ = false;
        acceptor_.close();
        return core::fail(listener_error("open, bind, or listen", error));
    }

    endpoint_ = acceptor_.local_endpoint(error);
    if (error) {
        running_ = false;
        acceptor_.close();
        return core::fail(listener_error("query", error));
    }

    accept();
    return {};
}

void ProxyServer::stop() noexcept {
    if (!running_.exchange(false)) {
        return;
    }

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
}

bool ProxyServer::running() const noexcept { return running_.load(); }

boost::asio::ip::tcp::endpoint ProxyServer::endpoint() const noexcept { return endpoint_; }

void ProxyServer::accept() {
    if (!running()) {
        return;
    }

    auto client = std::make_shared<boost::asio::ip::tcp::socket>(runtime_.context());
    acceptor_.async_accept(*client, [this, client](const boost::system::error_code &error) {
        if (!error && running()) {
            auto session = std::make_shared<Session>(
                *this, std::move(*client),
                [this](const SessionPtr &closed_session) { remove_session(closed_session); });
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

        if (running()) {
            accept();
        }
    });
}

void ProxyServer::open_stream(core::ConnectionMetadata metadata, core::StreamOpenHandler handler) {
    route_stream(router_.snapshot(), std::move(metadata), {}, 0, std::move(handler));
}

void ProxyServer::route_stream(router::TrafficRouter::Snapshot snapshot,
                               core::ConnectionMetadata metadata, router::RoutingContext context,
                               std::size_t start, core::StreamOpenHandler handler) {
    const auto evaluation = snapshot->evaluate(metadata, context, start);
    if (const auto *need = std::get_if<router::NeedMetadata>(&evaluation)) {
        if (need->need != router::MetadataNeed::destination_ip ||
            !metadata.destination.is_domain() || !resolver_) {
            handler(core::StreamOpenResult::failed(
                {core::ErrorCode::resolution, "destination IP enrichment is not configured"}));
            return;
        }

        context.destination_lookup = router::LookupState::in_progress;
        const auto resolver = resolver_;
        auto self = this;
        resolver->resolve(
            {metadata.destination.domain(), dns::DnsRecordType::a, 1},
            [self, snapshot, metadata = std::move(metadata), context = std::move(context),
             start = need->rule_index,
             handler = std::move(handler)](core::Result<dns::DnsAnswer> result) mutable {
                if (result && !result.value().addresses.empty()) {
                    context.destination_lookup = router::LookupState::resolved;
                    context.destination_address = result.value().addresses.front();
                } else {
                    context.destination_lookup = router::LookupState::failed;
                    context.destination_address.reset();
                }
                self->route_stream(snapshot, std::move(metadata), std::move(context), start,
                                   std::move(handler));
            });
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
        direct_outbound_->connect_stream(
            {std::move(metadata.destination), context.destination_address}, std::move(handler));
        return;
    case router::RouteActionKind::reject:
        reject_outbound_->connect_stream(
            {std::move(metadata.destination), context.destination_address}, std::move(handler));
        return;
    case router::RouteActionKind::named:
        handler(core::StreamOpenResult::failed(
            {core::ErrorCode::unsupported, fmt::format("named outbound '{}' is not configured",
                                                       matched->decision.action.target)}));
        return;
    }
}

void ProxyServer::remove_session(const SessionPtr &session) noexcept {
    std::lock_guard lock(sessions_mutex_);
    sessions_.erase(session);
}

} // namespace clash_native::proxy
