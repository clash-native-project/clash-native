#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/proxy/proxy_server.hpp>
#include <clash_native/proxy/tcp_relay.hpp>

#include "outbound/outbound_utils.hpp"
#include "outbound/proxy_address.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <semaphore>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clash_native::proxy {

namespace {

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
        udp_snapshot_ = owner_.snapshot_store_.load();
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
            std::make_shared<boost::asio::ip::udp::socket>(owner_.runtime_.context());
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
            boost::asio::buffer(udp_receive_buffer_), udp_packet_sender_,
            [self](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    if (error != boost::asio::error::operation_aborted) {
                        self->close();
                    }
                    return;
                }
                if (!self->accept_udp_sender(self->udp_packet_sender_)) {
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
        if (udp_relay_socket_) {
            boost::system::error_code ignored;
            udp_relay_socket_->cancel(ignored);
            udp_relay_socket_->close(ignored);
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
    std::shared_ptr<boost::asio::ip::udp::socket> udp_relay_socket_;
    boost::asio::ip::address udp_control_peer_ = boost::asio::ip::address_v4::any();
    boost::asio::ip::udp::endpoint udp_packet_sender_;
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

    auto snapshot = std::make_shared<const runtime::RuntimeSnapshot>(
        runtime::RuntimeSnapshot{next_snapshot_generation_++, router_.snapshot(),
                                 outbound_registry_->snapshot(), resolver_, fake_ip_store_});
    if (const auto result = snapshot_store_.publish(snapshot); !result) {
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
    if (const auto result = snapshot_store_.publish(std::move(snapshot)); !result) {
        return result;
    }
    spdlog::info("Proxy server published runtime snapshot generation {}",
                 snapshot_store_.load()->generation);
    return {};
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
    const auto snapshot = snapshot_store_.load();
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
