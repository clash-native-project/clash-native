#include "proxy_session.hpp"

#include "outbound/outbound_utils.hpp"
#include "outbound/proxy_address.hpp"
#include "socks5_udp_listener.hpp"

#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <fmt/format.h>

#include <exec/asio/use_sender.hpp>
#include <spdlog/spdlog.h>

#include <exec/task.hpp>

#include <algorithm>
#include <span>
#include <utility>

namespace clash_native::proxy {

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

// Handshake transport: exact read / full write over the client stream.
// Transport failures throw; the handshake task maps every failure to
// close(), matching the old per-step error branches.
exec::task<void> ProxySession::read_handshake_exact(std::shared_ptr<ProxySession> self,
                                                    boost::asio::mutable_buffer buffer) {
    co_await (boost::asio::async_read(self->client_, buffer, exec::asio::use_sender) |
              stdexec::then([](std::size_t) {}) | stdexec::let_error([](std::exception_ptr error) {
                  try {
                      std::rethrow_exception(std::move(error));
                  } catch (const boost::system::system_error &failure) {
                      return stdexec::just_error(std::make_exception_ptr(core::Error{
                          core::ErrorCode::transport_io, "SOCKS5 handshake read failed",
                          std::error_code(failure.code().value(), std::system_category())}));
                  }
                  std::rethrow_exception(std::current_exception());
              }));
}

exec::task<void> ProxySession::write_handshake_all(std::shared_ptr<ProxySession> self,
                                                   boost::asio::const_buffer buffer) {
    co_await (boost::asio::async_write(self->client_, buffer, exec::asio::use_sender) |
              stdexec::then([](std::size_t) {}) | stdexec::let_error([](std::exception_ptr error) {
                  try {
                      std::rethrow_exception(std::move(error));
                  } catch (const boost::system::system_error &failure) {
                      return stdexec::just_error(std::make_exception_ptr(core::Error{
                          core::ErrorCode::transport_io, "SOCKS5 handshake write failed",
                          std::error_code(failure.code().value(), std::system_category())}));
                  }
                  std::rethrow_exception(std::current_exception());
              }));
}

// Straight-line SOCKS5 handshake: method negotiation, optional username /
// password authentication, request parse. Terminals (target open, UDP
// association, reply-and-close) stay as methods; every transport failure
// closes the session, matching the old chain.
exec::task<void> ProxySession::run_socks5_handshake(std::shared_ptr<ProxySession> self) {
    try {
        co_await read_handshake_exact(self,
                                      boost::asio::buffer(self->method_header_.data() + 1, 1));
        self->methods_.resize(self->method_header_[1]);
        if (self->methods_.empty()) {
            try {
                self->method_response_ = {kSocksVersion, kNoAcceptableMethods};
                co_await write_handshake_all(self, boost::asio::buffer(self->method_response_));
            } catch (...) {
            }
            self->close();
            co_return;
        }
        co_await read_handshake_exact(self, boost::asio::buffer(self->methods_));
        const auto required_method = self->owner_.socks5_users_.empty()
                                         ? kNoAuthentication
                                         : kUsernamePasswordAuthentication;
        const auto method =
            std::find(self->methods_.begin(), self->methods_.end(), required_method);
        const auto negotiated =
            method == self->methods_.end() ? kNoAcceptableMethods : required_method;
        self->method_response_ = {kSocksVersion, negotiated};
        co_await write_handshake_all(self, boost::asio::buffer(self->method_response_));
        if (negotiated != kNoAuthentication && negotiated != kUsernamePasswordAuthentication) {
            self->close();
            co_return;
        }
        if (negotiated == kUsernamePasswordAuthentication) {
            co_await read_handshake_exact(self, boost::asio::buffer(self->auth_header_));
            if (self->auth_header_[0] != kSocksAuthVersion || self->auth_header_[1] == 0) {
                self->auth_response_ = {kSocksAuthVersion, 0x01};
                co_await write_handshake_all(self, boost::asio::buffer(self->auth_response_));
                self->close();
                co_return;
            }
            self->auth_username_.resize(self->auth_header_[1]);
            co_await read_handshake_exact(self, boost::asio::buffer(self->auth_username_));
            co_await read_handshake_exact(self, boost::asio::buffer(self->auth_password_length_));
            if (self->auth_password_length_[0] == 0) {
                self->auth_response_ = {kSocksAuthVersion, 0x01};
                co_await write_handshake_all(self, boost::asio::buffer(self->auth_response_));
                self->close();
                co_return;
            }
            self->auth_password_.resize(self->auth_password_length_[0]);
            co_await read_handshake_exact(self, boost::asio::buffer(self->auth_password_));
            const auto username =
                std::string(self->auth_username_.begin(), self->auth_username_.end());
            const auto password =
                std::string(self->auth_password_.begin(), self->auth_password_.end());
            const auto user = std::find_if(
                self->owner_.socks5_users_.begin(), self->owner_.socks5_users_.end(),
                [&username, &password](const Socks5User &candidate) {
                    return candidate.username == username && candidate.password == password;
                });
            const auto accepted = user != self->owner_.socks5_users_.end();
            if (accepted) {
                self->authenticated_user_ = user->username;
            }
            self->auth_response_ = {kSocksAuthVersion,
                                    static_cast<std::uint8_t>(accepted ? 0x00 : 0x01)};
            co_await write_handshake_all(self, boost::asio::buffer(self->auth_response_));
            if (!accepted) {
                self->close();
                co_return;
            }
        }
        co_await read_handshake_exact(self, boost::asio::buffer(self->request_header_));
        if (self->request_header_[0] != kSocksVersion) {
            self->close();
            co_return;
        }
        if (self->request_header_[1] != kConnectCommand &&
            self->request_header_[1] != kUdpAssociateCommand) {
            self->send_socks_reply(0x07, false);
            co_return;
        }
        switch (self->request_header_[3]) {
        case 0x01:
            self->request_body_.resize(6);
            break;
        case 0x03:
            co_await read_handshake_exact(self, boost::asio::buffer(self->domain_length_));
            if (self->domain_length_[0] == 0) {
                self->close();
                co_return;
            }
            self->request_body_.resize(self->domain_length_[0] + 2);
            break;
        case 0x04:
            self->request_body_.resize(18);
            break;
        default:
            self->send_socks_reply(0x08, false);
            co_return;
        }
        co_await read_handshake_exact(self, boost::asio::buffer(self->request_body_));
        self->open_socks_target();
    } catch (...) {
        self->close();
    }
}

std::uint16_t ProxySession::request_port() const noexcept {
    const auto size = request_body_.size();
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(request_body_[size - 2]) << 8) |
                                      request_body_[size - 1]);
}

void ProxySession::open_socks_target() {
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

void ProxySession::open_socks_udp_association() {
    if (closed_.load(std::memory_order_acquire)) {
        return;
    }
    udp_snapshot_ = owner_.snapshot_store_->load();
    if (!udp_snapshot_) {
        send_socks_reply(0x01, false);
        return;
    }

    if (owner_.socks5_udp_listener_) {
        const auto endpoint = owner_.socks5_udp_listener_->endpoint();
        if (!endpoint) {
            send_socks_reply(0x01, false);
            return;
        }
        send_socks_udp_associate_reply(*endpoint);
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

    udp_relay_socket_ = std::make_shared<net::UdpStream>(owner_.runtime_.serialized_executor());
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

void ProxySession::send_socks_udp_associate_reply(const boost::asio::ip::udp::endpoint &endpoint) {
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

void ProxySession::read_udp_control() {
    struct ControlReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<ProxySession> self;
        void set_value(std::optional<std::size_t> size) && noexcept {
            if (!size) {
                self->close();
                return;
            }
            self->read_udp_control();
        }
        void set_error(std::exception_ptr) && noexcept { self->close(); }
        void set_stopped() && noexcept { self->close(); }
    };
    auto sender = client_.async_read_some(boost::asio::buffer(udp_control_probe_));
    async::start_with_receiver(std::move(sender), ControlReceiver{shared_from_this()});
}

void ProxySession::read_socks_udp_packet() {
    if (closed_.load(std::memory_order_acquire) || !udp_relay_socket_) {
        return;
    }
    struct UdpPacketReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<ProxySession> self;
        void set_value(io::DatagramPacket packet) && noexcept {
            if (!packet.address.is_address() ||
                !self->accept_udp_sender(boost::asio::ip::udp::endpoint(packet.address.address(),
                                                                        packet.address.port()))) {
                self->read_socks_udp_packet();
                return;
            }
            self->process_socks_udp_packet(packet.size);
            self->read_socks_udp_packet();
        }
        void set_error(std::exception_ptr error) && noexcept {
            if (net::unpack_error(std::move(error)) != boost::asio::error::operation_aborted) {
                self->close();
            }
        }
        void set_stopped() && noexcept {}
    };
    auto self = shared_from_this();
    auto sender = udp_relay_socket_->async_receive_from(boost::asio::buffer(udp_receive_buffer_));
    async::start_with_receiver(std::move(sender), UdpPacketReceiver{self});
}

bool ProxySession::accept_udp_sender(const boost::asio::ip::udp::endpoint &sender) {
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

void ProxySession::process_socks_udp_packet(std::size_t size) {
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
    std::shared_ptr<UdpPath> existing_path;
    {
        std::lock_guard lock(udp_paths_mutex_);
        const auto existing = udp_paths_.find(key);
        if (existing != udp_paths_.end()) {
            existing_path = existing->second;
        } else {
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
        }
    }
    if (existing_path) {
        send_udp_payload(existing_path, std::move(payload));
        return;
    }

    const auto sender = *udp_client_endpoint_;
    core::ConnectionMetadata metadata{
        core::Network::udp,
        boost::asio::ip::tcp::endpoint(sender.address(), sender.port()),
        decoded.value().destination,
        "socks5",
        "socks5",
        authenticated_user_,
        {}};
    auto self = shared_from_this();
    self->scope_.spawn(run_udp_route(self, udp_snapshot_, std::move(metadata), std::move(key)));
}

exec::task<void> ProxySession::run_udp_route(std::shared_ptr<ProxySession> self,
                                             runtime::RuntimeSnapshotPtr snapshot,
                                             core::ConnectionMetadata metadata, std::string key) {
    ProxyServer::RoutedDatagram routed;
    try {
        routed = co_await self->owner_.open_datagram(std::move(snapshot), std::move(metadata));
    } catch (...) {
        // Late route failure with no pending path to attach: drop.
        co_return;
    }
    auto result = std::move(routed.result);
    const auto target = routed.target;
    if (self->closed_.load(std::memory_order_acquire)) {
        if (result.handle) {
            result.handle->close();
        }
        co_return;
    }
    std::vector<std::shared_ptr<std::vector<std::uint8_t>>> payloads;
    bool has_pending = false;
    {
        std::lock_guard lock(self->udp_paths_mutex_);
        auto packets = self->pending_udp_packets_.find(key);
        if (packets != self->pending_udp_packets_.end()) {
            payloads = std::move(packets->second);
            self->pending_udp_packets_.erase(packets);
            has_pending = true;
        }
    }
    if (!has_pending) {
        if (result.handle) {
            result.handle->close();
        }
        co_return;
    }
    if (!result.succeeded()) {
        co_return;
    }
    auto path = std::make_shared<UdpPath>();
    path->key = key;
    path->handle = std::shared_ptr<io::DatagramHandle>(std::move(result.handle));
    path->target = target;
    path->receive_buffer.resize(path->handle->max_datagram_size());
    {
        std::lock_guard lock(self->udp_paths_mutex_);
        self->udp_paths_.emplace(key, path);
    }
    self->receive_udp_response(path);
    for (auto &packet : payloads) {
        self->send_udp_payload(path, std::move(packet));
    }
}

void ProxySession::send_udp_payload(const std::shared_ptr<UdpPath> &path,
                                    std::shared_ptr<std::vector<std::uint8_t>> payload) {
    struct UdpSendReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<ProxySession> self;
        std::shared_ptr<UdpPath> path;
        std::shared_ptr<std::vector<std::uint8_t>> payload;
        void set_value(std::size_t) && noexcept {}
        void set_error(std::exception_ptr error) && noexcept {
            if (self->closed_.load(std::memory_order_acquire)) {
                return;
            }
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &failure) {
                spdlog::warn("Proxy outbound UDP send failed: {}", failure.context);
                if (failure.cause ==
                    std::error_code(boost::asio::error::message_size, std::system_category())) {
                    spdlog::warn("Proxy outbound UDP datagram exceeds the supported size limit");
                }
            } catch (...) {
                spdlog::warn("Proxy outbound UDP send failed");
            }
            std::shared_ptr<UdpPath> retired;
            {
                std::lock_guard lock(self->udp_paths_mutex_);
                const auto found = self->udp_paths_.find(path->key);
                if (found != self->udp_paths_.end() && found->second == path) {
                    retired = found->second;
                    self->udp_paths_.erase(found);
                }
            }
            if (retired) {
                retired->handle->close();
            }
        }
        void set_stopped() && noexcept {}
    };
    auto self = shared_from_this();
    // NOTE: name the sender first; argument order is unspecified.
    auto sender = path->handle->async_send_to(boost::asio::buffer(*payload),
                                              io::DatagramAddress::from_endpoint(path->target));
    async::start_with_receiver(std::move(sender), UdpSendReceiver{self, path, std::move(payload)});
}

void ProxySession::receive_udp_response(const std::shared_ptr<UdpPath> &path) {
    if (closed_.load(std::memory_order_acquire)) {
        return;
    }
    struct UdpReceiveReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<ProxySession> self;
        std::shared_ptr<UdpPath> path;
        void set_value(io::DatagramPacket packet) && noexcept {
            if (self->closed_.load(std::memory_order_acquire)) {
                return;
            }
            self->send_socks_udp_response(
                packet.address,
                std::span<const std::uint8_t>(path->receive_buffer.data(), packet.size));
            self->receive_udp_response(path);
        }
        void set_error(std::exception_ptr error) && noexcept {
            if (self->closed_.load(std::memory_order_acquire)) {
                return;
            }
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &failure) {
                spdlog::warn("Proxy outbound UDP receive failed: {}", failure.context);
            } catch (...) {
                spdlog::warn("Proxy outbound UDP receive failed");
            }
            std::lock_guard lock(self->udp_paths_mutex_);
            const auto found = self->udp_paths_.find(path->key);
            if (found != self->udp_paths_.end() && found->second == path) {
                self->udp_paths_.erase(found);
            }
        }
        void set_stopped() && noexcept {
            // Teardown aborted the pull; close() already retired the maps.
        }
    };
    auto self = shared_from_this();
    // NOTE: name the sender first; argument order is unspecified.
    auto sender = path->handle->async_receive_from(boost::asio::buffer(path->receive_buffer));
    async::start_with_receiver(std::move(sender), UdpReceiveReceiver{self, path});
}

void ProxySession::send_socks_udp_response(io::DatagramAddress source,
                                           std::span<const std::uint8_t> payload) {
    if (closed_.load(std::memory_order_acquire) || !udp_client_endpoint_) {
        return;
    }
    auto address = outbound::detail::encode_proxy_address(
        outbound::detail::to_core_destination(source.to_destination()));
    if (!address) {
        return;
    }
    auto packet = std::make_shared<std::vector<std::uint8_t>>();
    packet->reserve(3 + address.value().size() + payload.size());
    packet->insert(packet->end(), {0, 0, 0});
    packet->insert(packet->end(), address.value().begin(), address.value().end());
    packet->insert(packet->end(), payload.begin(), payload.end());
    struct UdpResponseReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<std::vector<std::uint8_t>> packet;
        void set_value(std::size_t) && noexcept {}
        void set_error(std::exception_ptr) && noexcept {}
        void set_stopped() && noexcept {}
    };
    // NOTE: name the sender first; argument order is unspecified.
    auto sender = udp_relay_socket_->async_send_to(
        boost::asio::buffer(*packet), io::DatagramAddress::from_endpoint(*udp_client_endpoint_));
    async::start_with_receiver(std::move(sender), UdpResponseReceiver{std::move(packet)});
}

void ProxySession::send_socks_reply(std::uint8_t reply, bool start_relay) {
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

} // namespace clash_native::proxy
