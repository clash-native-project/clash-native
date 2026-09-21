#include "proxy_session.hpp"

#include "outbound/outbound_utils.hpp"
#include "outbound/proxy_address.hpp"

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

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

void ProxySession::read_method_count() {
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

void ProxySession::read_methods() {
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

void ProxySession::send_method_response(std::uint8_t method) {
    method_response_ = {kSocksVersion, method};

    auto self = shared_from_this();
    boost::asio::async_write(client_, boost::asio::buffer(method_response_),
                             [self, method](const boost::system::error_code &error, std::size_t) {
                                 if (error || method != kNoAuthentication) {
                                     self->close();
                                     return;
                                 }

                                 self->read_request_header();
                             });
}

void ProxySession::read_request_header() {
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

void ProxySession::read_domain_length() {
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

void ProxySession::read_request_body() {
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

    udp_relay_socket_ = std::make_shared<net::UdpStream>(owner_.runtime_.context().get_executor());
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
    auto self = shared_from_this();
    client_.async_read_some(
        boost::asio::buffer(udp_control_probe_),
        [self](const boost::system::error_code &, std::size_t) { self->close(); });
}

void ProxySession::read_socks_udp_packet() {
    if (closed_.load(std::memory_order_acquire) || !udp_relay_socket_) {
        return;
    }
    auto self = shared_from_this();
    udp_relay_socket_->async_receive_from(
        boost::asio::buffer(udp_receive_buffer_),
        [self](const boost::system::error_code &error, std::size_t size,
               core::DatagramAddress sender) {
            if (error) {
                if (error != boost::asio::error::operation_aborted) {
                    self->close();
                }
                return;
            }
            if (!sender.is_address() || !self->accept_udp_sender(boost::asio::ip::udp::endpoint(
                                            sender.address(), sender.port()))) {
                self->read_socks_udp_packet();
                return;
            }
            self->process_socks_udp_packet(size);
            self->read_socks_udp_packet();
        });
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
    pending_udp_packets_.emplace(key,
                                 std::vector<std::shared_ptr<std::vector<std::uint8_t>>>{payload});

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
                             path->handle =
                                 std::shared_ptr<core::DatagramHandle>(std::move(result.handle));
                             path->target = target;
                             path->receive_buffer.resize(path->handle->max_datagram_size());
                             self->udp_paths_.emplace(key, path);
                             self->receive_udp_response(path);
                             for (auto &packet : payloads) {
                                 self->send_udp_payload(path, std::move(packet));
                             }
                         });
}

void ProxySession::send_udp_payload(const std::shared_ptr<UdpPath> &path,
                                    std::shared_ptr<std::vector<std::uint8_t>> payload) {
    auto self = shared_from_this();
    const auto payload_buffer = boost::asio::buffer(*payload);
    path->handle->async_send_to(
        payload_buffer, core::DatagramAddress::from_endpoint(path->target),
        [self, path, payload](const boost::system::error_code &error, std::size_t) {
            if (error && error != boost::asio::error::operation_aborted &&
                !self->closed_.load(std::memory_order_acquire)) {
                spdlog::warn("Proxy outbound UDP send failed: {}", error.message());
                if (error == boost::asio::error::message_size) {
                    spdlog::warn("Proxy outbound UDP datagram exceeds the supported size limit");
                }
                const auto found = self->udp_paths_.find(path->key);
                if (found != self->udp_paths_.end() && found->second == path) {
                    path->handle->close();
                    self->udp_paths_.erase(found);
                }
            }
        });
}

void ProxySession::receive_udp_response(const std::shared_ptr<UdpPath> &path) {
    if (closed_.load(std::memory_order_acquire)) {
        return;
    }
    auto self = shared_from_this();
    path->handle->async_receive_from(
        boost::asio::buffer(path->receive_buffer),
        [self, path](const boost::system::error_code &error, std::size_t size,
                     core::DatagramAddress source) {
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

void ProxySession::send_socks_udp_response(core::DatagramAddress source,
                                           std::span<const std::uint8_t> payload) {
    if (closed_.load(std::memory_order_acquire) || !udp_client_endpoint_) {
        return;
    }
    auto address = outbound::detail::encode_proxy_address(source.to_destination());
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
        boost::asio::buffer(*packet), core::DatagramAddress::from_endpoint(*udp_client_endpoint_),
        [self, packet](const boost::system::error_code &, std::size_t) {});
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
