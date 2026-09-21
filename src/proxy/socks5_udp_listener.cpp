#include "socks5_udp_listener.hpp"

#include "outbound/outbound_utils.hpp"
#include "outbound/proxy_address.hpp"
#include <clash_native/proxy/proxy_server.hpp>

#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <cstddef>
#include <system_error>
#include <utility>

namespace clash_native::proxy {

namespace {

core::Error udp_listener_error(std::string_view operation, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io,
            fmt::format("failed to {} SOCKS5 UDP listener", operation),
            std::error_code(error.value(), std::system_category())};
}

} // namespace

Socks5UdpListener::Socks5UdpListener(ProxyServer &owner) : owner_(owner) {}

core::Status Socks5UdpListener::start(boost::asio::ip::udp::endpoint endpoint) {
    stop();
    socket_ = std::make_shared<net::UdpStream>(owner_.runtime_.context().get_executor());
    boost::system::error_code error;
    socket_->open(endpoint.protocol(), error);
    if (!error) {
        socket_->bind(endpoint, error);
    }
    if (error) {
        socket_->close();
        socket_.reset();
        return core::fail(udp_listener_error("open or bind", error));
    }

    endpoint_ = socket_->local_endpoint(error);
    if (error) {
        socket_->close();
        socket_.reset();
        return core::fail(udp_listener_error("query", error));
    }
    stopped_ = false;
    spdlog::info("SOCKS5 UDP listener listening on {}:{}", endpoint_->address().to_string(),
                 endpoint_->port());
    receive();
    return {};
}

void Socks5UdpListener::stop() noexcept {
    if (stopped_ && !socket_) {
        return;
    }
    stopped_ = true;
    if (socket_) {
        socket_->close();
        socket_.reset();
    }
    for (auto &[key, path] : paths_) {
        (void)key;
        path->handle->close();
    }
    paths_.clear();
    pending_.clear();
    snapshot_.reset();
    endpoint_.reset();
}

std::optional<boost::asio::ip::udp::endpoint> Socks5UdpListener::endpoint() const noexcept {
    return endpoint_;
}

void Socks5UdpListener::receive() {
    if (stopped_ || !socket_) {
        return;
    }
    auto self = shared_from_this();
    socket_->async_receive_from(boost::asio::buffer(receive_buffer_),
                                [self](const boost::system::error_code &error, std::size_t size,
                                       core::DatagramAddress source) {
                                    if (self->stopped_) {
                                        return;
                                    }
                                    if (!error && source.is_address()) {
                                        self->process(size, {source.address(), source.port()});
                                    } else if (error != boost::asio::error::operation_aborted) {
                                        spdlog::warn("SOCKS5 UDP listener receive failed: {}",
                                                     error.message());
                                    }
                                    self->receive();
                                });
}

std::string Socks5UdpListener::path_key(const boost::asio::ip::udp::endpoint &client,
                                        const core::Destination &destination) {
    const auto encoded = outbound::detail::encode_proxy_address(destination);
    if (!encoded) {
        return {};
    }
    auto key = client.address().to_string();
    key.push_back(':');
    key.append(std::to_string(client.port()));
    key.push_back('\0');
    key.append(reinterpret_cast<const char *>(encoded.value().data()), encoded.value().size());
    return key;
}

void Socks5UdpListener::process(std::size_t size, boost::asio::ip::udp::endpoint client) {
    if (size < 4 || receive_buffer_[0] != 0 || receive_buffer_[1] != 0 || receive_buffer_[2] != 0) {
        return;
    }
    const auto packet = std::span<const std::uint8_t>(receive_buffer_.data(), size);
    const auto decoded = outbound::detail::decode_proxy_address(packet, 3);
    if (!decoded || decoded.value().destination.port() == 0 || 3 + decoded.value().size > size) {
        return;
    }
    const auto key = path_key(client, decoded.value().destination);
    if (key.empty()) {
        return;
    }
    auto payload = std::make_shared<std::vector<std::uint8_t>>(
        receive_buffer_.begin() + static_cast<std::ptrdiff_t>(3 + decoded.value().size),
        receive_buffer_.begin() + static_cast<std::ptrdiff_t>(size));
    const auto existing = paths_.find(key);
    if (existing != paths_.end()) {
        send_payload(existing->second, std::move(payload));
        return;
    }
    auto pending = pending_.find(key);
    if (pending != pending_.end()) {
        pending->second.push_back(std::move(payload));
        return;
    }
    pending_.emplace(key, std::vector<std::shared_ptr<std::vector<std::uint8_t>>>{payload});
    snapshot_ = owner_.snapshot_store_->load();
    if (!snapshot_) {
        pending_.erase(key);
        return;
    }

    core::ConnectionMetadata metadata{
        core::Network::udp,
        boost::asio::ip::tcp::endpoint(client.address(), client.port()),
        decoded.value().destination,
        "socks5",
        "socks5",
        {},
        {}};
    auto self = shared_from_this();
    owner_.open_datagram(snapshot_, std::move(metadata),
                         [self, key, client](core::DatagramOpenResult result,
                                             boost::asio::ip::udp::endpoint target) mutable {
                             if (self->stopped_) {
                                 if (result.handle) {
                                     result.handle->close();
                                 }
                                 return;
                             }
                             auto pending = self->pending_.find(key);
                             if (pending == self->pending_.end()) {
                                 if (result.handle) {
                                     result.handle->close();
                                 }
                                 return;
                             }
                             auto payloads = std::move(pending->second);
                             self->pending_.erase(pending);
                             if (!result.succeeded()) {
                                 return;
                             }
                             auto path = std::make_shared<Path>();
                             path->key = key;
                             path->handle =
                                 std::shared_ptr<core::DatagramHandle>(std::move(result.handle));
                             path->target = target;
                             path->client = client;
                             path->receive_buffer.resize(path->handle->max_datagram_size());
                             self->paths_.emplace(key, path);
                             self->receive_response(path);
                             for (auto &queued : payloads) {
                                 self->send_payload(path, std::move(queued));
                             }
                         });
}

void Socks5UdpListener::send_payload(const std::shared_ptr<Path> &path,
                                     std::shared_ptr<std::vector<std::uint8_t>> payload) {
    if (stopped_) {
        return;
    }
    auto self = shared_from_this();
    path->handle->async_send_to(
        boost::asio::buffer(*payload), core::DatagramAddress::from_endpoint(path->target),
        [self, path, payload](const boost::system::error_code &error, std::size_t) {
            if (error && error != boost::asio::error::operation_aborted && !self->stopped_) {
                spdlog::warn("SOCKS5 outbound UDP send failed: {}", error.message());
                const auto found = self->paths_.find(path->key);
                if (found != self->paths_.end() && found->second == path) {
                    path->handle->close();
                    self->paths_.erase(found);
                }
            }
        });
}

void Socks5UdpListener::receive_response(const std::shared_ptr<Path> &path) {
    if (stopped_) {
        return;
    }
    auto self = shared_from_this();
    path->handle->async_receive_from(
        boost::asio::buffer(path->receive_buffer),
        [self, path](const boost::system::error_code &error, std::size_t size,
                     core::DatagramAddress source) {
            if (self->stopped_) {
                return;
            }
            if (error) {
                if (error != boost::asio::error::operation_aborted) {
                    const auto found = self->paths_.find(path->key);
                    if (found != self->paths_.end() && found->second == path) {
                        self->paths_.erase(found);
                    }
                }
                return;
            }
            self->send_response(path, source,
                                std::span<const std::uint8_t>(path->receive_buffer.data(), size));
            self->receive_response(path);
        });
}

void Socks5UdpListener::send_response(const std::shared_ptr<Path> &path,
                                      core::DatagramAddress source,
                                      std::span<const std::uint8_t> payload) {
    if (stopped_ || !socket_) {
        return;
    }
    const auto address = outbound::detail::encode_proxy_address(source.to_destination());
    if (!address) {
        return;
    }
    auto packet = std::make_shared<std::vector<std::uint8_t>>();
    packet->reserve(3 + address.value().size() + payload.size());
    packet->insert(packet->end(), {0, 0, 0});
    packet->insert(packet->end(), address.value().begin(), address.value().end());
    packet->insert(packet->end(), payload.begin(), payload.end());
    auto self = shared_from_this();
    socket_->async_send_to(
        boost::asio::buffer(*packet), core::DatagramAddress::from_endpoint(path->client),
        [self, packet](const boost::system::error_code &error, std::size_t) {
            if (error && error != boost::asio::error::operation_aborted && !self->stopped_) {
                spdlog::warn("SOCKS5 UDP response send failed: {}", error.message());
            }
        });
}

} // namespace clash_native::proxy
