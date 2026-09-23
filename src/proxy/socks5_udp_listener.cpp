#include "socks5_udp_listener.hpp"

#include "outbound/outbound_utils.hpp"
#include "outbound/proxy_address.hpp"
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/net/datagram_handle_adapter.hpp>
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
    socket_ = std::make_shared<net::UdpStream>(owner_.runtime_.serialized_executor());
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
    std::unordered_map<std::string, std::shared_ptr<Path>> paths;
    {
        std::lock_guard lock(paths_mutex_);
        paths = std::move(paths_);
        paths_.clear();
        pending_.clear();
    }
    for (auto &[key, path] : paths) {
        (void)key;
        path->handle->close();
    }
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
    std::shared_ptr<Path> existing_path;
    {
        std::lock_guard lock(paths_mutex_);
        const auto existing = paths_.find(key);
        if (existing != paths_.end()) {
            existing_path = existing->second;
        } else {
            auto pending = pending_.find(key);
            if (pending != pending_.end()) {
                pending->second.push_back(std::move(payload));
                return;
            }
            pending_.emplace(key, std::vector<std::shared_ptr<std::vector<std::uint8_t>>>{payload});
        }
    }
    if (existing_path) {
        send_payload(existing_path, std::move(payload));
        return;
    }
    snapshot_ = owner_.snapshot_store_->load();
    if (!snapshot_) {
        std::lock_guard lock(paths_mutex_);
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
                             std::vector<std::shared_ptr<std::vector<std::uint8_t>>> payloads;
                             bool has_pending = false;
                             {
                                 std::lock_guard lock(self->paths_mutex_);
                                 auto pending = self->pending_.find(key);
                                 if (pending != self->pending_.end()) {
                                     payloads = std::move(pending->second);
                                     self->pending_.erase(pending);
                                     has_pending = true;
                                 }
                             }
                             if (!has_pending) {
                                 if (result.handle) {
                                     result.handle->close();
                                 }
                                 return;
                             }
                             if (!result.succeeded()) {
                                 return;
                             }
                             auto path = std::make_shared<Path>();
                             path->key = key;
                             // The open already yields io::; no adaptation remains.
                             path->handle =
                                 std::shared_ptr<io::DatagramHandle>(std::move(result.handle));
                             path->target = target;
                             path->client = client;
                             path->receive_buffer.resize(path->handle->max_datagram_size());
                             {
                                 std::lock_guard lock(self->paths_mutex_);
                                 self->paths_.emplace(key, path);
                             }
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
    struct SendReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<Socks5UdpListener> self;
        std::shared_ptr<Path> path;
        // Keeps the payload bytes alive until the send settles.
        std::shared_ptr<std::vector<std::uint8_t>> payload;
        void set_value(std::size_t) && noexcept {}
        void set_error(std::exception_ptr error) && noexcept {
            if (self->stopped_) {
                return;
            }
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &failure) {
                spdlog::warn("SOCKS5 outbound UDP send failed: {}", failure.context);
            } catch (...) {
                spdlog::warn("SOCKS5 outbound UDP send failed");
            }
            std::shared_ptr<Path> retired;
            {
                std::lock_guard lock(self->paths_mutex_);
                const auto found = self->paths_.find(path->key);
                if (found != self->paths_.end() && found->second == path) {
                    retired = found->second;
                    self->paths_.erase(found);
                }
            }
            if (retired) {
                retired->handle->close();
            }
        }
        void set_stopped() && noexcept {}
    };
    auto self = shared_from_this();
    // NOTE: the sender must be named before the receiver moves payload away;
    // argument evaluation order is unspecified (use-after-move otherwise).
    auto sender = path->handle->async_send_to(boost::asio::buffer(*payload),
                                              io::DatagramAddress::from_endpoint(path->target));
    async::start_with_receiver(std::move(sender), SendReceiver{self, path, std::move(payload)});
}

void Socks5UdpListener::receive_response(const std::shared_ptr<Path> &path) {
    if (stopped_) {
        return;
    }
    struct ReceiveReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<Socks5UdpListener> self;
        std::shared_ptr<Path> path;
        void set_value(io::DatagramPacket packet) && noexcept {
            if (self->stopped_) {
                return;
            }
            self->send_response(
                path, packet.address,
                std::span<const std::uint8_t>(path->receive_buffer.data(), packet.size));
            self->receive_response(path);
        }
        void set_error(std::exception_ptr error) && noexcept {
            if (self->stopped_) {
                return;
            }
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &failure) {
                spdlog::warn("SOCKS5 outbound UDP receive failed: {}", failure.context);
            } catch (...) {
                spdlog::warn("SOCKS5 outbound UDP receive failed");
            }
            std::lock_guard lock(self->paths_mutex_);
            const auto found = self->paths_.find(path->key);
            if (found != self->paths_.end() && found->second == path) {
                self->paths_.erase(found);
            }
        }
        void set_stopped() && noexcept {
            // Teardown aborted the pull; stop() already retired the maps.
        }
    };
    auto self = shared_from_this();
    // NOTE: name the sender first; argument order is unspecified.
    auto sender = path->handle->async_receive_from(boost::asio::buffer(path->receive_buffer));
    async::start_with_receiver(std::move(sender), ReceiveReceiver{self, path});
}

void Socks5UdpListener::send_response(const std::shared_ptr<Path> &path, io::DatagramAddress source,
                                      std::span<const std::uint8_t> payload) {
    if (stopped_ || !socket_) {
        return;
    }
    const auto address =
        outbound::detail::encode_proxy_address(net::to_core_destination(source.to_destination()));
    if (!address) {
        return;
    }
    auto packet = std::make_shared<std::vector<std::uint8_t>>();
    packet->reserve(3 + address.value().size() + payload.size());
    packet->insert(packet->end(), {0, 0, 0});
    packet->insert(packet->end(), address.value().begin(), address.value().end());
    packet->insert(packet->end(), payload.begin(), payload.end());
    struct ResponseReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<Socks5UdpListener> self;
        std::shared_ptr<std::vector<std::uint8_t>> packet;
        void set_value(std::size_t) && noexcept {}
        void set_error(std::exception_ptr error) && noexcept {
            if (self->stopped_) {
                return;
            }
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &failure) {
                spdlog::warn("SOCKS5 UDP response send failed: {}", failure.context);
            } catch (...) {
                spdlog::warn("SOCKS5 UDP response send failed");
            }
        }
        void set_stopped() && noexcept {}
    };
    auto self = shared_from_this();
    // NOTE: name the sender first; argument order is unspecified.
    auto sender = socket_->async_send_to(boost::asio::buffer(*packet),
                                         io::DatagramAddress::from_endpoint(path->client));
    async::start_with_receiver(std::move(sender), ResponseReceiver{self, std::move(packet)});
}

} // namespace clash_native::proxy
