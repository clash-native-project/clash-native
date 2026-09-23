#include "proxy_session.hpp"

#include <clash_native/net/stream_handle_adapter.hpp>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <utility>

namespace clash_native::proxy {

ProxySession::ProxySession(ProxyServer &owner, boost::asio::ip::tcp::socket client,
                           CloseHandler close_handler)
    : owner_(owner), client_(std::move(client), owner.tls_context_),
      handshake_timer_(client_.executor()), close_handler_(std::move(close_handler)) {}

void ProxySession::start() {
    reset_handshake_timer();
    auto self = shared_from_this();
    client_.async_server_handshake([self](const boost::system::error_code &error) {
        if (error) {
            spdlog::debug("Local proxy TLS handshake failed: {}", error.message());
            self->close();
            return;
        }
        if (self->owner_.inbound_mode_ == ProxyInboundMode::http) {
            self->protocol_ = Protocol::http;
            self->read_http_headers();
        } else {
            self->read_protocol_byte();
        }
    });
}

void ProxySession::stop() noexcept { close(); }

void ProxySession::reset_handshake_timer() {
    handshake_timer_.expires_after(kHandshakeTimeout);
    auto self = shared_from_this();
    handshake_timer_.async_wait([self](const boost::system::error_code &error) {
        if (!error) {
            self->close();
        }
    });
}

void ProxySession::cancel_handshake_timer() noexcept { handshake_timer_.cancel(); }

void ProxySession::read_protocol_byte() {
    auto self = shared_from_this();
    boost::asio::async_read(client_, boost::asio::buffer(protocol_byte_),
                            [self](const boost::system::error_code &error, std::size_t) {
                                if (error) {
                                    self->close();
                                    return;
                                }

                                if (self->protocol_byte_[0] == 0x04) {
                                    if (self->owner_.inbound_mode_ == ProxyInboundMode::http) {
                                        self->close();
                                        return;
                                    }
                                    self->protocol_ = Protocol::socks4;
                                    self->socks4_request_[0] = self->protocol_byte_[0];
                                    self->read_socks4_request();
                                    return;
                                }

                                if (self->protocol_byte_[0] == kSocksVersion) {
                                    if (self->owner_.inbound_mode_ == ProxyInboundMode::http) {
                                        self->close();
                                        return;
                                    }
                                    self->protocol_ = Protocol::socks5;
                                    self->method_header_[0] = self->protocol_byte_[0];
                                    self->scope_.spawn(self->run_socks5_handshake(self));
                                    return;
                                }

                                if (self->owner_.inbound_mode_ == ProxyInboundMode::socks) {
                                    self->close();
                                    return;
                                }

                                self->protocol_ = Protocol::http;
                                auto prepared = self->http_buffer_.prepare(1);
                                boost::asio::buffer_copy(prepared,
                                                         boost::asio::buffer(self->protocol_byte_));
                                self->http_buffer_.commit(1);
                                self->read_http_headers();
                            });
}

void ProxySession::open_target(core::Destination destination) {
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
                                      protocol_ == Protocol::socks4   ? "socks4"
                                      : protocol_ == Protocol::socks5 ? "socks5"
                                                                      : "http",
                                      protocol_ == Protocol::socks4   ? "socks4"
                                      : protocol_ == Protocol::socks5 ? "socks5"
                                                                      : "http",
                                      authenticated_user_,
                                      {}};
    if (owner_.connection_registry_) {
        connection_id_ = owner_.connection_registry_->add(metadata, {});
    }
    auto self = shared_from_this();
    owner_.open_stream(std::move(metadata), connection_id_, [self](core::StreamOpenResult result) {
        self->handle_open_result(std::move(result));
    });
}

void ProxySession::handle_open_result(core::StreamOpenResult result) {
    if (closed_.load(std::memory_order_acquire)) {
        return;
    }
    cancel_handshake_timer();
    if (!result.succeeded()) {
        if (result.error) {
            spdlog::warn("Proxy outbound stream open failed ({}): {}{}",
                         core::to_string(result.error->code), result.error->context,
                         result.error->cause ? fmt::format(": {}", result.error->cause.message())
                                             : std::string{});
        }
        if (protocol_ == Protocol::socks4) {
            send_socks4_reply(0x5b, false);
        } else if (protocol_ == Protocol::socks5) {
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
    if (protocol_ == Protocol::socks4) {
        send_socks4_reply(0x5a, true);
    } else if (protocol_ == Protocol::socks5) {
        send_socks_reply(0x00, true);
    } else if (http_forward_) {
        if (http_upgrade_forward_) {
            start_http_upgrade_exchange();
        } else {
            start_http_forward_exchange();
        }
    } else {
        send_http_response(200, "Connection Established", true);
    }
}

void ProxySession::start_relay() {
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
        client_.detach(), std::move(remote_),
        [self](RelayStats stats) {
            if (self->connection_id_ && self->owner_.connection_registry_) {
                self->owner_.connection_registry_->update_stats(
                    *self->connection_id_, stats.left_to_right_bytes, stats.right_to_left_bytes);
            }
            self->close();
        },
        std::move(http_initial_data_));
}

void ProxySession::close() noexcept {
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
        // Single-use session: stop() fails the in-flight exchange.
        http_session_->stop();
        http_session_.reset();
    }
    if (http_tunnel_session_) {
        http_tunnel_session_->stop();
        http_tunnel_session_.reset();
    }
    if (udp_relay_socket_) {
        udp_relay_socket_->close();
        udp_relay_socket_.reset();
    }
    std::unordered_map<std::string, std::shared_ptr<UdpPath>> udp_paths;
    {
        std::lock_guard lock(udp_paths_mutex_);
        udp_paths = std::move(udp_paths_);
        udp_paths_.clear();
        pending_udp_packets_.clear();
    }
    for (auto &[key, path] : udp_paths) {
        (void)key;
        path->handle->close();
    }
    udp_snapshot_.reset();

    if (connection_id_ && owner_.connection_registry_) {
        owner_.connection_registry_->remove(*connection_id_);
        connection_id_.reset();
    }

    boost::system::error_code ignored;
    client_.cancel(ignored);
    client_.close();

    if (close_handler_) {
        close_handler_(shared_from_this());
    }
}

} // namespace clash_native::proxy
