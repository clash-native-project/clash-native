#include "proxy_session.hpp"

#include <clash_native/async/timer.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <exec/asio/use_sender.hpp>
#include <exec/when_any.hpp>

#include <chrono>
#include <stdexec/execution.hpp>
#include <utility>

namespace clash_native::proxy {

ProxySession::ProxySession(ProxyServer &owner, boost::asio::ip::tcp::socket client,
                           CloseHandler close_handler)
    : owner_(owner), client_(std::move(client), owner.tls_context_),
      close_handler_(std::move(close_handler)) {}

void ProxySession::start() {
    // Handshake phase runs as one task: TLS handshake races the handshake
    // timeout (sleep_after + when_any) instead of a steady_timer.async_wait
    // leaf, then the protocol dispatch runs inline. Timeout closes the
    // session; stop closes the socket, which aborts the in-flight I/O.
    auto self = shared_from_this();
    scope_.spawn(run_handshake(self));
}

exec::task<void> ProxySession::run_handshake(std::shared_ptr<ProxySession> self) {
    const auto executor = self->client_.get_executor();
    try {
        // Tri-state race: true = handshake done, false = timeout; a
        // stopped outer scope throws out of the co_await instead.
        const bool finished = co_await async::with_timeout<bool>(
            executor, kHandshakeTimeout,
            self->client_.async_server_handshake() | stdexec::then([] { return true; }),
            [] { return false; });
        if (self->closed_.load(std::memory_order_acquire)) {
            co_return;
        }
        if (!finished) {
            spdlog::debug("Local proxy handshake timed out");
            self->close();
            co_return;
        }
    } catch (const boost::system::system_error &failure) {
        spdlog::debug("Local proxy TLS handshake failed: {}", failure.code().message());
        self->close();
        co_return;
    } catch (...) {
        self->close();
        co_return;
    }
    // TLS done (or disabled): read the protocol byte inline, then dispatch.
    // Transport failures close; the timeout above already fired only for
    // the TLS phase, while later phases are bounded by close()/relay.
    try {
        co_await (boost::asio::async_read(self->client_, boost::asio::buffer(self->protocol_byte_),
                                          exec::asio::use_sender) |
                  stdexec::then([](std::size_t) {}));
    } catch (...) {
        self->close();
        co_return;
    }
    if (self->closed_.load(std::memory_order_acquire)) {
        co_return;
    }
    if (self->protocol_byte_[0] == 0x04) {
        if (self->owner_.inbound_mode_ == ProxyInboundMode::http) {
            self->close();
            co_return;
        }
        self->protocol_ = Protocol::socks4;
        self->socks4_request_[0] = self->protocol_byte_[0];
        self->scope_.spawn(run_socks4_request(self));
        co_return;
    }
    if (self->protocol_byte_[0] == kSocksVersion) {
        if (self->owner_.inbound_mode_ == ProxyInboundMode::http) {
            self->close();
            co_return;
        }
        self->protocol_ = Protocol::socks5;
        self->method_header_[0] = self->protocol_byte_[0];
        self->scope_.spawn(run_socks5_handshake(self));
        co_return;
    }
    if (self->owner_.inbound_mode_ == ProxyInboundMode::socks) {
        self->close();
        co_return;
    }
    self->protocol_ = Protocol::http;
    auto prepared = self->http_buffer_.prepare(1);
    boost::asio::buffer_copy(prepared, boost::asio::buffer(self->protocol_byte_));
    self->http_buffer_.commit(1);
    self->read_http_headers();
}

void ProxySession::stop() noexcept { close(); }

std::optional<observability::ConnectionRegistry::ConnectionId>
ProxySession::connection_id() const noexcept {
    const auto id = connection_id_.load(std::memory_order_acquire);
    if (id == 0) {
        return std::nullopt;
    }
    return id;
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
    std::optional<observability::ConnectionRegistry::ConnectionId> connection_id;
    if (owner_.connection_registry_) {
        connection_id = owner_.connection_registry_->add(metadata, {});
        connection_id_.store(*connection_id, std::memory_order_release);
    }
    auto self = shared_from_this();
    self->scope_.spawn(run_open_target(self, std::move(metadata), std::move(connection_id)));
}

exec::task<void> ProxySession::run_open_target(
    std::shared_ptr<ProxySession> self, core::ConnectionMetadata metadata,
    std::optional<observability::ConnectionRegistry::ConnectionId> connection_id) {
    core::StreamOpenResult result;
    try {
        result = co_await self->owner_.open_stream(std::move(metadata), connection_id);
    } catch (const core::Error &failure) {
        result = core::StreamOpenResult::failed(failure);
    } catch (...) {
        result = core::StreamOpenResult::failed(
            {core::ErrorCode::endpoint_connection, "proxy outbound open failed", {}});
    }
    self->handle_open_result(std::move(result));
}

void ProxySession::handle_open_result(core::StreamOpenResult result) {
    if (closed_.load(std::memory_order_acquire)) {
        return;
    }
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
    if (!remote_) {
        close();
        return;
    }

    auto self = shared_from_this();
    relay_ = TcpRelay::start(
        client_.detach(), std::move(remote_),
        [self](RelayStats stats) {
            const auto connection_id = self->connection_id_.load(std::memory_order_acquire);
            if (connection_id != 0 && self->owner_.connection_registry_) {
                self->owner_.connection_registry_->update_stats(
                    connection_id, stats.left_to_right_bytes, stats.right_to_left_bytes);
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

    const auto connection_id = connection_id_.exchange(0, std::memory_order_acq_rel);
    if (connection_id != 0 && owner_.connection_registry_) {
        owner_.connection_registry_->remove(connection_id);
    }

    boost::system::error_code ignored;
    client_.cancel(ignored);
    client_.close();

    if (close_handler_) {
        close_handler_(shared_from_this());
    }
}

} // namespace clash_native::proxy
