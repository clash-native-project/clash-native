#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/timer.hpp>
#include <clash_native/core/base64.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/outbound/http_proxy_outbound.hpp>
#include <clash_native/transport/http_sessions.hpp>
#include <clash_native/transport/tls_client.hpp>

#include "outbound_utils.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>

#include <clash_native/async/detached.hpp>
#include <exec/asio/use_sender.hpp>

#include <stdexec/execution.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::outbound {

namespace {

constexpr auto kConnectTimeout = std::chrono::seconds(15);

std::error_code to_std_error(const boost::system::error_code &error) {
    return {error.value(), std::system_category()};
}

std::string destination_authority(const core::Destination &destination) {
    std::string authority;
    if (destination.is_address() && destination.address().is_v6()) {
        authority = '[' + destination.address().to_string() + ']';
    } else if (destination.is_address()) {
        authority = destination.address().to_string();
    } else {
        authority = destination.domain();
    }
    authority += ':' + std::to_string(destination.port());
    return authority;
}

class HttpProxyTunnelStream final : public io::StreamHandle {
  public:
    HttpProxyTunnelStream(std::unique_ptr<io::StreamHandle> stream,
                          std::shared_ptr<io::ExchangeSession> session)
        : stream_(std::move(stream)), session_(std::move(session)) {}

    // The tunnel stream is already io:: (adapted at the exchange edge),
    // so pulls drive it directly.
    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        return stream_->async_read_some(buffer);
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        return stream_->async_write(buffer);
    }

    boost::asio::any_io_executor executor() noexcept override { return stream_->executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        return stream_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        stream_->shutdown_send(error);
    }

    void close() noexcept override {
        if (stream_) {
            stream_->close();
            stream_.reset();
        }
        if (session_) {
            session_->stop();
            session_.reset();
        }
    }

    ~HttpProxyTunnelStream() override { close(); }

  private:
    std::unique_ptr<io::StreamHandle> stream_;
    std::shared_ptr<io::ExchangeSession> session_;
};

class HttpProxyConnectState final : public std::enable_shared_from_this<HttpProxyConnectState> {
  public:
    HttpProxyConnectState(runtime::AsioRuntime &runtime,
                          std::shared_ptr<dns::ResolverService> resolver,
                          HttpProxyOutboundConfig config, core::StreamRequest request,
                          core::StreamOpenHandler handler)
        : runtime_(runtime), resolver_(std::move(resolver)), config_(std::move(config)),
          request_(std::move(request)),
          socket_(std::make_shared<boost::asio::ip::tcp::socket>(runtime.serialized_executor())),
          handler_(std::move(handler)) {}

    void start() {
        const auto validation = validate_config(config_);
        if (!validation) {
            finish(core::StreamOpenResult::failed(validation.error()));
            return;
        }
        if (request_.destination.port() == 0) {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration, "HTTP proxy target port must be non-zero"}));
            return;
        }
        deadline_ = std::chrono::steady_clock::now() + kConnectTimeout;
        auto self = shared_from_this();
        // Guarded open races a 15s timeout via with_timeout; runs detached
        // (immortal heap scope): the finished task holds the last state
        // reference at completion, which would free a member scope_ before
        // __complete touches scope->__active_ (ASan #194). Teardown stays
        // guard-driven plus socket/session abort; no request_stop on a
        // detached scope.
        async::spawn_detached(run_guarded(self));
    }
    // Abort for sender-driven cancellation: posted to the strand so it stays
    // ordered with finish(). Marks completion so the chain task bails at its
    // next guard; abort closes the socket/session (no request_stop: the task
    // runs detached); the callback_sender settlement drops the late terminal.
    void abort() noexcept {
        auto self = shared_from_this();
        try {
            // Runtime outlives every operation; socket_ may already be moved
            // into the stream chain, so never touch it here.
            boost::asio::post(runtime_.serialized_executor(), [self]() {
                if (self->completed_) {
                    return;
                }
                self->completed_ = true;
                // No request_stop: detached tasks have no shared scope to
                // stop; closing the socket/session aborts the open chain, and
                // the timeout branch drops inside with_timeout.
                boost::system::error_code ignored;
                if (self->socket_) {
                    self->socket_->cancel(ignored);
                    self->socket_->close(ignored);
                }
                if (self->session_) {
                    self->session_->stop();
                }
            });
        } catch (...) {
        }
    }

  private:
    static core::Status validate_config(const HttpProxyOutboundConfig &config) {
        if (config.id.empty() || config.server_host.empty() || config.server_port == 0) {
            return core::fail({core::ErrorCode::configuration,
                               "HTTP proxy outbound ID, server, and port are required"});
        }
        if (config.username.empty() != config.password.empty()) {
            return core::fail({core::ErrorCode::configuration,
                               "HTTP proxy username and password must be provided together"});
        }
        if (config.username.find_first_of("\r\n") != std::string::npos ||
            config.password.find_first_of("\r\n") != std::string::npos) {
            return core::fail({core::ErrorCode::configuration,
                               "HTTP proxy credentials contain invalid characters"});
        }
        return {};
    }

    // Straight-line connect chain: resolve, TCP connect, optional TLS
    // handshake, HTTP session, CONNECT tunnel. Every terminal returns a
    // Result; run_guarded funnels it through finish(), so the spawned task
    // always ends with a value unless an outer stop ends it early.
    static stdexec::task<core::StreamOpenResult>
    run_work(std::shared_ptr<HttpProxyConnectState> self) {
        core::Result<detail::AddressList> resolved;
        try {
            resolved = co_await detail::resolve_host_sender(self->runtime_, self->resolver_,
                                                            self->config_.server_host);
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::resolution, "failed to resolve HTTP proxy server"});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "HTTP proxy connect cancelled"});
        }
        if (!resolved) {
            co_return core::StreamOpenResult::failed(resolved.error());
        }
        auto endpoints = std::make_shared<std::vector<boost::asio::ip::tcp::endpoint>>();
        endpoints->reserve(resolved.value().size());
        for (const auto &address : resolved.value()) {
            endpoints->emplace_back(address, self->config_.server_port);
        }
        try {
            try {
                co_await (
                    boost::asio::async_connect(*self->socket_, *endpoints, exec::asio::use_sender) |
                    stdexec::then([](const boost::asio::ip::tcp::endpoint &) {}) |
                    stdexec::let_error([](std::exception_ptr error) {
                        try {
                            std::rethrow_exception(std::move(error));
                        } catch (const boost::system::system_error &failure) {
                            return stdexec::just_error(std::make_exception_ptr(
                                core::Error{core::ErrorCode::endpoint_connection,
                                            "failed to connect to HTTP proxy server",
                                            to_std_error(failure.code())}));
                        }
                        std::rethrow_exception(std::current_exception());
                    }));
            } catch (const core::Error &failure) {
                co_return core::StreamOpenResult::failed(failure);
            } catch (...) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::endpoint_connection, "failed to connect to HTTP proxy"});
            }
            if (self->completed_) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::cancelled, "HTTP proxy connect cancelled"});
            }
            std::unique_ptr<io::StreamHandle> stream =
                std::make_unique<net::TcpStream>(std::move(*self->socket_));
            self->socket_.reset();
            std::string alpn;
            if (self->config_.tls) {
                transport::TlsClientOptions options;
                options.server_name = self->config_.server_name.empty() ? self->config_.server_host
                                                                        : self->config_.server_name;
                options.verify_peer = self->config_.verify_peer;
                options.trusted_ca_pem = self->config_.trusted_ca_pem;
                options.alpn_protocols = {"h2", "http/1.1"};
                options.deadline = self->deadline_;
                transport::TlsClientConnection connection;
                try {
                    connection = co_await transport::async_tls_client_handshake(std::move(stream),
                                                                                std::move(options));
                } catch (const core::Error &failure) {
                    co_return core::StreamOpenResult::failed(failure);
                } catch (...) {
                    co_return core::StreamOpenResult::failed(
                        {core::ErrorCode::endpoint_connection, "HTTP proxy TLS failed"});
                }
                if (self->completed_) {
                    if (connection.stream) {
                        connection.stream->close();
                    }
                    co_return core::StreamOpenResult::failed(
                        {core::ErrorCode::cancelled, "HTTP proxy connect cancelled"});
                }
                if (!connection.negotiated_alpn.empty() && connection.negotiated_alpn != "h2" &&
                    connection.negotiated_alpn != "http/1.1") {
                    connection.stream->close();
                    co_return core::StreamOpenResult::failed(
                        {core::ErrorCode::unsupported,
                         "HTTP proxy negotiated an unsupported ALPN protocol"});
                }
                alpn = std::move(connection.negotiated_alpn);
                stream = std::move(connection.stream);
            }
            if (self->completed_) {
                if (stream) {
                    stream->close();
                }
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::cancelled, "HTTP proxy connect cancelled"});
            }
            if (alpn == "h2") {
                self->session_ = transport::make_http2_exchange_session(std::move(stream));
            } else {
                self->session_ = transport::make_http1_exchange_session(std::move(stream));
            }
            if (!self->session_) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "failed to create HTTP proxy client session"});
            }
            io::StreamUpgradeRequest tunnel;
            tunnel.authority = destination_authority(self->request_.destination);
            if (!self->config_.username.empty()) {
                tunnel.headers.push_back(
                    {"proxy-authorization",
                     "Basic " + core::base64_encode(self->config_.username + ':' +
                                                    self->config_.password)});
            }
            io::StreamUpgradeResponse tunneled;
            try {
                tunneled = co_await self->session_->open_tunnel(std::move(tunnel), self->deadline_);
            } catch (const core::Error &failure) {
                co_return core::StreamOpenResult::failed(failure);
            } catch (...) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::endpoint_connection, "HTTP proxy tunnel failed"});
            }
            if (self->completed_) {
                if (tunneled.stream) {
                    tunneled.stream->close();
                }
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::cancelled, "HTTP proxy connect cancelled"});
            }
            if (!tunneled.stream) {
                const auto status = tunneled.response.status;
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::rejected,
                     "HTTP proxy rejected CONNECT with status " + std::to_string(status)});
            }
            auto tunnel_stream = std::make_unique<HttpProxyTunnelStream>(std::move(tunneled.stream),
                                                                         std::move(self->session_));
            co_return core::StreamOpenResult::opened(std::move(tunnel_stream));
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "HTTP proxy connect failed"});
        }
    }

    // Timeout race driver: the connect chain races a sleep via with_timeout
    // so a stalled peer cannot park the open. Timeout surfaces as an
    // in-band Result; machinery set_error crosses as an exception mapped to
    // a transport_io failure; outer stop cancels both branches. A named
    // function (not an immediately-invoked capturing lambda) builds the
    // task; see docs/async-pitfalls.md.
    static stdexec::task<void> run_guarded(std::shared_ptr<HttpProxyConnectState> self) {
        core::StreamOpenResult result = core::StreamOpenResult::failed(
            {core::ErrorCode::cancelled, "HTTP proxy connect stopped"});
        try {
            result = co_await async::with_timeout<core::StreamOpenResult>(
                self->runtime_.serialized_executor(), kConnectTimeout, run_work(self), [] {
                    return core::StreamOpenResult::failed(
                        {core::ErrorCode::timeout, "timed out opening HTTP proxy tunnel"});
                });
        } catch (...) {
            result = core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "HTTP proxy connect failed"});
        }
        self->finish(std::move(result));
    }

    void finish(core::StreamOpenResult result) {
        if (completed_) {
            if (result.handle) {
                result.handle->close();
            }
            return;
        }
        completed_ = true;
        if (!result.succeeded()) {
            boost::system::error_code ignored;
            if (socket_) {
                socket_->cancel(ignored);
                socket_->close(ignored);
                socket_.reset();
            }
            if (session_) {
                session_->stop();
                session_.reset();
            }
        }
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    runtime::AsioRuntime &runtime_;
    std::shared_ptr<dns::ResolverService> resolver_;
    HttpProxyOutboundConfig config_;
    core::StreamRequest request_;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::shared_ptr<io::ExchangeSession> session_;
    // No member scope: connect task runs detached (immortal heap scope) so
    // the last state reference cannot free its scope (#194).
    core::StreamOpenHandler handler_;
    // Absolute budget still feeding the TLS and tunnel sub-operations.
    std::chrono::steady_clock::time_point deadline_{};
    bool completed_ = false;
};

} // namespace

HttpProxyOutbound::HttpProxyOutbound(runtime::AsioRuntime &runtime, HttpProxyOutboundConfig config,
                                     std::shared_ptr<dns::ResolverService> resolver)
    : runtime_(runtime), config_(std::move(config)), resolver_(std::move(resolver)),
      descriptor_{config_.id, "http"} {}

core::Status HttpProxyOutbound::validate() const {
    if (config_.id.empty() || config_.server_host.empty() || config_.server_port == 0) {
        return core::fail({core::ErrorCode::configuration,
                           "HTTP proxy outbound ID, server, and port are required"});
    }
    if (config_.username.empty() != config_.password.empty()) {
        return core::fail({core::ErrorCode::configuration,
                           "HTTP proxy username and password must be provided together"});
    }
    if (config_.username.find_first_of("\r\n") != std::string::npos ||
        config_.password.find_first_of("\r\n") != std::string::npos) {
        return core::fail(
            {core::ErrorCode::configuration, "HTTP proxy credentials contain invalid characters"});
    }
    return {};
}

const core::OutboundDescriptor &HttpProxyOutbound::descriptor() const noexcept {
    return descriptor_;
}

core::OutboundCapabilities HttpProxyOutbound::capabilities() const noexcept {
    return capabilities_;
}

io::AnySender<core::StreamOpenResult>
HttpProxyOutbound::connect_stream(core::StreamRequest request) {
    using Signatures = stdexec::completion_signatures<stdexec::set_value_t(core::StreamOpenResult),
                                                      stdexec::set_error_t(std::exception_ptr),
                                                      stdexec::set_stopped_t()>;
    return io::AnySender<core::StreamOpenResult>{async::callback_sender<Signatures>(
        [&runtime = runtime_, resolver = resolver_, config = config_,
         request = std::move(request)](auto terminal) mutable -> async::CallbackAbortFn {
            auto state = std::make_shared<HttpProxyConnectState>(
                runtime, std::move(resolver), std::move(config), std::move(request),
                core::StreamOpenHandler{std::move(terminal)});
            state->start();
            return async::CallbackAbortFn{[state] { state->abort(); }};
        },
        [](stdexec::receiver auto &&receiver, core::StreamOpenResult result) {
            stdexec::set_value(std::forward<decltype(receiver)>(receiver), std::move(result));
        })};
}

io::AnySender<core::DatagramOpenResult> HttpProxyOutbound::open_datagram(core::DatagramRequest) {
    return io::AnySender<core::DatagramOpenResult>{
        stdexec::just(core::DatagramOpenResult::unsupported())};
}

} // namespace clash_native::outbound
