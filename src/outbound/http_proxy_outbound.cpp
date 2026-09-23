#include <clash_native/async/bridge.hpp>
#include <clash_native/async/callback_sender.hpp>
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
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

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

class HttpProxyConnectOperation final
    : public std::enable_shared_from_this<HttpProxyConnectOperation> {
  public:
    HttpProxyConnectOperation(runtime::AsioRuntime &runtime,
                              std::shared_ptr<dns::ResolverService> resolver,
                              HttpProxyOutboundConfig config, core::StreamRequest request,
                              core::StreamOpenHandler handler)
        : runtime_(runtime), resolver_(std::move(resolver)), config_(std::move(config)),
          request_(std::move(request)),
          socket_(std::make_shared<boost::asio::ip::tcp::socket>(runtime.serialized_executor())),
          timer_(runtime.serialized_executor()), handler_(std::move(handler)) {}

    void start() {
        const auto self = shared_from_this();
        boost::asio::dispatch(runtime_.serialized_executor(), [self] { self->start_on_owner(); });
    }

  private:
    void start_on_owner() {
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
        timer_.expires_at(deadline_);
        timer_.async_wait([self = shared_from_this()](const boost::system::error_code &error) {
            if (!error) {
                self->finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::timeout, "timed out opening HTTP proxy tunnel"}));
            }
        });

        auto self = shared_from_this();
        detail::resolve_host(runtime_, resolver_, config_.server_host,
                             [self](core::Result<detail::AddressList> result) mutable {
                                 boost::asio::dispatch(
                                     self->runtime_.serialized_executor(),
                                     [self, result = std::move(result)]() mutable {
                                         self->resolved(std::move(result));
                                     });
                             });
    }

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

    // Straight-line connect chain: TCP connect, optional TLS handshake,
    // HTTP session, CONNECT tunnel. Every terminal funnels through finish(),
    // so the spawned task always ends with a value.
    static exec::task<void>
    run(std::shared_ptr<HttpProxyConnectOperation> self,
        std::shared_ptr<std::vector<boost::asio::ip::tcp::endpoint>> endpoints) {
        using ConnectSigs = stdexec::completion_signatures<stdexec::set_value_t(bool),
                                                           stdexec::set_error_t(std::exception_ptr),
                                                           stdexec::set_stopped_t()>;
        try {
            try {
                co_await async::callback_sender<ConnectSigs>(
                    [self, endpoints](auto terminal) mutable {
                        boost::asio::async_connect(*self->socket_, *endpoints, std::move(terminal));
                    },
                    [](auto receiver, const boost::system::error_code &error, auto) {
                        if (error) {
                            stdexec::set_error(std::move(receiver),
                                               std::make_exception_ptr(core::Error{
                                                   core::ErrorCode::endpoint_connection,
                                                   "failed to connect to HTTP proxy server",
                                                   to_std_error(error)}));
                            return;
                        }
                        stdexec::set_value(std::move(receiver), true);
                    });
            } catch (const core::Error &failure) {
                self->finish(core::StreamOpenResult::failed(failure));
                co_return;
            } catch (...) {
                self->finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::endpoint_connection, "failed to connect to HTTP proxy"}));
                co_return;
            }
            if (self->completed_) {
                co_return;
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
                    self->finish(core::StreamOpenResult::failed(failure));
                    co_return;
                } catch (...) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::endpoint_connection, "HTTP proxy TLS failed"}));
                    co_return;
                }
                if (self->completed_) {
                    if (connection.stream) {
                        connection.stream->close();
                    }
                    co_return;
                }
                if (!connection.negotiated_alpn.empty() && connection.negotiated_alpn != "h2" &&
                    connection.negotiated_alpn != "http/1.1") {
                    connection.stream->close();
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::unsupported,
                         "HTTP proxy negotiated an unsupported ALPN protocol"}));
                    co_return;
                }
                alpn = std::move(connection.negotiated_alpn);
                stream = std::move(connection.stream);
            }
            if (self->completed_) {
                if (stream) {
                    stream->close();
                }
                co_return;
            }
            if (alpn == "h2") {
                self->session_ = transport::make_http2_exchange_session(std::move(stream));
            } else {
                self->session_ = transport::make_http1_exchange_session(std::move(stream));
            }
            if (!self->session_) {
                self->finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "failed to create HTTP proxy client session"}));
                co_return;
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
                self->finish(core::StreamOpenResult::failed(failure));
                co_return;
            } catch (...) {
                self->finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::endpoint_connection, "HTTP proxy tunnel failed"}));
                co_return;
            }
            if (self->completed_) {
                if (tunneled.stream) {
                    tunneled.stream->close();
                }
                co_return;
            }
            if (!tunneled.stream) {
                const auto status = tunneled.response.status;
                self->finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::rejected,
                     "HTTP proxy rejected CONNECT with status " + std::to_string(status)}));
                co_return;
            }
            auto tunnel_stream = std::make_unique<HttpProxyTunnelStream>(std::move(tunneled.stream),
                                                                         std::move(self->session_));
            self->finish(core::StreamOpenResult::opened(std::move(tunnel_stream)));
        } catch (...) {
            self->finish(core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "HTTP proxy connect failed"}));
        }
        co_return;
    }

    void resolved(core::Result<detail::AddressList> result) {
        if (completed_) {
            return;
        }
        if (!result) {
            finish(core::StreamOpenResult::failed(result.error()));
            return;
        }
        auto endpoints = std::make_shared<std::vector<boost::asio::ip::tcp::endpoint>>();
        endpoints->reserve(result.value().size());
        for (const auto &address : result.value()) {
            endpoints->emplace_back(address, config_.server_port);
        }
        // The scope only owns this chain task (merge-shaped usage);
        // teardown stays guard-driven, so no stop is ever requested.
        scope_.spawn(run(shared_from_this(), std::move(endpoints)));
    }

  public:
    // Abort for sender-driven cancellation: posted to the strand so it stays
    // ordered with finish(). Marks completion so the chain task bails at its
    // next guard; the bridge drops the late terminal.
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
                boost::system::error_code ignored;
                (void)self->timer_.cancel();
                if (self->socket_) {
                    self->socket_->cancel(ignored);
                    self->socket_->close(ignored);
                }
            });
        } catch (...) {
        }
    }

  private:
    void finish(core::StreamOpenResult result) {
        if (completed_) {
            if (result.handle) {
                result.handle->close();
            }
            return;
        }
        completed_ = true;
        (void)timer_.cancel();
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
    // Owns the single connect chain task, which always ends with a value.
    exec::async_scope scope_;
    boost::asio::steady_timer timer_;
    core::StreamOpenHandler handler_;
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
    auto &runtime = runtime_;
    auto resolver = resolver_;
    auto config = config_;
    return async::bridge_sender<core::StreamOpenResult>(
        [&runtime, resolver = std::move(resolver), config = std::move(config),
         request = std::move(request)](
            async::BridgeSender<core::StreamOpenResult>::Handler terminal) mutable {
            auto operation = std::make_shared<HttpProxyConnectOperation>(
                runtime, std::move(resolver), std::move(config), std::move(request),
                std::move(terminal));
            operation->start();
            return [operation] { operation->abort(); };
        });
}

io::AnySender<core::DatagramOpenResult> HttpProxyOutbound::open_datagram(core::DatagramRequest) {
    return io::AnySender<core::DatagramOpenResult>{
        stdexec::just(core::DatagramOpenResult::unsupported())};
}

} // namespace clash_native::outbound
