#include <clash_native/core/base64.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/outbound/http_proxy_outbound.hpp>
#include <clash_native/transport/exchange_session.hpp>
#include <clash_native/transport/tls_client.hpp>

#include "outbound_utils.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

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

class HttpProxyTunnelStream final : public core::StreamHandle {
  public:
    HttpProxyTunnelStream(std::unique_ptr<core::StreamHandle> stream,
                          std::shared_ptr<transport::ExchangeSession> session)
        : stream_(std::move(stream)), session_(std::move(session)) {}

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        stream_->async_read_some(buffer, std::move(handler));
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        stream_->async_write(buffer, std::move(handler));
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
    std::unique_ptr<core::StreamHandle> stream_;
    std::shared_ptr<transport::ExchangeSession> session_;
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
        auto self = shared_from_this();
        boost::asio::async_connect(
            *socket_, *endpoints,
            [self, endpoints](const boost::system::error_code &error,
                              const boost::asio::ip::tcp::endpoint &) {
                if (self->completed_) {
                    return;
                }
                if (error) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::endpoint_connection,
                         "failed to connect to HTTP proxy server", to_std_error(error)}));
                    return;
                }
                self->connected();
            });
    }

    void connected() {
        auto stream = std::make_unique<net::TcpStream>(std::move(*socket_));
        socket_.reset();
        if (!config_.tls) {
            begin_http(std::move(stream), {});
            return;
        }

        transport::TlsClientOptions options;
        options.server_name =
            config_.server_name.empty() ? config_.server_host : config_.server_name;
        options.verify_peer = config_.verify_peer;
        options.trusted_ca_pem = config_.trusted_ca_pem;
        options.alpn_protocols = {"h2", "http/1.1"};
        options.deadline = deadline_;
        auto self = shared_from_this();
        tls_handshake_ = transport::async_tls_client_handshake(
            std::move(stream), std::move(options),
            [self](core::Result<transport::TlsClientConnection> result) mutable {
                self->tls_handshake_.reset();
                if (self->completed_) {
                    if (result && result->stream) {
                        result->stream->close();
                    }
                    return;
                }
                if (!result) {
                    self->finish(core::StreamOpenResult::failed(result.error()));
                    return;
                }
                auto connection = std::move(result.value());
                if (!connection.negotiated_alpn.empty() && connection.negotiated_alpn != "h2" &&
                    connection.negotiated_alpn != "http/1.1") {
                    connection.stream->close();
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::unsupported,
                         "HTTP proxy negotiated an unsupported ALPN protocol"}));
                    return;
                }
                self->begin_http(std::move(connection.stream), connection.negotiated_alpn);
            });
    }

    void begin_http(std::unique_ptr<core::StreamHandle> stream, std::string_view alpn) {
        if (completed_) {
            if (stream) {
                stream->close();
            }
            return;
        }
        if (alpn == "h2") {
            session_ = transport::make_http2_exchange_session(std::move(stream));
        } else {
            session_ = transport::make_http1_exchange_session(std::move(stream));
        }
        if (!session_) {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "failed to create HTTP proxy client session"}));
            return;
        }

        transport::StreamUpgradeRequest tunnel;
        tunnel.authority = destination_authority(request_.destination);
        if (!config_.username.empty()) {
            tunnel.headers.push_back(
                {"proxy-authorization",
                 "Basic " + core::base64_encode(config_.username + ':' + config_.password)});
        }
        auto self = shared_from_this();
        session_->open_tunnel(
            std::move(tunnel), deadline_,
            [self](core::Result<transport::StreamUpgradeResponse> result) mutable {
                if (self->completed_) {
                    if (result && result->stream) {
                        result->stream->close();
                    }
                    return;
                }
                if (!result) {
                    self->finish(core::StreamOpenResult::failed(result.error()));
                    return;
                }
                if (!result->stream) {
                    const auto status = result->response.status;
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::rejected,
                         "HTTP proxy rejected CONNECT with status " + std::to_string(status)}));
                    return;
                }
                auto tunnel_stream = std::make_unique<HttpProxyTunnelStream>(
                    std::move(result->stream), std::move(self->session_));
                self->finish(core::StreamOpenResult::opened(std::move(tunnel_stream)));
            });
    }

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
            if (tls_handshake_) {
                tls_handshake_->cancel();
                tls_handshake_.reset();
            }
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
    std::shared_ptr<transport::TlsClientHandshake> tls_handshake_;
    std::shared_ptr<transport::ExchangeSession> session_;
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

void HttpProxyOutbound::connect_stream(core::StreamRequest request,
                                       core::StreamOpenHandler handler) {
    auto operation = std::make_shared<HttpProxyConnectOperation>(
        runtime_, resolver_, config_, std::move(request), std::move(handler));
    operation->start();
}

void HttpProxyOutbound::open_datagram(core::DatagramRequest, core::DatagramOpenHandler handler) {
    runtime_.scheduler().post([handler = std::move(handler)]() mutable {
        handler(core::DatagramOpenResult::unsupported());
    });
}

} // namespace clash_native::outbound
