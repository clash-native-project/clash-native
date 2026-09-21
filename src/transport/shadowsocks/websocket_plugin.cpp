#include <clash_native/transport/shadowsocks/websocket_plugin.hpp>

#include <clash_native/net/tcp_stream.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/errc.hpp>

#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

core::Error configuration_error(std::string message) {
    return {core::ErrorCode::configuration, std::move(message), {}};
}

class WebSocketPluginOperation final
    : public clash_native::transport::WebSocketClientHandshake,
      public std::enable_shared_from_this<WebSocketPluginOperation> {
  public:
    WebSocketPluginOperation(std::unique_ptr<core::StreamHandle> stream,
                             WebSocketPluginOptions options, WebSocketPluginHandler handler)
        : executor_(stream->executor()), stream_(std::move(stream)), options_(std::move(options)),
          handler_(std::move(handler)) {}

    void start() {
        auto self = shared_from_this();
        boost::asio::post(executor_, [self] { self->start_on_executor(); });
    }

    void cancel() noexcept override {
        try {
            auto self = shared_from_this();
            boost::asio::post(executor_, [self] {
                if (self->completed_) {
                    return;
                }
                if (self->websocket_) {
                    self->websocket_->cancel();
                }
                if (self->stream_) {
                    self->stream_->close();
                }
                self->finish(core::fail(
                    {core::ErrorCode::cancelled, "WebSocket plugin handshake was cancelled"}));
            });
        } catch (...) {
            if (stream_) {
                stream_->close();
            }
        }
    }

  private:
    void start_on_executor() {
        if (completed_) {
            return;
        }
        if (options_.host.empty()) {
            finish(core::fail(configuration_error("WebSocket plugin host is required")));
            return;
        }
        if (options_.path.empty()) {
            options_.path = "/";
        }
        start_websocket();
    }

    void start_websocket() {
        if (completed_ || !stream_) {
            return;
        }
        WebSocketClientOptions websocket_options;
        websocket_options.host = options_.host;
        websocket_options.target = options_.path;
        websocket_options.tls = options_.tls;
        websocket_options.tls_server_name = options_.host;
        websocket_options.tls_verify_peer = !options_.skip_cert_verify;
        websocket_options.tls_alpn_protocols = {"http/1.1"};
        auto self = shared_from_this();
        websocket_ = async_websocket_client_handshake(
            std::move(stream_), std::move(websocket_options),
            [self](core::Result<std::unique_ptr<core::StreamHandle>> result) mutable {
                self->websocket_.reset();
                if (!result) {
                    self->finish(core::fail(result.error()));
                    return;
                }
                self->finish(std::move(result.value()));
            });
    }

    void finish(core::Result<std::unique_ptr<core::StreamHandle>> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        if (!result && stream_) {
            stream_->close();
            stream_.reset();
        }
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    boost::asio::any_io_executor executor_;
    std::unique_ptr<core::StreamHandle> stream_;
    WebSocketPluginOptions options_;
    WebSocketPluginHandler handler_;
    std::shared_ptr<clash_native::transport::WebSocketClientHandshake> websocket_;
    bool completed_ = false;
};

class WebSocketPluginMuxOperation final
    : public WebSocketMuxHandshake,
      public std::enable_shared_from_this<WebSocketPluginMuxOperation> {
  public:
    WebSocketPluginMuxOperation(std::unique_ptr<core::StreamHandle> stream,
                                WebSocketPluginOptions options, WebSocketPluginMuxHandler handler)
        : executor_(stream->executor()), stream_(std::move(stream)), options_(std::move(options)),
          handler_(std::move(handler)) {}

    void start() {
        auto self = shared_from_this();
        boost::asio::post(executor_, [self] { self->start_on_executor(); });
    }

    void cancel() noexcept override {
        try {
            auto self = shared_from_this();
            boost::asio::post(executor_, [self] {
                if (self->completed_) {
                    return;
                }
                if (self->websocket_) {
                    self->websocket_->cancel();
                }
                if (self->mux_) {
                    self->mux_->cancel();
                }
                if (self->stream_) {
                    self->stream_->close();
                }
                self->finish(
                    core::Result<std::shared_ptr<clash_native::transport::MultiplexedSession>>(
                        core::fail({core::ErrorCode::cancelled,
                                    "WebSocket plugin mux handshake was cancelled",
                                    {}})));
            });
        } catch (...) {
            if (stream_) {
                stream_->close();
            }
        }
    }

  private:
    void start_on_executor() {
        if (completed_) {
            return;
        }
        if (options_.host.empty()) {
            finish(core::Result<std::shared_ptr<clash_native::transport::MultiplexedSession>>(
                core::fail(configuration_error("WebSocket plugin host is required"))));
            return;
        }
        if (options_.path.empty()) {
            options_.path = "/";
        }
        start_websocket();
    }

    void start_websocket() {
        if (completed_ || !stream_) {
            return;
        }
        WebSocketClientOptions websocket_options;
        websocket_options.host = options_.host;
        websocket_options.target = options_.path;
        websocket_options.tls = options_.tls;
        websocket_options.tls_server_name = options_.host;
        websocket_options.tls_verify_peer = !options_.skip_cert_verify;
        websocket_options.tls_alpn_protocols = {"http/1.1"};
        auto self = shared_from_this();
        websocket_ = async_websocket_client_handshake(
            std::move(stream_), std::move(websocket_options),
            [self](core::Result<std::unique_ptr<core::StreamHandle>> result) mutable {
                self->websocket_.reset();
                if (!result) {
                    self->finish(
                        core::Result<std::shared_ptr<clash_native::transport::MultiplexedSession>>(
                            core::fail(result.error())));
                    return;
                }
                WebSocketMuxOptions mux_options;
                mux_options.protocol = self->options_.mux_protocol;
                mux_options.smux_version = self->options_.smux_version;
                self->mux_ = async_open_websocket_mux(
                    std::move(result.value()), mux_options,
                    [self](
                        core::Result<std::shared_ptr<clash_native::transport::MultiplexedSession>>
                            mux_result) mutable {
                        self->mux_.reset();
                        self->finish(std::move(mux_result));
                    });
            });
    }

    void finish(core::Result<std::shared_ptr<clash_native::transport::MultiplexedSession>> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        auto handler = std::move(handler_);
        if (!result && stream_) {
            stream_->close();
            stream_.reset();
        }
        if (handler) {
            handler(std::move(result));
        }
    }

    boost::asio::any_io_executor executor_;
    std::unique_ptr<core::StreamHandle> stream_;
    WebSocketPluginOptions options_;
    WebSocketPluginMuxHandler handler_;
    std::shared_ptr<clash_native::transport::WebSocketClientHandshake> websocket_;
    std::shared_ptr<WebSocketMuxHandshake> mux_;
    bool completed_ = false;
};

} // namespace

std::shared_ptr<clash_native::transport::WebSocketClientHandshake>
async_open_websocket_plugin(std::unique_ptr<core::StreamHandle> stream,
                            WebSocketPluginOptions options, WebSocketPluginHandler handler) {
    if (!stream || !handler) {
        if (stream) {
            stream->close();
        }
        if (handler) {
            handler(core::fail(
                configuration_error("WebSocket plugin requires a stream and completion handler")));
        }
        return {};
    }
    auto operation = std::make_shared<WebSocketPluginOperation>(
        std::move(stream), std::move(options), std::move(handler));
    operation->start();
    return operation;
}

std::shared_ptr<WebSocketMuxHandshake>
async_open_websocket_plugin_mux(std::unique_ptr<core::StreamHandle> stream,
                                WebSocketPluginOptions options, WebSocketPluginMuxHandler handler) {
    if (!stream || !handler) {
        if (stream) {
            stream->close();
        }
        if (handler) {
            handler(core::Result<std::shared_ptr<clash_native::transport::MultiplexedSession>>(
                core::fail(configuration_error(
                    "WebSocket plugin mux requires a stream and completion handler"))));
        }
        return {};
    }
    auto operation = std::make_shared<WebSocketPluginMuxOperation>(
        std::move(stream), std::move(options), std::move(handler));
    operation->start();
    return operation;
}

void WebSocketPluginMuxPool::async_open_stream(
    std::vector<boost::asio::ip::tcp::endpoint> endpoints, WebSocketPluginOptions options,
    StreamHandler handler) {
    if (!handler) {
        return;
    }
    auto self = shared_from_this();
    boost::asio::post(executor_, [self, endpoints = std::move(endpoints),
                                  options = std::move(options),
                                  handler = std::move(handler)]() mutable {
        if (self->stopped_) {
            handler(core::fail(
                {core::ErrorCode::cancelled, "WebSocket plugin mux pool is stopped", {}}));
            return;
        }
        if (self->session_ && self->session_->retired()) {
            self->session_.reset();
        }
        if (self->session_) {
            self->session_->open_stream({},
                                        std::chrono::steady_clock::now() + std::chrono::seconds(15),
                                        std::move(handler));
            return;
        }
        if (endpoints.empty()) {
            handler(core::fail({core::ErrorCode::endpoint_connection,
                                "WebSocket plugin mux received no server endpoints",
                                {}}));
            return;
        }
        self->pending_.push_back({std::move(endpoints), std::move(options), std::move(handler)});
        if (!self->opening_) {
            self->start_carrier();
        }
    });
}

void WebSocketPluginMuxPool::start_carrier() {
    if (stopped_ || opening_ || pending_.empty()) {
        return;
    }
    opening_ = true;
    const auto &request = pending_.front();
    connecting_socket_ = std::make_shared<boost::asio::ip::tcp::socket>(executor_);
    auto self = shared_from_this();
    boost::asio::async_connect(
        *connecting_socket_, request.endpoints,
        [self, options = request.options](const boost::system::error_code &error,
                                          const boost::asio::ip::tcp::endpoint &) mutable {
            if (error) {
                self->connecting_socket_.reset();
                self->opening_ = false;
                self->fail_pending({core::ErrorCode::endpoint_connection,
                                    "failed to connect WebSocket mux carrier",
                                    std::error_code(error.value(), std::system_category())});
                return;
            }
            auto stream = std::make_unique<net::TcpStream>(std::move(*self->connecting_socket_));
            self->connecting_socket_.reset();
            self->async_open_carrier(std::move(stream), std::move(options));
        });
}

void WebSocketPluginMuxPool::async_open_carrier(std::unique_ptr<core::StreamHandle> stream,
                                                WebSocketPluginOptions options) {
    auto self = shared_from_this();
    async_open_websocket_plugin_mux(
        std::move(stream), std::move(options),
        [self](core::Result<std::shared_ptr<clash_native::transport::MultiplexedSession>> result) {
            self->opening_ = false;
            if (!result) {
                self->fail_pending(result.error());
                return;
            }
            self->session_ = std::move(result.value());
            self->drain_pending();
        });
}

void WebSocketPluginMuxPool::drain_pending() {
    if (!session_ || session_->retired()) {
        fail_pending({core::ErrorCode::transport_io,
                      "WebSocket plugin mux session retired while opening",
                      {}});
        session_.reset();
        return;
    }
    auto pending = std::move(pending_);
    pending_.clear();
    for (auto &request : pending) {
        session_->open_stream({}, std::chrono::steady_clock::now() + std::chrono::seconds(15),
                              std::move(request.handler));
    }
}

void WebSocketPluginMuxPool::fail_pending(core::Error error) {
    auto pending = std::move(pending_);
    pending_.clear();
    for (auto &request : pending) {
        request.handler(core::fail(error));
    }
}

void WebSocketPluginMuxPool::stop() noexcept {
    stopped_ = true;
    if (connecting_socket_) {
        boost::system::error_code ignored;
        connecting_socket_->cancel(ignored);
        connecting_socket_->close(ignored);
        connecting_socket_.reset();
    }
    if (session_) {
        session_->stop();
        session_.reset();
    }
    fail_pending({core::ErrorCode::cancelled, "WebSocket plugin mux pool was stopped", {}});
}

} // namespace clash_native::transport::shadowsocks
