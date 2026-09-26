#include <clash_native/transport/shadowsocks/websocket_plugin.hpp>

#include <clash_native/async/bridge.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/net/tcp_stream.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/errc.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

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
    WebSocketPluginOperation(std::unique_ptr<io::StreamHandle> stream,
                             WebSocketPluginOptions options, WebSocketPluginHandler handler)
        : executor_(stream->executor()), stream_(std::move(stream)), options_(std::move(options)),
          handler_(std::move(handler)) {}

    void start() {
        auto self = shared_from_this();
        boost::asio::post(executor_, [self] { self->scope_.spawn(run_open(self)); });
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
    static exec::task<void> run_open(std::shared_ptr<WebSocketPluginOperation> self) {
        if (self->options_.host.empty()) {
            self->finish(core::fail(configuration_error("WebSocket plugin host is required")));
            co_return;
        }
        if (self->options_.path.empty()) {
            self->options_.path = "/";
        }
        if (self->completed_ || !self->stream_) {
            co_return;
        }
        core::Result<std::unique_ptr<io::StreamHandle>> result;
        try {
            result = co_await async::bridge_sender<core::Result<std::unique_ptr<io::StreamHandle>>>(
                [self](async::BridgeSender<core::Result<std::unique_ptr<io::StreamHandle>>>::Handler
                           done) mutable {
                    WebSocketClientOptions options;
                    options.host = self->options_.host;
                    options.target = self->options_.path;
                    options.headers = self->options_.headers;
                    options.tls = self->options_.tls;
                    options.tls_server_name = self->options_.host;
                    options.tls_verify_peer = !self->options_.skip_cert_verify;
                    options.tls_verify_hostname = self->options_.name_cert_verify;
                    options.tls_client_certificate_pem = self->options_.client_certificate_pem;
                    options.tls_client_private_key_pem = self->options_.client_private_key_pem;
                    options.tls_certificate_pin = self->options_.certificate_pin;
                    if (!self->options_.ech_config_list.empty()) {
                        options.tls_ech_config_list = self->options_.ech_config_list;
                    }
                    options.tls_alpn_protocols = {"http/1.1"};
                    self->websocket_ = async_websocket_client_handshake(
                        std::move(self->stream_), std::move(options),
                        [self,
                         done](core::Result<std::unique_ptr<io::StreamHandle>> opened) mutable {
                            self->websocket_.reset();
                            done(std::move(opened));
                        });
                    return [self] {
                        if (self->websocket_) {
                            self->websocket_->cancel();
                        }
                    };
                });
        } catch (...) {
            self->finish(core::fail(core::Error{
                core::ErrorCode::endpoint_connection, "WebSocket plugin handshake failed", {}}));
            co_return;
        }
        if (self->completed_) {
            co_return;
        }
        self->finish(std::move(result));
    }

    void finish(core::Result<std::unique_ptr<io::StreamHandle>> result) {
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
    std::unique_ptr<io::StreamHandle> stream_;
    WebSocketPluginOptions options_;
    WebSocketPluginHandler handler_;
    std::shared_ptr<clash_native::transport::WebSocketClientHandshake> websocket_;
    bool completed_ = false;
    exec::async_scope scope_;
};

class WebSocketPluginMuxOperation final
    : public WebSocketMuxHandshake,
      public std::enable_shared_from_this<WebSocketPluginMuxOperation> {
  public:
    WebSocketPluginMuxOperation(std::unique_ptr<io::StreamHandle> stream,
                                WebSocketPluginOptions options, WebSocketPluginMuxHandler handler)
        : executor_(stream->executor()), stream_(std::move(stream)), options_(std::move(options)),
          handler_(std::move(handler)) {}

    void start() {
        auto self = shared_from_this();
        boost::asio::post(executor_, [self] { self->scope_.spawn(run_open(self)); });
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
                self->finish(core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>>(
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
    static exec::task<void> run_open(std::shared_ptr<WebSocketPluginMuxOperation> self) {
        if (self->options_.host.empty()) {
            self->finish(core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>>(
                core::fail(configuration_error("WebSocket plugin host is required"))));
            co_return;
        }
        if (self->options_.path.empty()) {
            self->options_.path = "/";
        }
        if (self->completed_ || !self->stream_) {
            co_return;
        }
        core::Result<std::unique_ptr<io::StreamHandle>> ws_result;
        try {
            ws_result =
                co_await async::bridge_sender<core::Result<std::unique_ptr<io::StreamHandle>>>(
                    [self](async::BridgeSender<
                           core::Result<std::unique_ptr<io::StreamHandle>>>::Handler done) mutable {
                        WebSocketClientOptions websocket_options;
                        websocket_options.host = self->options_.host;
                        websocket_options.target = self->options_.path;
                        websocket_options.tls = self->options_.tls;
                        websocket_options.tls_server_name = self->options_.host;
                        websocket_options.tls_verify_peer = !self->options_.skip_cert_verify;
                        websocket_options.tls_alpn_protocols = {"http/1.1"};
                        self->websocket_ = async_websocket_client_handshake(
                            std::move(self->stream_), std::move(websocket_options),
                            [self,
                             done](core::Result<std::unique_ptr<io::StreamHandle>> opened) mutable {
                                self->websocket_.reset();
                                done(std::move(opened));
                            });
                        return [self] {
                            if (self->websocket_) {
                                self->websocket_->cancel();
                            }
                        };
                    });
        } catch (...) {
            self->finish(core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>>(
                core::fail(core::Error{core::ErrorCode::endpoint_connection,
                                       "WebSocket plugin handshake failed",
                                       {}})));
            co_return;
        }
        if (self->completed_) {
            co_return;
        }
        if (!ws_result) {
            self->finish(core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>>(
                core::fail(ws_result.error())));
            co_return;
        }
        WebSocketMuxOptions mux_options;
        mux_options.protocol = self->options_.mux_protocol;
        mux_options.smux_version = self->options_.smux_version;
        core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>> mux_result;
        try {
            mux_result = co_await async::bridge_sender<
                core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>>>(
                [self, mux_options,
                 stream = std::make_shared<std::unique_ptr<io::StreamHandle>>(
                     std::move(ws_result.value()))](
                    async::BridgeSender<core::Result<std::shared_ptr<
                        clash_native::io::MultiplexedSession>>>::Handler done) mutable {
                    self->mux_ = async_open_websocket_mux(
                        std::move(*stream), mux_options,
                        [self,
                         done](core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>>
                                   opened) mutable {
                            self->mux_.reset();
                            done(std::move(opened));
                        });
                    return [self] {
                        if (self->mux_) {
                            self->mux_->cancel();
                        }
                    };
                });
        } catch (...) {
            self->finish(
                core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>>(core::fail(
                    core::Error{core::ErrorCode::transport_io, "WebSocket mux open failed", {}})));
            co_return;
        }
        self->finish(std::move(mux_result));
    }

    void finish(core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>> result) {
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
    std::unique_ptr<io::StreamHandle> stream_;
    WebSocketPluginOptions options_;
    WebSocketPluginMuxHandler handler_;
    std::shared_ptr<clash_native::transport::WebSocketClientHandshake> websocket_;
    std::shared_ptr<WebSocketMuxHandshake> mux_;
    bool completed_ = false;
    exec::async_scope scope_;
};

} // namespace

std::shared_ptr<clash_native::transport::WebSocketClientHandshake>
async_open_websocket_plugin(std::unique_ptr<io::StreamHandle> stream,
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
async_open_websocket_plugin_mux(std::unique_ptr<io::StreamHandle> stream,
                                WebSocketPluginOptions options, WebSocketPluginMuxHandler handler) {
    if (!stream || !handler) {
        if (stream) {
            stream->close();
        }
        if (handler) {
            handler(core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>>(
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
            struct OpenReceiver {
                using receiver_concept = stdexec::receiver_tag;
                StreamHandler handler;
                void set_value(std::unique_ptr<io::StreamHandle> stream) && noexcept {
                    auto callback = std::move(handler);
                    callback(std::move(stream));
                }
                void set_error(std::exception_ptr error) && noexcept {
                    auto callback = std::move(handler);
                    try {
                        std::rethrow_exception(std::move(error));
                    } catch (const core::Error &failure) {
                        callback(core::fail(failure));
                    } catch (...) {
                        callback(core::fail(
                            core::Error{core::ErrorCode::transport_io, "mux open failed", {}}));
                    }
                }
                void set_stopped() && noexcept {
                    auto callback = std::move(handler);
                    callback(core::fail(
                        core::Error{core::ErrorCode::cancelled, "mux open stopped", {}}));
                }
            };
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = self->session_->open_stream({}, std::chrono::steady_clock::now() +
                                                              std::chrono::seconds(15));
            async::start_with_receiver(std::move(sender), OpenReceiver{std::move(handler)});
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

void WebSocketPluginMuxPool::async_open_carrier(std::unique_ptr<io::StreamHandle> stream,
                                                WebSocketPluginOptions options) {
    auto self = shared_from_this();
    async_open_websocket_plugin_mux(
        std::move(stream), std::move(options),
        [self](core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>> result) {
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
        struct OpenReceiver {
            using receiver_concept = stdexec::receiver_tag;
            StreamHandler handler;
            void set_value(std::unique_ptr<io::StreamHandle> stream) && noexcept {
                auto callback = std::move(handler);
                callback(std::move(stream));
            }
            void set_error(std::exception_ptr error) && noexcept {
                auto callback = std::move(handler);
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const core::Error &failure) {
                    callback(core::fail(failure));
                } catch (...) {
                    callback(core::fail(
                        core::Error{core::ErrorCode::transport_io, "mux open failed", {}}));
                }
            }
            void set_stopped() && noexcept {
                auto callback = std::move(handler);
                callback(
                    core::fail(core::Error{core::ErrorCode::cancelled, "mux open stopped", {}}));
            }
        };
        // NOTE: name the sender first; argument order is unspecified.
        auto sender =
            session_->open_stream({}, std::chrono::steady_clock::now() + std::chrono::seconds(15));
        async::start_with_receiver(std::move(sender), OpenReceiver{std::move(request.handler)});
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
