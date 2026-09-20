#include <clash_native/transport/shadowsocks/websocket_plugin.hpp>

#include <clash_native/transport/tls_client.hpp>

#include <boost/asio/post.hpp>

#include <memory>
#include <string>
#include <utility>

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
                if (self->tls_) {
                    self->tls_->cancel();
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
        if (options_.tls) {
            TlsClientOptions tls_options;
            tls_options.server_name = options_.host;
            tls_options.verify_peer = !options_.skip_cert_verify;
            auto self = shared_from_this();
            tls_ = async_tls_client_handshake(
                std::move(stream_), std::move(tls_options),
                [self](core::Result<TlsClientConnection> result) mutable {
                    self->tls_.reset();
                    if (!result) {
                        self->finish(core::fail(result.error()));
                        return;
                    }
                    self->stream_ = std::move(result.value().stream);
                    self->start_websocket();
                });
            return;
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
    std::shared_ptr<clash_native::transport::TlsClientHandshake> tls_;
    std::shared_ptr<clash_native::transport::WebSocketClientHandshake> websocket_;
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

} // namespace clash_native::transport::shadowsocks
