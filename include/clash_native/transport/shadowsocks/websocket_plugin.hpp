#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/transport/shadowsocks/websocket_mux.hpp>
#include <clash_native/transport/tls_client.hpp>
#include <clash_native/transport/websocket_client.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clash_native::transport::shadowsocks {

struct WebSocketPluginOptions {
    std::string host;
    std::string path = "/";
    bool tls = false;
    bool skip_cert_verify = false;
    // Additional WebSocket handshake headers (Mihomo plugin-opts headers).
    std::vector<io::ExchangeField> headers;
    // Server certificate SHA-256 pin (Mihomo plugin-opts fingerprint).
    std::string certificate_pin;
    // Hostname verification target override (Mihomo name-cert-verify).
    std::string name_cert_verify;
    // Mutual-TLS client identity (Mihomo certificate/private-key). Only
    // sent when the server requests a client certificate.
    std::string client_certificate_pem;
    std::string client_private_key_pem;
    // Resolved ECH config list bytes (Mihomo ech-opts), empty disables ECH.
    std::vector<std::uint8_t> ech_config_list;
    bool mux = false;
    WebSocketMuxProtocol mux_protocol = WebSocketMuxProtocol::v2ray;
    std::uint8_t smux_version = 1;
};

using WebSocketPluginHandler = std::function<void(core::Result<std::unique_ptr<io::StreamHandle>>)>;

// Establishes an optional TLS layer followed by an HTTP/1.1 WebSocket
// upgrade. The returned stream carries raw Shadowsocks bytes as binary
// WebSocket messages.
std::shared_ptr<clash_native::transport::WebSocketClientHandshake>
async_open_websocket_plugin(std::unique_ptr<io::StreamHandle> stream,
                            WebSocketPluginOptions options, WebSocketPluginHandler handler);

using WebSocketPluginMuxHandler =
    std::function<void(core::Result<std::shared_ptr<clash_native::io::MultiplexedSession>>)>;

// Establishes a WebSocket carrier and exposes the selected plugin mux as a
// common MultiplexedSession. The caller owns the returned handshake operation
// until the callback completes or it is cancelled.
std::shared_ptr<WebSocketMuxHandshake>
async_open_websocket_plugin_mux(std::unique_ptr<io::StreamHandle> stream,
                                WebSocketPluginOptions options, WebSocketPluginMuxHandler handler);

// Reuses one WebSocket carrier for multiple logical plugin streams. A pool is
// scoped to one outbound configuration, so it does not mix hosts or plugin
// protocols. If the carrier retires, the next request establishes a new one.
class WebSocketPluginMuxPool final : public std::enable_shared_from_this<WebSocketPluginMuxPool> {
  public:
    using StreamHandler =
        std::function<void(core::Result<std::unique_ptr<clash_native::io::StreamHandle>>)>;

    explicit WebSocketPluginMuxPool(boost::asio::any_io_executor executor)
        : executor_(std::move(executor)) {}
    ~WebSocketPluginMuxPool() { stop(); }

    void async_open_stream(std::vector<boost::asio::ip::tcp::endpoint> endpoints,
                           WebSocketPluginOptions options, StreamHandler handler);
    void stop() noexcept;

  private:
    struct PendingOpen {
        std::vector<boost::asio::ip::tcp::endpoint> endpoints;
        WebSocketPluginOptions options;
        StreamHandler handler;
    };

    void start_carrier();
    void async_open_carrier(std::unique_ptr<io::StreamHandle> stream,
                            WebSocketPluginOptions options);
    void drain_pending();
    void fail_pending(core::Error error);

    boost::asio::any_io_executor executor_;
    std::shared_ptr<clash_native::io::MultiplexedSession> session_;
    std::vector<PendingOpen> pending_;
    std::shared_ptr<boost::asio::ip::tcp::socket> connecting_socket_;
    bool opening_ = false;
    bool stopped_ = false;
};

} // namespace clash_native::transport::shadowsocks
