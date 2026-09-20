#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/transport/tls_client.hpp>
#include <clash_native/transport/websocket_client.hpp>

#include <functional>
#include <memory>
#include <string>

namespace clash_native::transport::shadowsocks {

struct WebSocketPluginOptions {
    std::string host;
    std::string path = "/";
    bool tls = false;
    bool skip_cert_verify = false;
};

using WebSocketPluginHandler =
    std::function<void(core::Result<std::unique_ptr<core::StreamHandle>>)>;

// Establishes an optional TLS layer followed by an HTTP/1.1 WebSocket
// upgrade. The returned stream carries raw Shadowsocks bytes as binary
// WebSocket messages. Multiplexing is intentionally not enabled here.
std::shared_ptr<clash_native::transport::WebSocketClientHandshake>
async_open_websocket_plugin(std::unique_ptr<core::StreamHandle> stream,
                            WebSocketPluginOptions options, WebSocketPluginHandler handler);

} // namespace clash_native::transport::shadowsocks
