#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/transport/exchange_session.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace clash_native::transport {

struct WebSocketClientOptions {
    // HTTP/1.1 Host value used by the WebSocket handshake.
    std::string host;
    // HTTP/1.1 origin-form request target, normally beginning with '/'.
    std::string target;
    // Additional handshake headers. Connection, Upgrade, Host, and
    // Sec-WebSocket-* framing headers are managed by the client.
    std::vector<ExchangeField> headers;
    std::size_t max_message_size = 16 * 1024 * 1024;
    // When enabled, perform a TLS handshake before the HTTP/1.1 Upgrade.
    bool tls = false;
    std::string tls_server_name;
    bool tls_verify_peer = true;
    std::string tls_trusted_ca_pem;
    std::vector<std::string> tls_alpn_protocols;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

class WebSocketClientHandshake {
  public:
    virtual void cancel() noexcept = 0;
    virtual ~WebSocketClientHandshake() = default;
};

using WebSocketClientHandler =
    std::function<void(core::Result<std::unique_ptr<core::StreamHandle>>)>;

// Completes an optional TLS handshake followed by an HTTP/1.1 WebSocket
// Upgrade over an already established stream. The returned stream maps each
// async_write call to one binary WebSocket message and exposes incoming binary
// message payloads as a byte stream. Ping, pong, close, masking, and
// fragmentation are handled by the WebSocket implementation.
std::shared_ptr<WebSocketClientHandshake>
async_websocket_client_handshake(std::unique_ptr<core::StreamHandle> stream,
                                 WebSocketClientOptions options, WebSocketClientHandler handler);

} // namespace clash_native::transport
