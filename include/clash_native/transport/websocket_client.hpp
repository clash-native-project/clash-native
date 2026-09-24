#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/transport/tls_client.hpp>

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
    std::vector<io::ExchangeField> headers;
    // First payload bytes carried by the handshake (Mihomo early-data
    // semantics): min(size, max_early_data) base64url-encoded into the
    // request path (or early_data_header_name when set); the remainder
    // is sent as the first post-handshake message(s) by the handshake
    // operation. A `?ed=N` target query auto-configures max_early_data
    // with Sec-WebSocket-Protocol, matching Mihomo.
    std::vector<std::uint8_t> initial_payload;
    std::size_t max_early_data = 0;
    std::string early_data_header_name;
    // v2ray-http-upgrade: plain HTTP Upgrade tunnel without WebSocket
    // framing; initial_payload is written raw after the 101.
    bool v2ray_http_upgrade = false;
    std::size_t max_message_size = 16 * 1024 * 1024;
    // When enabled, perform a TLS handshake before the HTTP/1.1 Upgrade.
    bool tls = false;
    std::string tls_server_name;
    bool tls_verify_peer = true;
    std::string tls_trusted_ca_pem;
    std::string tls_verify_hostname;
    std::string tls_client_certificate_pem;
    std::string tls_client_private_key_pem;
    std::vector<std::string> tls_alpn_protocols;
    // ClientHello camouflage profile, forwarded to the TLS client.
    std::string tls_fingerprint;
    std::optional<TlsRealityOptions> tls_reality;
    std::optional<std::vector<std::uint8_t>> tls_ech_config_list;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

class WebSocketClientHandshake {
  public:
    virtual void cancel() noexcept = 0;
    virtual ~WebSocketClientHandshake() = default;
};

using WebSocketClientHandler = std::function<void(core::Result<std::unique_ptr<io::StreamHandle>>)>;

// Completes an optional TLS handshake followed by an HTTP/1.1 WebSocket
// Upgrade over an already established stream. The returned stream maps each
// async_write call to one binary WebSocket message and exposes incoming binary
// message payloads as a byte stream. Ping, pong, close, masking, and
// fragmentation are handled by the WebSocket implementation.
std::shared_ptr<WebSocketClientHandshake>
async_websocket_client_handshake(std::unique_ptr<io::StreamHandle> stream,
                                 WebSocketClientOptions options, WebSocketClientHandler handler);

} // namespace clash_native::transport
