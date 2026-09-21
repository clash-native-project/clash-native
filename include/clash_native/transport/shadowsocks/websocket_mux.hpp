#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/transport/multiplexed_session.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

// Shadowsocks WebSocket plugin multiplexing for v2ray mux and gost SMUX.

namespace clash_native::transport::shadowsocks {

enum class WebSocketMuxProtocol : std::uint8_t {
    v2ray,
    smux,
};

struct WebSocketMuxOptions {
    WebSocketMuxProtocol protocol = WebSocketMuxProtocol::v2ray;
    std::uint8_t smux_version = 1;
    std::size_t max_frame_size = 32 * 1024;
    std::size_t smux_stream_buffer = 2 * 1024 * 1024;
    std::size_t max_concurrent_streams = 1024;
};

class WebSocketMuxHandshake {
  public:
    virtual void cancel() noexcept = 0;
    virtual ~WebSocketMuxHandshake() = default;
};

using WebSocketMuxHandler =
    std::function<void(core::Result<std::shared_ptr<clash_native::transport::MultiplexedSession>>)>;

// Takes ownership of an established HTTP/1.1 WebSocket byte stream and adds
// the selected plugin multiplexing protocol above it. The returned session
// owns the WebSocket stream and exposes each plugin logical stream as the
// common StreamHandle interface.
std::shared_ptr<WebSocketMuxHandshake>
async_open_websocket_mux(std::unique_ptr<core::StreamHandle> websocket, WebSocketMuxOptions options,
                         WebSocketMuxHandler handler);

} // namespace clash_native::transport::shadowsocks
