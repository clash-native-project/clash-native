#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/stream_handle.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace clash_native::transport::proxy {

// gRPC Tun framing (transport/gun/gun.go), shared by Trojan/VLESS/VMess
// grpc carriers. Each message on the wire is
//   0x00 | u32be(1 + varlen + payload) | 0x0A | uvarint(payload) | payload
// This is a shared proxy carrier: it composes only the base
// io::ExchangeSession interface and never names a consumer protocol.
namespace gun {

// Length of the fixed frame prefix: flag + u32 length + field tag.
constexpr std::size_t kFramePrefixSize = 6;

std::size_t uvarint_length(std::uint64_t value) noexcept;

// Encodes one payload into a Tun frame.
std::vector<std::uint8_t> encode_frame(std::span<const std::uint8_t> payload);

struct GunStreamOptions {
    // Service path segment; empty means "GunService" (Mihomo default).
    std::string service_name;
    std::string user_agent = "grpc-go/1.36.0";
    std::string host;
    std::chrono::steady_clock::time_point deadline{};
    // Executor serializing the request queue and read state.
    boost::asio::any_io_executor executor;
};

using GunStreamHandler = std::function<void(core::Result<std::unique_ptr<io::StreamHandle>>)>;

// Opens a bidirectional Tun stream over an HTTP/2 exchange session:
// POST https://host/<service>/Tun with a streaming request body. Like
// Mihomo's gun Dial, the handle is delivered as soon as the request is
// submitted, WITHOUT waiting for the response head: the peer reads our
// first message before answering, so waiting would deadlock. Reads park
// until the head arrives; a head failure poisons later reads and writes.
// Request and response bodies then flow concurrently until either side
// closes.
void async_open_gun_stream(std::shared_ptr<io::ExchangeSession> session, GunStreamOptions options,
                           GunStreamHandler handler);

} // namespace gun
} // namespace clash_native::transport::proxy
