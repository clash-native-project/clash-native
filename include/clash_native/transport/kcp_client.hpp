#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <boost/asio/ip/udp.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <vector>

namespace clash_native::transport {

using KcpPacketEncoder =
    std::function<std::vector<std::vector<std::uint8_t>>(std::span<const std::uint8_t>)>;
using KcpPacketDecoder =
    std::function<std::vector<std::vector<std::uint8_t>>(std::span<const std::uint8_t>)>;

struct KcpClientOptions {
    std::uint32_t conversation_id = 0;
    int mtu = 1400;
    int send_window = 128;
    int receive_window = 128;
    int nodelay = 1;
    int interval_ms = 20;
    int fast_resend = 2;
    int disable_congestion_control = 1;
    bool ack_nodelay = false;
    int rate_limit = 0;
    KcpPacketEncoder encode_packet;
    KcpPacketDecoder decode_packet;
};

// Creates a reliable, ordered byte stream over an already-open UDP handle.
// The datagram handle is owned by the returned stream. KCP has no standard
// half-close or connection handshake, so shutdown_send reports unsupported
// and the first application write establishes traffic for the peer.
core::Result<std::unique_ptr<core::StreamHandle>>
make_kcp_client_stream(std::unique_ptr<core::DatagramHandle> datagram,
                       boost::asio::ip::udp::endpoint remote_endpoint,
                       KcpClientOptions options = {});

} // namespace clash_native::transport
