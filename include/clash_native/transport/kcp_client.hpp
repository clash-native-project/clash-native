#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <boost/asio/ip/udp.hpp>

#include <cstdint>
#include <memory>

namespace clash_native::transport {

struct KcpClientOptions {
    std::uint32_t conversation_id = 0;
    int mtu = 1400;
    int send_window = 128;
    int receive_window = 128;
    int nodelay = 1;
    int interval_ms = 20;
    int fast_resend = 2;
    int disable_congestion_control = 1;
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
