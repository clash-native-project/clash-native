#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <cstdint>
#include <memory>
#include <optional>

namespace clash_native::transport::shadowsocks {

enum class UdpOverTcpVersion : std::uint8_t {
    legacy = 1,
    version2 = 2,
};

struct UdpOverTcpOptions {
    UdpOverTcpVersion version = UdpOverTcpVersion::legacy;
    // Version 2 carries the UoT request header in the first stream write. The
    // request uses the standard SOCKS address encoding; packet frames use the
    // UoT-specific address encoding and carry their own destination.
    std::optional<core::Destination> request_destination;
};

// Adapts the stream opened to the Shadowsocks UoT magic destination to the
// addressed DatagramHandle interface. Version 2 writes its request lazily on
// the first datagram; both versions use per-datagram addresses on the wire.
core::Result<std::unique_ptr<core::DatagramHandle>>
make_udp_over_tcp_datagram_handle(std::unique_ptr<core::StreamHandle> stream,
                                  UdpOverTcpOptions options);

} // namespace clash_native::transport::shadowsocks
