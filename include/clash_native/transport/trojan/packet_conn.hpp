#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/io/datagram_handle.hpp>
#include <clash_native/io/stream_handle.hpp>

#include <cstdint>
#include <memory>

namespace clash_native::transport::trojan {

// Trojan-specific UDP-over-TCP framing (transport/trojan/trojan.go):
// each packet on the wire is
//   socks5-addr | u16be length | CRLF | payload
// and payloads larger than kMaxPacketPayload are split into multiple
// packets. The receive side keeps remainder state like Mihomo's PacketConn:
// when the caller's buffer is smaller than a packet, the packet head is
// delivered and the rest is parked for the next receive.
//
// This is Trojan code: it composes only the base io::StreamHandle
// interface and never includes another protocol's transport.
constexpr std::size_t kMaxPacketPayload = 8192;

// Trojan UDP command byte used in the stream request header.
constexpr std::uint8_t kCommandUdp = 0x03;

core::Result<std::unique_ptr<io::DatagramHandle>>
make_trojan_packet_conn(std::unique_ptr<io::StreamHandle> stream);

} // namespace clash_native::transport::trojan
