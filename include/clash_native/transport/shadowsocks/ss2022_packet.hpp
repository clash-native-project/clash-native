#pragma once

#include <clash_native/core/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace clash_native::transport::shadowsocks {

// Stateful Shadowsocks 2022 UDP packet codec. The session identifier and
// packet counter are kept here because they are part of the wire protocol;
// socket ownership and asynchronous I/O remain in the outbound adapter.
class Shadowsocks2022DatagramCodec final {
  public:
    Shadowsocks2022DatagramCodec(std::string method, std::string password);

    core::Result<std::vector<std::uint8_t>> encrypt(std::span<const std::uint8_t> destination,
                                                    std::span<const std::uint8_t> payload);

    // Returns destination address bytes followed by payload bytes after
    // validating and removing the Shadowsocks 2022 response header.
    core::Result<std::vector<std::uint8_t>> decrypt(std::span<const std::uint8_t> wire);

    std::size_t max_datagram_size(std::size_t wire_limit,
                                  std::size_t destination_limit) const noexcept;

  private:
    std::string method_;
    std::string password_;
    std::vector<std::uint8_t> psk_;
    std::uint64_t session_id_ = 0;
    std::uint64_t packet_id_ = 0;
};

} // namespace clash_native::transport::shadowsocks
