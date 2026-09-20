#pragma once

#include <clash_native/core/result.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace clash_native::transport::shadowsocks {

// Implements the packet pipeline used by kcp-go: optional FEC, followed by
// per-datagram integrity protection and packet encryption.
class KcptunPacketCodec final {
  public:
    struct Impl;

    static core::Result<std::shared_ptr<KcptunPacketCodec>>
    create(std::string key, std::string crypt, int data_shard, int parity_shard);

    std::vector<std::vector<std::uint8_t>> encode(std::span<const std::uint8_t> kcp_packet);
    std::vector<std::vector<std::uint8_t>> decode(std::span<const std::uint8_t> wire_packet);

  private:
    KcptunPacketCodec(std::vector<std::uint8_t> pass, std::string crypt, int data_shard,
                      int parity_shard);

    std::unique_ptr<Impl> impl_;
};

} // namespace clash_native::transport::shadowsocks
