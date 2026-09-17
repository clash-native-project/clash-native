#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_types.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace clash_native::dns {

class DnsMessageCodec final {
  public:
    static core::Result<DnsPacket>
    decode_packet(std::span<const std::uint8_t> message,
                  std::optional<std::uint16_t> expected_id = std::nullopt);
    static core::Result<std::vector<std::uint8_t>> encode_query_packet(const DnsQuestion &question,
                                                                       std::uint16_t id);
    static core::Result<std::vector<std::uint8_t>> rewrite_id(const DnsPacket &packet,
                                                              std::uint16_t id);
    static core::Result<DnsAnswer> to_address_answer(const DnsPacket &packet);

    static core::Result<std::vector<std::uint8_t>> encode_query(const DnsQuestion &question,
                                                                std::uint16_t id);
    static core::Result<DnsQuery> decode_query(std::span<const std::uint8_t> message);
    static core::Result<DnsAnswer> decode_response(std::span<const std::uint8_t> message,
                                                   std::uint16_t expected_id);
    static core::Result<std::vector<std::uint8_t>> encode_response(const DnsQuery &query,
                                                                   const DnsAnswer &answer);
    static core::Result<std::vector<std::uint8_t>> encode_response(const DnsPacket &query,
                                                                   const DnsAnswer &answer);
    static core::Result<std::vector<std::uint8_t>> encode_error_response(const DnsPacket &query,
                                                                         std::uint16_t code);
    static core::Result<std::vector<std::uint8_t>>
    truncate_udp_response(std::span<const std::uint8_t> response, std::size_t maximum_size);
};

} // namespace clash_native::dns
