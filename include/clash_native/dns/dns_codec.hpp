#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_types.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace clash_native::dns {

class DnsMessageCodec final {
  public:
    static core::Result<std::vector<std::uint8_t>> encode_query(const DnsQuestion &question,
                                                                std::uint16_t id);
    static core::Result<DnsQuery> decode_query(std::span<const std::uint8_t> message);
    static core::Result<DnsAnswer> decode_response(std::span<const std::uint8_t> message,
                                                   std::uint16_t expected_id);
    static core::Result<std::vector<std::uint8_t>> encode_response(const DnsQuery &query,
                                                                   const DnsAnswer &answer);
};

} // namespace clash_native::dns
