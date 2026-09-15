#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_types.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace clash_native::dns {

class DnsMessageCodec final {
  public:
    static core::Result<std::vector<std::uint8_t>> encode_query(const DnsQuestion &question,
                                                                std::uint16_t id);
    static core::Result<DnsAnswer> decode_response(std::span<const std::uint8_t> message,
                                                   std::uint16_t expected_id);
};

} // namespace clash_native::dns
