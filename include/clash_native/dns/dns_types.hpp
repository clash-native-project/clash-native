#pragma once

#include <boost/asio/ip/address.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace clash_native::dns {

enum class DnsRecordType : std::uint16_t {
    a = 1,
    aaaa = 28,
};

struct DnsQuestion {
    std::string name;
    DnsRecordType type = DnsRecordType::a;
    std::uint16_t class_code = 1;
};

struct DnsQuery {
    std::uint16_t id = 0;
    DnsQuestion question;
    bool recursion_desired = true;
};

struct DnsAnswer {
    DnsQuestion question;
    std::vector<boost::asio::ip::address> addresses;
    std::uint32_t ttl_seconds = 0;
    std::uint8_t response_code = 0;
    bool truncated = false;
    bool authoritative = false;

    bool negative() const noexcept { return response_code != 0 || addresses.empty(); }
};

std::string normalize_name(std::string_view name);

} // namespace clash_native::dns
