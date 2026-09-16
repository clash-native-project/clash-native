#pragma once

#include <boost/asio/ip/address.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace clash_native::dns {

enum class DnsRecordType : std::uint16_t {
    a = 1,
    ns = 2,
    cname = 5,
    soa = 6,
    ptr = 12,
    mx = 15,
    txt = 16,
    aaaa = 28,
    srv = 33,
    opt = 41,
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

struct DnsResourceRecord {
    std::string name;
    std::uint16_t type = 0;
    std::uint16_t class_code = 1;
    std::uint32_t ttl_seconds = 0;
    std::vector<std::uint8_t> rdata;
    std::optional<std::string> target_name;
};

struct DnsPacket {
    std::vector<std::uint8_t> wire;
    std::uint16_t id = 0;
    std::uint16_t flags = 0;
    std::vector<DnsQuestion> questions;
    std::vector<DnsResourceRecord> answers;
    std::vector<DnsResourceRecord> authorities;
    std::vector<DnsResourceRecord> additionals;

    bool response() const noexcept { return (flags & 0x8000) != 0; }
    bool truncated() const noexcept { return (flags & 0x0200) != 0; }
    bool recursion_desired() const noexcept { return (flags & 0x0100) != 0; }
    bool authoritative() const noexcept { return (flags & 0x0400) != 0; }
    std::uint8_t response_code() const noexcept {
        return static_cast<std::uint8_t>(flags & 0x000f);
    }
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
