#pragma once

#include <boost/asio/ip/address.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace clash_native::dns {

enum class DnsRecordType : std::uint16_t {
    a = 1,
    ns = 2,
    cname = 5,
    soa = 6,
    ptr = 12,
    hinfo = 13,
    mx = 15,
    txt = 16,
    sig = 24,
    aaaa = 28,
    srv = 33,
    naptr = 35,
    opt = 41,
    tlsa = 52,
    svcb = 64,
    https = 65,
    any = 255,
    uri = 256,
    caa = 257,
};

constexpr DnsRecordType dns_record_type_from_code(std::uint16_t code) noexcept {
    return static_cast<DnsRecordType>(code);
}

constexpr std::uint16_t dns_record_type_code(DnsRecordType type) noexcept {
    return static_cast<std::uint16_t>(type);
}

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

struct DnsSoaData {
    std::string primary_name_server;
    std::string responsible_mailbox;
    std::uint32_t serial = 0;
    std::uint32_t refresh = 0;
    std::uint32_t retry = 0;
    std::uint32_t expire = 0;
    std::uint32_t minimum_ttl = 0;
};

struct DnsMxData {
    std::uint16_t preference = 0;
    std::string exchange;
};

struct DnsSrvData {
    std::uint16_t priority = 0;
    std::uint16_t weight = 0;
    std::uint16_t port = 0;
    std::string target;
};

struct DnsResourceRecordOption {
    std::uint16_t code = 0;
    std::vector<std::uint8_t> data;
};

enum class DnsResourceRecordFieldType : std::uint8_t {
    ipv4_address,
    ipv6_address,
    unsigned_8,
    unsigned_16,
    unsigned_32,
    domain_name,
    string,
    binary,
    binary_strings,
    options,
};

using DnsResourceRecordFieldValue =
    std::variant<boost::asio::ip::address, std::uint8_t, std::uint16_t, std::uint32_t, std::string,
                 std::vector<std::uint8_t>, std::vector<std::vector<std::uint8_t>>,
                 std::vector<DnsResourceRecordOption>>;

struct DnsResourceRecordField {
    std::uint32_t key_code = 0;
    std::string key_name;
    DnsResourceRecordFieldType type = DnsResourceRecordFieldType::binary;
    DnsResourceRecordFieldValue value = std::vector<std::uint8_t>{};
};

struct DnsResourceRecord {
    std::string name;
    std::uint16_t type = 0;
    std::uint16_t class_code = 1;
    std::uint32_t ttl_seconds = 0;
    // Opaque RDATA for records c-ares represents as raw records or EDNS options.
    std::vector<std::uint8_t> rdata;
    std::optional<std::string> target_name;
    std::optional<boost::asio::ip::address> parsed_address;
    std::optional<DnsSoaData> soa;
    std::optional<DnsMxData> mx;
    std::vector<std::vector<std::uint8_t>> txt_strings;
    std::optional<DnsSrvData> srv;
    std::vector<DnsResourceRecordField> fields;
};

struct DnsPacket {
    std::vector<std::uint8_t> wire;
    std::uint16_t id = 0;
    std::uint16_t flags = 0;
    std::uint8_t extended_response_code = 0;
    std::vector<DnsQuestion> questions;
    std::vector<DnsResourceRecord> answers;
    std::vector<DnsResourceRecord> authorities;
    std::vector<DnsResourceRecord> additionals;

    bool response() const noexcept { return (flags & 0x8000) != 0; }
    bool truncated() const noexcept { return (flags & 0x0200) != 0; }
    bool recursion_desired() const noexcept { return (flags & 0x0100) != 0; }
    bool authoritative() const noexcept { return (flags & 0x0400) != 0; }
    std::uint16_t response_code() const noexcept {
        return static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(extended_response_code) << 4) | (flags & 0x000f));
    }
};

struct DnsAnswer {
    DnsQuestion question;
    std::vector<boost::asio::ip::address> addresses;
    std::uint32_t ttl_seconds = 0;
    std::uint16_t response_code = 0;
    bool truncated = false;
    bool authoritative = false;

    bool negative() const noexcept { return response_code != 0 || addresses.empty(); }
};

std::string normalize_name(std::string_view name);

} // namespace clash_native::dns
