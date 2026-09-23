#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/io/address.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace clash_native::outbound::detail {

struct DecodedProxyAddress {
    core::Destination destination;
    std::size_t size = 0;
};

// Converts an io:: dial/route target into the core:: vocabulary for the
// proxy address codecs above, which still speak core::.
inline core::Destination to_core_destination(const io::Destination &destination) {
    return destination.is_domain()
               ? core::Destination::domain(destination.domain(), destination.port())
               : core::Destination::address(destination.address(), destination.port());
}

inline core::Result<std::vector<std::uint8_t>>
encode_proxy_address(const core::Destination &destination) {
    std::vector<std::uint8_t> result;
    if (destination.is_address() && destination.address().is_v4()) {
        result.push_back(0x01);
        const auto bytes = destination.address().to_v4().to_bytes();
        result.insert(result.end(), bytes.begin(), bytes.end());
    } else if (destination.is_address()) {
        result.push_back(0x04);
        const auto bytes = destination.address().to_v6().to_bytes();
        result.insert(result.end(), bytes.begin(), bytes.end());
    } else {
        const auto &domain = destination.domain();
        if (domain.empty() || domain.size() > 255) {
            return core::fail({core::ErrorCode::protocol_framing,
                               "proxy protocol domain name length is invalid"});
        }
        result.push_back(0x03);
        result.push_back(static_cast<std::uint8_t>(domain.size()));
        result.insert(result.end(), domain.begin(), domain.end());
    }
    result.push_back(static_cast<std::uint8_t>(destination.port() >> 8));
    result.push_back(static_cast<std::uint8_t>(destination.port() & 0xff));
    return result;
}

inline core::Result<DecodedProxyAddress> decode_proxy_address(std::span<const std::uint8_t> bytes,
                                                              std::size_t offset = 0) {
    if (offset >= bytes.size()) {
        return core::fail(
            {core::ErrorCode::protocol_framing, "proxy protocol address is truncated"});
    }
    const auto type = bytes[offset++];
    core::Destination destination =
        core::Destination::address(boost::asio::ip::address_v4::any(), 0);
    std::size_t address_size = 0;
    switch (type) {
    case 0x01:
        address_size = 4;
        if (bytes.size() - offset < address_size + 2) {
            return core::fail(
                {core::ErrorCode::protocol_framing, "IPv4 proxy protocol address is truncated"});
        }
        {
            boost::asio::ip::address_v4::bytes_type address_bytes{};
            std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), address_size,
                        address_bytes.begin());
            destination = core::Destination::address(
                boost::asio::ip::address_v4(address_bytes),
                static_cast<std::uint16_t>((bytes[offset + 4] << 8) | bytes[offset + 5]));
        }
        return DecodedProxyAddress{std::move(destination), 1 + address_size + 2};
    case 0x04:
        address_size = 16;
        if (bytes.size() - offset < address_size + 2) {
            return core::fail(
                {core::ErrorCode::protocol_framing, "IPv6 proxy protocol address is truncated"});
        }
        {
            boost::asio::ip::address_v6::bytes_type address_bytes{};
            std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), address_size,
                        address_bytes.begin());
            destination = core::Destination::address(
                boost::asio::ip::address_v6(address_bytes),
                static_cast<std::uint16_t>((bytes[offset + 16] << 8) | bytes[offset + 17]));
        }
        return DecodedProxyAddress{std::move(destination), 1 + address_size + 2};
    case 0x03: {
        if (bytes.size() - offset < 1) {
            return core::fail(
                {core::ErrorCode::protocol_framing, "domain proxy protocol address is truncated"});
        }
        const auto domain_size = bytes[offset++];
        if (domain_size == 0 || bytes.size() - offset < domain_size + 2) {
            return core::fail({core::ErrorCode::protocol_framing,
                               "domain proxy protocol address has an invalid length"});
        }
        std::string domain(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                           bytes.begin() + static_cast<std::ptrdiff_t>(offset + domain_size));
        const auto port_offset = offset + domain_size;
        destination = core::Destination::domain(
            std::move(domain),
            static_cast<std::uint16_t>((bytes[port_offset] << 8) | bytes[port_offset + 1]));
        return DecodedProxyAddress{std::move(destination),
                                   static_cast<std::size_t>(1 + 1 + domain_size + 2)};
    }
    default:
        return core::fail(
            {core::ErrorCode::protocol_framing, "unsupported proxy protocol address type"});
    }
}

} // namespace clash_native::outbound::detail
