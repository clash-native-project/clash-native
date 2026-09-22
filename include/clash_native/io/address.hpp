#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

#include <cstdint>
#include <string>
#include <variant>

namespace clash_native::io {

// Dial target: either a domain name or a literal IP address.
class Destination {
  public:
    static Destination domain(std::string value, std::uint16_t port) {
        return Destination(std::move(value), port);
    }

    static Destination address(boost::asio::ip::address value, std::uint16_t port) {
        return Destination(std::move(value), port);
    }

    bool is_domain() const noexcept { return std::holds_alternative<std::string>(value_); }
    bool is_address() const noexcept {
        return std::holds_alternative<boost::asio::ip::address>(value_);
    }

    const std::string &domain() const { return std::get<std::string>(value_); }
    const boost::asio::ip::address &address() const {
        return std::get<boost::asio::ip::address>(value_);
    }
    std::uint16_t port() const noexcept { return port_; }

  private:
    Destination(std::string value, std::uint16_t port) : value_(std::move(value)), port_(port) {}
    Destination(boost::asio::ip::address value, std::uint16_t port)
        : value_(std::move(value)), port_(port) {}

    std::variant<std::string, boost::asio::ip::address> value_;
    std::uint16_t port_;
};

// Address carried by a datagram protocol. Unlike udp::endpoint, this type
// preserves a domain name when the protocol supplies one on the wire.
class DatagramAddress {
  public:
    DatagramAddress() = default;

    static DatagramAddress domain(std::string value, std::uint16_t port) {
        return DatagramAddress(std::move(value), port);
    }

    static DatagramAddress address(boost::asio::ip::address value, std::uint16_t port) {
        return DatagramAddress(std::move(value), port);
    }

    static DatagramAddress from_endpoint(boost::asio::ip::udp::endpoint value) {
        return address(value.address(), value.port());
    }

    bool is_domain() const noexcept { return std::holds_alternative<std::string>(value_); }
    bool is_address() const noexcept {
        return std::holds_alternative<boost::asio::ip::address>(value_);
    }

    const std::string &domain() const { return std::get<std::string>(value_); }
    const boost::asio::ip::address &address() const {
        return std::get<boost::asio::ip::address>(value_);
    }
    std::uint16_t port() const noexcept { return port_; }

    Destination to_destination() const {
        return is_domain() ? Destination::domain(domain(), port())
                           : Destination::address(address(), port());
    }

  private:
    DatagramAddress(std::string value, std::uint16_t port)
        : value_(std::move(value)), port_(port) {}
    DatagramAddress(boost::asio::ip::address value, std::uint16_t port)
        : value_(std::move(value)), port_(port) {}

    std::variant<boost::asio::ip::address, std::string> value_ = boost::asio::ip::address{};
    std::uint16_t port_ = 0;
};

} // namespace clash_native::io
