#pragma once

#include <clash_native/core/outbound.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <optional>
#include <string>

namespace clash_native::core {

enum class Network {
    tcp,
    udp,
};

struct ConnectionMetadata {
    Network network = Network::tcp;
    std::optional<boost::asio::ip::tcp::endpoint> source;
    Destination destination;
    std::string inbound_name;
    std::string inbound_type;
    std::optional<std::string> authenticated_user;
    std::optional<std::string> sniffed_host;
};

} // namespace clash_native::core
