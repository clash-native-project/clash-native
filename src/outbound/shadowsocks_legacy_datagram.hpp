#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/io/datagram_handle.hpp>
#include <clash_native/net/udp_stream.hpp>

#include <boost/asio/ip/udp.hpp>

#include <memory>
#include <string>

namespace clash_native::outbound::detail {

core::Result<std::unique_ptr<io::DatagramHandle>>
make_legacy_shadowsocks_datagram_handle(std::shared_ptr<net::UdpStream> socket,
                                        boost::asio::ip::udp::endpoint server, std::string method,
                                        std::string password);

} // namespace clash_native::outbound::detail
