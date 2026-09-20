#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/net/udp_stream.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/udp.hpp>

#include <memory>
#include <string>

namespace clash_native::outbound::detail {

core::Result<std::unique_ptr<core::DatagramHandle>> make_legacy_shadowsocks_datagram_handle(
    runtime::AsioRuntime &runtime, std::shared_ptr<dns::ResolverService> resolver,
    std::shared_ptr<net::UdpStream> socket, boost::asio::ip::udp::endpoint server,
    std::string method, std::string password);

} // namespace clash_native::outbound::detail
