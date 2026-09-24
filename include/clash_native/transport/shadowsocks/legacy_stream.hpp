#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/transport/proxy/crypto.hpp>
#include <clash_native/transport/shadowsocks/simple_obfs.hpp>
#include <clash_native/transport/shadowsocks/stream_carrier.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace clash_native::transport::shadowsocks {

core::Result<std::unique_ptr<io::StreamHandle>>
make_legacy_stream_handle(std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::string method,
                          std::string password, transport::proxy::LegacyStreamCipher write_cipher,
                          std::vector<std::uint8_t> initial_wire = {},
                          ObfsMode obfs_mode = ObfsMode::none);

core::Result<std::unique_ptr<io::StreamHandle>>
make_legacy_stream_handle(std::shared_ptr<StreamCarrier> carrier, std::string method,
                          std::string password, transport::proxy::LegacyStreamCipher write_cipher,
                          std::vector<std::uint8_t> initial_wire = {});

} // namespace clash_native::transport::shadowsocks
