#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/transport/shadowsocks/simple_obfs.hpp>
#include <clash_native/transport/shadowsocks/stream_carrier.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace clash_native::transport::shadowsocks {

using Shadowsocks2022OpenHandler = std::function<void(core::StreamOpenResult)>;

// Opens a Shadowsocks 2022 TCP session on an already connected socket. The
// destination is the Shadowsocks address encoding, keeping proxy address
// parsing outside the reusable transport module.
void async_open_shadowsocks_2022_stream(runtime::AsioRuntime &runtime,
                                        std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                        std::string method, std::string password,
                                        std::vector<std::uint8_t> destination,
                                        std::optional<ObfsClientOptions> obfs_options,
                                        Shadowsocks2022OpenHandler handler);

void async_open_shadowsocks_2022_stream(runtime::AsioRuntime &runtime,
                                        std::shared_ptr<StreamCarrier> carrier, std::string method,
                                        std::string password, std::vector<std::uint8_t> destination,
                                        Shadowsocks2022OpenHandler handler);

} // namespace clash_native::transport::shadowsocks
