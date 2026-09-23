#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/udp.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace clash_native::transport::shadowsocks {

// Options for the kcptun carrier used by Mihomo. The packet pipeline follows
// kcp-go (outer crypt, optional FEC) and the stream pipeline follows Mihomo
// (optional Snappy framing below SMUX).
struct KcptunClientOptions {
    std::string key = "it's a secrect";
    std::string crypt = "aes";
    std::string mode = "fast";
    int connection_count = 1;
    int auto_expire_seconds = 0;
    int scavenge_ttl_seconds = 600;
    int mtu = 1350;
    int rate_limit = 0;
    int send_window = 128;
    int receive_window = 512;
    int dscp = 0;
    bool ack_nodelay = false;
    int nodelay = 0;
    int interval_ms = 30;
    int fast_resend = 2;
    int disable_congestion_control = 1;
    int socket_buffer = 0;
    int data_shard = 10;
    int parity_shard = 3;
    bool no_compression = false;
    int smux_version = 1;
    int smux_buffer = 4 * 1024 * 1024;
    int frame_size = 8192;
    int stream_buffer = 2 * 1024 * 1024;
    int keepalive_seconds = 10;
};

core::Status validate_kcptun_client_options(const KcptunClientOptions &options);

// Creates the encrypted KCP byte carrier before SMUX stream multiplexing.
// The returned stream is owned by the caller and is suitable for exactly one
// Kcptun SMUX session.
core::Result<std::unique_ptr<io::StreamHandle>>
make_kcptun_carrier(runtime::AsioRuntime &runtime, boost::asio::ip::udp::endpoint remote_endpoint,
                    KcptunClientOptions options = {});

core::Result<std::unique_ptr<io::StreamHandle>>
make_kcptun_client_stream(runtime::AsioRuntime &runtime,
                          boost::asio::ip::udp::endpoint remote_endpoint,
                          KcptunClientOptions options = {});

} // namespace clash_native::transport::shadowsocks
