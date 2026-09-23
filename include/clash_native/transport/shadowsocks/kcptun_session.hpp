#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/transport/shadowsocks/kcptun.hpp>

#include <boost/asio/ip/udp.hpp>

#include <memory>

namespace clash_native::transport::shadowsocks {

// Reuses a bounded set of KCP/SMUX sessions for one Shadowsocks kcptun
// endpoint. Each opened stream remains an ordinary StreamHandle to callers;
// session ownership and SMUX stream IDs stay inside this carrier layer.
class KcptunClientPool final {
  public:
    KcptunClientPool(runtime::AsioRuntime &runtime, KcptunClientOptions options);
    ~KcptunClientPool();

    KcptunClientPool(const KcptunClientPool &) = delete;
    KcptunClientPool &operator=(const KcptunClientPool &) = delete;

    io::AnySender<std::unique_ptr<io::StreamHandle>>
    open_stream(boost::asio::ip::udp::endpoint endpoint);
    void close() noexcept;

  private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

} // namespace clash_native::transport::shadowsocks
