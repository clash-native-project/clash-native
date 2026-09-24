#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/transport/proxy/gun_stream.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace clash_native::transport::proxy::gun {

// Connection pool over gun Transports (transport/gun Client), shared by
// Trojan/VLESS/VMess grpc carriers. Each Transport owns one HTTP/2
// session; streams are spread by least count with Mihomo's
// max-connections/min-streams/max-streams growth rule.
struct GunClientOptions {
    gun::GunStreamOptions stream{};
    // Bounds each Tun handshake (response head arrival).
    std::chrono::seconds open_timeout{15};
    int max_connections = 0;
    int min_streams = 0;
    int max_streams = 0;
};

class GunClient final : public std::enable_shared_from_this<GunClient> {
  public:
    // Builds one Transport session on demand (TCP/TLS/HTTP-2 dial owned by
    // the consumer protocol).
    using SessionMaker = std::function<io::AnySender<std::shared_ptr<io::ExchangeSession>>()>;

    GunClient(GunClientOptions options, SessionMaker maker);

    // Dials one Tun stream on the least-loaded Transport, creating a new
    // Transport when the growth rule allows it.
    io::AnySender<std::unique_ptr<io::StreamHandle>> dial();

    void close() noexcept;

  private:
    struct TransportEntry {
        std::shared_ptr<io::ExchangeSession> session;
        std::atomic<int> streams{0};
    };

    // Releases the Transport stream reservation when the Tun stream closes.
    class CountedStreamHandle final : public io::StreamHandle {
      public:
        CountedStreamHandle(std::unique_ptr<io::StreamHandle> inner,
                            std::shared_ptr<TransportEntry> entry)
            : inner_(std::move(inner)), entry_(std::move(entry)) {}
        ~CountedStreamHandle() override { entry_->streams.fetch_sub(1, std::memory_order_relaxed); }
        io::AnySender<std::optional<std::size_t>>
        async_read_some(boost::asio::mutable_buffer buffer) override {
            return inner_->async_read_some(buffer);
        }
        io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
            return inner_->async_write(buffer);
        }
        boost::asio::any_io_executor executor() noexcept override { return inner_->executor(); }
        boost::asio::ip::tcp::endpoint
        local_endpoint(boost::system::error_code &error) const noexcept override {
            return inner_->local_endpoint(error);
        }
        void shutdown_send(boost::system::error_code &error) noexcept override {
            inner_->shutdown_send(error);
        }
        void close() noexcept override { inner_->close(); }

      private:
        std::unique_ptr<io::StreamHandle> inner_;
        std::shared_ptr<TransportEntry> entry_;
    };

    std::shared_ptr<TransportEntry> pick_transport();

    GunClientOptions options_;
    SessionMaker maker_;
    std::mutex mutex_;
    std::vector<std::shared_ptr<TransportEntry>> transports_;
    bool closed_ = false;
};

} // namespace clash_native::transport::proxy::gun
