#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/transport/multiplexed_session.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace clash_native::transport {

struct QuicClientOptions {
    std::string server_name;
    std::vector<std::string> alpn_protocols;
    bool verify_peer = true;
    std::string trusted_ca_pem;
    std::chrono::steady_clock::duration handshake_timeout = std::chrono::seconds(30);
};

struct QuicClientEvents {
    std::function<void(std::string)> ready;
    std::function<void(std::int64_t, const std::uint8_t *, std::size_t, bool)> stream_data;
    // Called with each acknowledged-to-ngtcp2 byte count, then once more with
    // complete=true after the queued application chunk has been consumed.
    std::function<void(std::int64_t, std::size_t, bool)> stream_write_consumed;
    std::function<void(std::int64_t, std::uint64_t)> stream_data_acked;
    std::function<void(std::int64_t)> stream_blocked;
    std::function<void(std::int64_t)> stream_writable;
    std::function<void(std::int64_t, std::uint64_t)> stream_closed;
    std::function<void(std::int64_t, std::uint64_t)> stream_reset;
    std::function<void()> stream_capacity;
    std::function<void(core::Error)> failed;
};

struct QuicOpenStreamResult {
    enum class State { opened, blocked, failed } state = State::failed;
    std::int64_t stream_id = -1;
    std::optional<core::Error> error;
};

struct QuicStreamObserver {
    std::function<void(const std::uint8_t *, std::size_t, bool)> data;
    std::function<void(std::size_t, bool)> write_consumed;
    std::function<void()> writable;
    std::function<void(std::uint64_t)> closed;
    std::function<void(std::uint64_t)> reset;
};

struct QuicDatagramObserver {
    std::function<void(const std::uint8_t *, std::size_t)> data;
    std::function<void()> closed;
};

class QuicClientConnection final : public MultiplexedSession,
                                   public std::enable_shared_from_this<QuicClientConnection> {
  public:
    using ObserverId = std::uint64_t;
    using DatagramWriteHandler = core::DatagramHandle::WriteHandler;

    QuicClientConnection(const QuicClientConnection &) = delete;
    QuicClientConnection &operator=(const QuicClientConnection &) = delete;
    ~QuicClientConnection();

    // All operations other than close() must be called on the supplied executor.
    QuicOpenStreamResult open_bidirectional_stream();
    QuicOpenStreamResult open_unidirectional_stream();
    void write_stream_data(std::int64_t stream_id, std::vector<std::uint8_t> data, bool fin);
    void shutdown_stream(std::int64_t stream_id, std::uint64_t application_error) noexcept;
    core::Status extend_receive_credit(std::int64_t stream_id, std::size_t consumed);

    StreamId open_stream(MultiplexedStreamRequest request,
                         std::chrono::steady_clock::time_point deadline,
                         StreamHandler handler) override;
    void cancel(StreamId stream_id) noexcept override;
    std::size_t active_streams() const noexcept override;
    std::optional<std::size_t> max_concurrent_streams() const noexcept override;
    void stop() noexcept override { close(); }

    ObserverId observe_stream(std::int64_t stream_id, QuicStreamObserver observer);
    void remove_stream_observer(std::int64_t stream_id, ObserverId observer_id) noexcept;
    ObserverId observe_datagrams(QuicDatagramObserver observer);
    void remove_datagram_observer(ObserverId observer_id) noexcept;
    void async_send_datagram(std::vector<std::uint8_t> data, DatagramWriteHandler handler);
    std::unique_ptr<core::DatagramHandle> open_datagram();
    std::size_t max_datagram_size() const noexcept;
    boost::asio::ip::udp::endpoint remote_endpoint() const noexcept;
    bool ready() const noexcept;
    bool retired() const noexcept override;
    boost::asio::any_io_executor executor() const noexcept;
    void set_events(QuicClientEvents events);
    void close() noexcept;

  private:
    class Impl;
    explicit QuicClientConnection(std::shared_ptr<Impl> impl);

    std::shared_ptr<Impl> impl_;
    friend std::shared_ptr<QuicClientConnection> make_quic_client_connection(
        boost::asio::any_io_executor, std::unique_ptr<core::DatagramHandle>,
        boost::asio::ip::udp::endpoint, QuicClientOptions, QuicClientEvents);
};

// Takes ownership of the already-opened datagram handle. Events run on the
// supplied executor. The handle must support one connected peer endpoint.
std::shared_ptr<QuicClientConnection>
make_quic_client_connection(boost::asio::any_io_executor executor,
                            std::unique_ptr<core::DatagramHandle> datagram,
                            boost::asio::ip::udp::endpoint remote_endpoint,
                            QuicClientOptions options, QuicClientEvents events);

} // namespace clash_native::transport
