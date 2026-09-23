#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/io/stream_handle.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <cstddef>
#include <functional>
#include <optional>

namespace clash_native::net {

// TCP stream over an owned socket: the leaf byte-stream implementation.
// Sender completions are value / core::Error / stopped, with
// per-operation cancellation through Asio slots so cancelling a read never
// disturbs a concurrent write.
class TcpStream final : public io::StreamHandle {
  public:
    explicit TcpStream(boost::asio::ip::tcp::socket socket);

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override;
    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override;
    boost::asio::any_io_executor executor() noexcept override;
    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override;
    void shutdown_send(boost::system::error_code &error) noexcept override;
    void close() noexcept override;

  private:
    boost::asio::ip::tcp::socket socket_;
};

} // namespace clash_native::net
