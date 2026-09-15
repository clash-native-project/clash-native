#pragma once

#include <clash_native/core/outbound.hpp>

#include <boost/asio/ip/tcp.hpp>

namespace clash_native::net {

class TcpStream final : public core::StreamHandle {
  public:
    explicit TcpStream(boost::asio::ip::tcp::socket socket);

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override;
    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override;
    boost::asio::any_io_executor executor() noexcept override;
    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override;
    void shutdown_send(boost::system::error_code &error) noexcept override;
    void close() noexcept override;

  private:
    boost::asio::ip::tcp::socket socket_;
};

} // namespace clash_native::net
