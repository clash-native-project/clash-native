#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <memory>

namespace clash_native::transport::detail {
class TlsClientHandshakeOperationImpl;
}

namespace clash_native::net {

class TlsStream final : public core::StreamHandle {
  public:
    using SslStream = boost::asio::ssl::stream<StreamHandleAdapter>;

    TlsStream(std::shared_ptr<boost::asio::ssl::context> context,
              std::unique_ptr<core::StreamHandle> stream);

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override;
    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override;
    boost::asio::any_io_executor executor() noexcept override;
    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override;
    void shutdown_send(boost::system::error_code &error) noexcept override;
    void close() noexcept override;

  private:
    std::shared_ptr<boost::asio::ssl::context> context_;
    std::unique_ptr<SslStream> stream_;

    friend class transport::detail::TlsClientHandshakeOperationImpl;
};

} // namespace clash_native::net
