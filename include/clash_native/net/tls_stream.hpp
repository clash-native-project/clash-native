#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <memory>

namespace clash_native::transport::detail {
class TlsClientHandshakeOperationImpl;
}

namespace clash_native::net {

class TlsStream final : public io::StreamHandle {
  public:
    using SslStream = boost::asio::ssl::stream<StreamHandleAdapter<io::StreamHandle>>;

    TlsStream(std::shared_ptr<boost::asio::ssl::context> context,
              std::unique_ptr<io::StreamHandle> stream);

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override;
    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override;
    boost::asio::any_io_executor executor() noexcept override;
    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override;
    void shutdown_send(boost::system::error_code &error) noexcept override;
    void close() noexcept override;

    // Detaches the underlying project stream after a completed handshake.
    // The SSL layer must not be used after this call.
    std::unique_ptr<io::StreamHandle> take_transport() noexcept;

  private:
    std::shared_ptr<boost::asio::ssl::context> context_;
    std::unique_ptr<SslStream> stream_;

    friend class transport::detail::TlsClientHandshakeOperationImpl;
};

} // namespace clash_native::net
