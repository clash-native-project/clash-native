#include <clash_native/net/tls_stream.hpp>

#include <boost/asio/write.hpp>

#include <utility>

namespace clash_native::net {

TlsStream::TlsStream(std::shared_ptr<boost::asio::ssl::context> context,
                     std::unique_ptr<core::StreamHandle> stream)
    : context_(std::move(context)),
      stream_(std::make_unique<SslStream>(StreamHandleAdapter(std::move(stream)), *context_)) {}

void TlsStream::async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) {
    stream_->async_read_some(buffer, std::move(handler));
}

void TlsStream::async_write(boost::asio::const_buffer buffer, WriteHandler handler) {
    boost::asio::async_write(*stream_, buffer, std::move(handler));
}

boost::asio::any_io_executor TlsStream::executor() noexcept { return stream_->get_executor(); }

boost::asio::ip::tcp::endpoint
TlsStream::local_endpoint(boost::system::error_code &error) const noexcept {
    return stream_->lowest_layer().local_endpoint(error);
}

void TlsStream::shutdown_send(boost::system::error_code &error) noexcept {
    stream_->lowest_layer().shutdown_send(error);
}

void TlsStream::close() noexcept { stream_->lowest_layer().close(); }

} // namespace clash_native::net
