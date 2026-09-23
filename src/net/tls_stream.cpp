#include <clash_native/net/tls_stream.hpp>

#include <clash_native/core/error.hpp>

#include <exec/asio/use_sender.hpp>

#include <boost/asio/write.hpp>

#include <exception>
#include <utility>

namespace clash_native::net {
namespace {

core::Error transport_error(const char *what, const boost::system::error_code &error) {
    return core::Error{core::ErrorCode::transport_io, what, error};
}

} // namespace

TlsStream::TlsStream(std::shared_ptr<boost::asio::ssl::context> context,
                     std::unique_ptr<io::StreamHandle> stream)
    : context_(std::move(context)),
      stream_(std::make_unique<SslStream>(StreamHandleAdapter(std::move(stream)), *context_)) {}

io::AnySender<std::optional<std::size_t>>
TlsStream::async_read_some(boost::asio::mutable_buffer buffer) {
    return io::AnySender<std::optional<std::size_t>>{
        stream_->async_read_some(buffer, exec::asio::use_sender) |
        stdexec::then([](std::size_t count) { return std::optional<std::size_t>(count); }) |
        stdexec::let_error(
            [](std::exception_ptr error) -> decltype(stdexec::just(std::optional<std::size_t>())) {
                try {
                    std::rethrow_exception(error);
                } catch (const boost::system::system_error &failure) {
                    if (failure.code() == boost::asio::error::eof) {
                        return stdexec::just(std::optional<std::size_t>());
                    }
                    std::rethrow_exception(
                        std::make_exception_ptr(transport_error("tls read", failure.code())));
                }
                std::rethrow_exception(error);
            })};
}

io::AnySender<std::size_t> TlsStream::async_write(boost::asio::const_buffer buffer) {
    return io::AnySender<std::size_t>{
        boost::asio::async_write(*stream_, buffer, exec::asio::use_sender) |
        stdexec::let_error([](std::exception_ptr error) -> decltype(stdexec::just(std::size_t(0))) {
            try {
                std::rethrow_exception(error);
            } catch (const boost::system::system_error &failure) {
                std::rethrow_exception(
                    std::make_exception_ptr(transport_error("tls write", failure.code())));
            }
            std::rethrow_exception(error);
        })};
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

std::unique_ptr<io::StreamHandle> TlsStream::take_transport() noexcept {
    if (!stream_) {
        return {};
    }
    auto transport = stream_->next_layer().release();
    stream_.reset();
    return transport;
}

} // namespace clash_native::net
