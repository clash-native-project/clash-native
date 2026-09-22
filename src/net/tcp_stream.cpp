#include <clash_native/net/tcp_stream.hpp>

#include <clash_native/core/error.hpp>

#include <exec/asio/use_sender.hpp>

#include <boost/asio/write.hpp>

#include <exception>
#include <utility>

namespace clash_native::net {
namespace {

// Asio system_errors surface as core::Error (preserving the code); aborts
// are already translated to set_stopped() by use_sender itself.
core::Error transport_error(const char *what, const boost::system::error_code &error) {
    return core::Error{core::ErrorCode::transport_io, what, error};
}

} // namespace

TcpStream::TcpStream(boost::asio::ip::tcp::socket socket) : socket_(std::move(socket)) {}

void TcpStream::async_read_some(boost::asio::mutable_buffer buffer,
                                core::StreamHandle::ReadHandler handler) {
    socket_.async_read_some(buffer, std::move(handler));
}

void TcpStream::async_write(boost::asio::const_buffer buffer,
                            core::StreamHandle::WriteHandler handler) {
    boost::asio::async_write(socket_, buffer, std::move(handler));
}

io::AnySender<std::optional<std::size_t>>
TcpStream::async_read_some(boost::asio::mutable_buffer buffer) {
    // use_sender turns the Asio initiation into a sender (error_code mapped
    // to system_error/set_stopped, stop token wired to Asio cancellation);
    // the adaptors below only translate into the io::StreamHandle contract
    // (EOF as empty, failures as core::Error).
    return io::AnySender<std::optional<std::size_t>>{
        socket_.async_read_some(buffer, exec::asio::use_sender) |
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
                        std::make_exception_ptr(transport_error("tcp read", failure.code())));
                }
                std::rethrow_exception(error);
            })};
}

io::AnySender<std::size_t> TcpStream::async_write(boost::asio::const_buffer buffer) {
    return io::AnySender<std::size_t>{
        boost::asio::async_write(socket_, buffer, exec::asio::use_sender) |
        stdexec::then([](std::size_t count) { return count; }) |
        stdexec::let_error([](std::exception_ptr error) -> decltype(stdexec::just(std::size_t(0))) {
            try {
                std::rethrow_exception(error);
            } catch (const boost::system::system_error &failure) {
                std::rethrow_exception(
                    std::make_exception_ptr(transport_error("tcp write", failure.code())));
            }
            std::rethrow_exception(error);
        })};
}

boost::asio::any_io_executor TcpStream::executor() noexcept { return socket_.get_executor(); }

boost::asio::ip::tcp::endpoint
TcpStream::local_endpoint(boost::system::error_code &error) const noexcept {
    return socket_.local_endpoint(error);
}

void TcpStream::shutdown_send(boost::system::error_code &error) noexcept {
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, error);
}

void TcpStream::close() noexcept {
    boost::system::error_code ignored;
    socket_.cancel(ignored);
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
}

} // namespace clash_native::net
