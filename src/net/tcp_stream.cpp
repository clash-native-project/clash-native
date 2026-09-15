#include <clash_native/net/tcp_stream.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>

#include <utility>

namespace clash_native::net {

TcpStream::TcpStream(boost::asio::ip::tcp::socket socket) : socket_(std::move(socket)) {}

void TcpStream::async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) {
    socket_.async_read_some(buffer, std::move(handler));
}

void TcpStream::async_write(boost::asio::const_buffer buffer, WriteHandler handler) {
    boost::asio::async_write(socket_, buffer, std::move(handler));
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
