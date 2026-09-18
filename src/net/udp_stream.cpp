#include <clash_native/net/udp_stream.hpp>

#include <utility>

namespace clash_native::net {

UdpStream::UdpStream(boost::asio::any_io_executor executor)
    : socket_(std::make_shared<boost::asio::ip::udp::socket>(std::move(executor))) {}

UdpStream::~UdpStream() { close(); }

void UdpStream::open(boost::asio::ip::udp protocol, boost::system::error_code &error) {
    socket_->open(protocol, error);
}

void UdpStream::bind(boost::asio::ip::udp::endpoint endpoint, boost::system::error_code &error) {
    socket_->bind(std::move(endpoint), error);
}

void UdpStream::async_send_to(boost::asio::const_buffer buffer,
                              boost::asio::ip::udp::endpoint destination, WriteHandler handler) {
    const auto socket = socket_;
    socket->async_send_to(
        buffer, destination,
        [socket, handler = std::move(handler)](const boost::system::error_code &error,
                                               std::size_t size) mutable { handler(error, size); });
}

void UdpStream::async_receive_from(boost::asio::mutable_buffer buffer, ReadHandler handler) {
    const auto socket = socket_;
    const auto sender = std::make_shared<boost::asio::ip::udp::endpoint>();
    socket->async_receive_from(buffer, *sender,
                               [socket, sender, handler = std::move(handler)](
                                   const boost::system::error_code &error,
                                   std::size_t size) mutable { handler(error, size, *sender); });
}

boost::asio::any_io_executor UdpStream::executor() noexcept { return socket_->get_executor(); }

boost::asio::ip::udp::endpoint
UdpStream::local_endpoint(boost::system::error_code &error) const noexcept {
    return socket_->local_endpoint(error);
}

void UdpStream::cancel() noexcept {
    boost::system::error_code ignored;
    socket_->cancel(ignored);
}

void UdpStream::close() noexcept {
    boost::system::error_code ignored;
    socket_->cancel(ignored);
    socket_->close(ignored);
}

} // namespace clash_native::net
