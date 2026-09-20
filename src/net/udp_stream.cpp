#include <clash_native/net/udp_stream.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/socket_base.hpp>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

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

void UdpStream::set_buffer_size(int bytes, boost::system::error_code &error) {
    if (bytes <= 0) {
        error.clear();
        return;
    }
    socket_->set_option(boost::asio::socket_base::receive_buffer_size(bytes), error);
    if (!error) {
        socket_->set_option(boost::asio::socket_base::send_buffer_size(bytes), error);
    }
}

void UdpStream::set_dscp(int dscp, boost::system::error_code &error) {
    if (dscp < 0 || dscp > 63) {
        error = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    if (dscp == 0) {
        error.clear();
        return;
    }
    const auto endpoint = socket_->local_endpoint(error);
    if (error) {
        return;
    }
    const int value = dscp << 2;
    const auto native = socket_->native_handle();
    int result = 0;
    if (endpoint.address().is_v4()) {
#if defined(_WIN32)
        result = ::setsockopt(native, IPPROTO_IP, IP_TOS,
                              reinterpret_cast<const char *>(&value), sizeof(value));
#else
        result = ::setsockopt(native, IPPROTO_IP, IP_TOS, &value, sizeof(value));
#endif
    } else {
#if defined(_WIN32)
        result = ::setsockopt(native, IPPROTO_IPV6, IPV6_TCLASS,
                              reinterpret_cast<const char *>(&value), sizeof(value));
#else
        result = ::setsockopt(native, IPPROTO_IPV6, IPV6_TCLASS, &value, sizeof(value));
#endif
    }
    if (result != 0) {
#if defined(_WIN32)
        error = boost::system::error_code(::WSAGetLastError(), boost::system::system_category());
#else
        error = boost::system::error_code(errno, boost::system::system_category());
#endif
    } else {
        error.clear();
    }
}

void UdpStream::async_send_to(boost::asio::const_buffer buffer, core::DatagramAddress destination,
                              WriteHandler handler) {
    const auto socket = socket_;
    if (!destination.is_address()) {
        boost::asio::post(socket->get_executor(), [handler = std::move(handler)]() mutable {
            handler(boost::asio::error::operation_not_supported, 0);
        });
        return;
    }
    const auto endpoint = boost::asio::ip::udp::endpoint(destination.address(), destination.port());
    socket->async_send_to(
        buffer, endpoint,
        [socket, handler = std::move(handler)](const boost::system::error_code &error,
                                               std::size_t size) mutable { handler(error, size); });
}

void UdpStream::async_receive_from(boost::asio::mutable_buffer buffer, ReadHandler handler) {
    const auto socket = socket_;
    const auto sender = std::make_shared<boost::asio::ip::udp::endpoint>();
    socket->async_receive_from(
        buffer, *sender,
        [socket, sender, handler = std::move(handler)](const boost::system::error_code &error,
                                                       std::size_t size) mutable {
            handler(error, size, core::DatagramAddress::from_endpoint(*sender));
        });
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
