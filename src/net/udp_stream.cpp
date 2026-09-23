#include <clash_native/net/udp_stream.hpp>

#include <clash_native/core/error.hpp>

#include <exec/asio/use_sender.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/socket_base.hpp>

#include <exception>
#include <stdexec/execution.hpp>
#include <system_error>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <utility>

namespace clash_native::net {
namespace {

// Asio system_errors surface as core::Error (preserving the code); aborts
// are already translated to set_stopped() by use_sender itself.
core::Error transport_error(const char *what, const boost::system::error_code &error) {
    return core::Error{core::ErrorCode::transport_io, what, error};
}

} // namespace

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
        result = ::setsockopt(native, IPPROTO_IP, IP_TOS, reinterpret_cast<const char *>(&value),
                              sizeof(value));
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

io::AnySender<std::size_t> UdpStream::async_send_to(boost::asio::const_buffer buffer,
                                                    io::DatagramAddress destination) {
    if (!destination.is_address()) {
        const boost::system::error_code unsupported = boost::asio::error::operation_not_supported;
        return io::AnySender<std::size_t>{stdexec::just_error(std::make_exception_ptr(
            transport_error("udp send requires an IP destination", unsupported)))};
    }
    const auto endpoint = boost::asio::ip::udp::endpoint(destination.address(), destination.port());
    // NOTE: the recovery builds its error sender explicitly and never throws
    // out of the let_error function; throwing across the adaptor frames
    // proved unreliable on this toolchain.
    return io::AnySender<std::size_t>{
        socket_->async_send_to(buffer, endpoint, exec::asio::use_sender) |
        stdexec::let_error([](std::exception_ptr error) {
            try {
                std::rethrow_exception(error);
            } catch (const boost::system::system_error &failure) {
                return stdexec::just_error(
                    std::make_exception_ptr(transport_error("udp send", failure.code())));
            } catch (...) {
                return stdexec::just_error(std::current_exception());
            }
            return stdexec::just_error(std::current_exception());
        })};
}

io::AnySender<io::DatagramPacket>
UdpStream::async_receive_from(boost::asio::mutable_buffer buffer) {
    auto sender = std::make_shared<boost::asio::ip::udp::endpoint>();
    return io::AnySender<io::DatagramPacket>{
        socket_->async_receive_from(buffer, *sender, exec::asio::use_sender) |
        stdexec::then([sender](std::size_t size) {
            return io::DatagramPacket{size, io::DatagramAddress::from_endpoint(*sender)};
        }) |
        stdexec::let_error([](std::exception_ptr error) {
            try {
                std::rethrow_exception(error);
            } catch (const boost::system::system_error &failure) {
                return stdexec::just_error(
                    std::make_exception_ptr(transport_error("udp receive", failure.code())));
            } catch (...) {
                return stdexec::just_error(std::current_exception());
            }
            return stdexec::just_error(std::current_exception());
        })};
}

void UdpStream::async_send_to(boost::asio::const_buffer buffer, core::DatagramAddress destination,
                              core::DatagramHandle::WriteHandler handler) {
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

void UdpStream::async_receive_from(boost::asio::mutable_buffer buffer,
                                   core::DatagramHandle::ReadHandler handler) {
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
