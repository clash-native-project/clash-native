#pragma once

#include <clash_native/core/error.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/io/stream_handle.hpp>

#include <exec/asio/use_sender.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>

#include <stdexec/execution.hpp>

#include <exception>
#include <memory>
#include <optional>
#include <utility>
namespace clash_native::transport::shadowsocks {

// A Shadowsocks byte carrier that can be backed by a raw TCP socket or by a
// higher-level stream such as TLS or WebSocket. The cipher/framing layer only
// depends on this small contract and therefore does not need to know which
// transport plugin established the connection.
class StreamCarrier final : public std::enable_shared_from_this<StreamCarrier> {
  public:
    explicit StreamCarrier(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
        : socket_(std::move(socket)) {}

    explicit StreamCarrier(std::unique_ptr<io::StreamHandle> stream)
        : stream_(std::shared_ptr<io::StreamHandle>(std::move(stream))) {}

    explicit StreamCarrier(std::shared_ptr<io::StreamHandle> stream) : stream_(std::move(stream)) {}

    // Sender-native exterior: the cipher layers pull/push through here
    // regardless of which backing leg the carrier was built over.
    io::AnySender<std::optional<std::size_t>> async_read_some(boost::asio::mutable_buffer buffer) {
        if (stream_) {
            return stream_->async_read_some(buffer);
        }
        // use_sender drives the socket initiation directly; the stop token
        // wires to Asio cancellation and system_errors translate below.
        auto socket = socket_;
        return io::AnySender<std::optional<std::size_t>>{
            socket->async_read_some(buffer, exec::asio::use_sender) |
            stdexec::then([](std::size_t count) { return std::optional<std::size_t>(count); }) |
            stdexec::let_error([](std::exception_ptr error) -> decltype(stdexec::just(
                                                                std::optional<std::size_t>())) {
                try {
                    std::rethrow_exception(error);
                } catch (const boost::system::system_error &failure) {
                    if (failure.code() == boost::asio::error::eof) {
                        return stdexec::just(std::optional<std::size_t>());
                    }
                    std::rethrow_exception(std::make_exception_ptr(core::Error{
                        core::ErrorCode::transport_io, "carrier read",
                        std::error_code(failure.code().value(), std::system_category())}));
                }
                std::rethrow_exception(error);
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) {
        if (stream_) {
            return stream_->async_write(buffer);
        }
        auto socket = socket_;
        return io::AnySender<std::size_t>{
            boost::asio::async_write(*socket, buffer, exec::asio::use_sender) |
            stdexec::then([](std::size_t count) { return count; }) |
            stdexec::let_error(
                [](std::exception_ptr error) -> decltype(stdexec::just(std::size_t(0))) {
                    try {
                        std::rethrow_exception(error);
                    } catch (const boost::system::system_error &failure) {
                        std::rethrow_exception(std::make_exception_ptr(core::Error{
                            core::ErrorCode::transport_io, "carrier write",
                            std::error_code(failure.code().value(), std::system_category())}));
                    }
                    std::rethrow_exception(error);
                })};
    }

    boost::asio::any_io_executor executor() noexcept {
        if (stream_) {
            return stream_->executor();
        }
        return socket_->get_executor();
    }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        if (stream_) {
            return stream_->local_endpoint(error);
        }
        return socket_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        if (stream_) {
            stream_->shutdown_send(error);
        } else {
            socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_send, error);
        }
    }

    void close() noexcept {
        if (stream_) {
            stream_->close();
        }
        if (!stream_) {
            boost::system::error_code ignored;
            socket_->cancel(ignored);
            socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
            socket_->close(ignored);
        }
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket() const noexcept { return socket_; }

  private:
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::shared_ptr<io::StreamHandle> stream_;
};

} // namespace clash_native::transport::shadowsocks
