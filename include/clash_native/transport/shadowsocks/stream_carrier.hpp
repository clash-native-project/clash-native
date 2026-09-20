#pragma once

#include <clash_native/core/outbound.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>

#include <memory>

namespace clash_native::transport::shadowsocks {

// A Shadowsocks byte carrier that can be backed by a raw TCP socket or by a
// higher-level stream such as TLS or WebSocket. The cipher/framing layer only
// depends on this small contract and therefore does not need to know which
// transport plugin established the connection.
class StreamCarrier final : public std::enable_shared_from_this<StreamCarrier> {
  public:
    explicit StreamCarrier(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
        : socket_(std::move(socket)) {}

    explicit StreamCarrier(std::unique_ptr<core::StreamHandle> stream)
        : stream_(std::shared_ptr<core::StreamHandle>(std::move(stream))) {}

    explicit StreamCarrier(std::shared_ptr<core::StreamHandle> stream)
        : stream_(std::move(stream)) {}

    void async_read_some(boost::asio::mutable_buffer buffer,
                         core::StreamHandle::ReadHandler handler) {
        if (stream_) {
            stream_->async_read_some(buffer, std::move(handler));
            return;
        }
        socket_->async_read_some(buffer, std::move(handler));
    }

    void async_write(boost::asio::const_buffer buffer, core::StreamHandle::WriteHandler handler) {
        if (stream_) {
            stream_->async_write(buffer, std::move(handler));
            return;
        }
        boost::asio::async_write(*socket_, buffer, std::move(handler));
    }

    boost::asio::any_io_executor executor() noexcept {
        return stream_ ? stream_->executor() : socket_->get_executor();
    }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        return stream_ ? stream_->local_endpoint(error) : socket_->local_endpoint(error);
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
            return;
        }
        boost::system::error_code ignored;
        socket_->cancel(ignored);
        socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
        socket_->close(ignored);
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket() const noexcept { return socket_; }

  private:
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::shared_ptr<core::StreamHandle> stream_;
};

} // namespace clash_native::transport::shadowsocks
