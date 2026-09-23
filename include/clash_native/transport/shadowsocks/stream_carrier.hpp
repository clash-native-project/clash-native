#pragma once

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/core/outbound.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

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

    explicit StreamCarrier(std::unique_ptr<core::StreamHandle> stream)
        : legacy_stream_(std::shared_ptr<core::StreamHandle>(std::move(stream))) {}

    explicit StreamCarrier(std::shared_ptr<core::StreamHandle> stream)
        : legacy_stream_(std::move(stream)) {}

    explicit StreamCarrier(std::unique_ptr<io::StreamHandle> stream)
        : stream_(std::shared_ptr<io::StreamHandle>(std::move(stream))) {}

    explicit StreamCarrier(std::shared_ptr<io::StreamHandle> stream) : stream_(std::move(stream)) {}

    // Sender-native exterior: the cipher layers pull/push through here
    // regardless of which backing leg the carrier was built over. Legs that
    // still speak callbacks are bridged per operation; the core:: leg dies
    // with the mux-fed paths.
    io::AnySender<std::optional<std::size_t>> async_read_some(boost::asio::mutable_buffer buffer) {
        if (stream_) {
            return stream_->async_read_some(buffer);
        }
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        if (legacy_stream_) {
            auto legacy = legacy_stream_;
            return io::AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
                [legacy, buffer](auto terminal) mutable {
                    legacy->async_read_some(buffer, std::move(terminal));
                },
                [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                    net::translate_read(std::move(receiver), error, size, "carrier read");
                })};
        }
        auto socket = socket_;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
            [socket, buffer](auto terminal) mutable {
                socket->async_read_some(buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                net::translate_read(std::move(receiver), error, size, "carrier read");
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) {
        if (stream_) {
            return stream_->async_write(buffer);
        }
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        if (legacy_stream_) {
            auto legacy = legacy_stream_;
            return io::AnySender<std::size_t>{async::callback_sender<Signatures>(
                [legacy, buffer](auto terminal) mutable {
                    legacy->async_write(buffer, std::move(terminal));
                },
                [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                    net::translate_write(std::move(receiver), error, size, "carrier write");
                })};
        }
        auto socket = socket_;
        return io::AnySender<std::size_t>{async::callback_sender<Signatures>(
            [socket, buffer](auto terminal) mutable {
                boost::asio::async_write(*socket, buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                net::translate_write(std::move(receiver), error, size, "carrier write");
            })};
    }

    boost::asio::any_io_executor executor() noexcept {
        if (stream_) {
            return stream_->executor();
        }
        if (legacy_stream_) {
            return legacy_stream_->executor();
        }
        return socket_->get_executor();
    }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        if (stream_) {
            return stream_->local_endpoint(error);
        }
        if (legacy_stream_) {
            return legacy_stream_->local_endpoint(error);
        }
        return socket_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        if (stream_) {
            stream_->shutdown_send(error);
        } else if (legacy_stream_) {
            legacy_stream_->shutdown_send(error);
        } else {
            socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_send, error);
        }
    }

    void close() noexcept {
        if (stream_) {
            stream_->close();
        }
        if (legacy_stream_) {
            legacy_stream_->close();
        }
        if (!stream_ && !legacy_stream_) {
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
    // Transitional: carriers built over not-yet-migrated core:: streams
    // (mux pool, kcptun). Deleted when those paths migrate.
    std::shared_ptr<core::StreamHandle> legacy_stream_;
};

} // namespace clash_native::transport::shadowsocks
