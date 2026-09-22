#pragma once

#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/core/outbound.hpp>
#include <clash_native/io/stream_handle.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>

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

    void async_read_some(boost::asio::mutable_buffer buffer,
                         core::StreamHandle::ReadHandler handler) {
        if (stream_) {
            drive_read(stream_, buffer, std::move(handler));
            return;
        }
        if (legacy_stream_) {
            legacy_stream_->async_read_some(buffer, std::move(handler));
            return;
        }
        socket_->async_read_some(buffer, std::move(handler));
    }

    void async_write(boost::asio::const_buffer buffer, core::StreamHandle::WriteHandler handler) {
        if (stream_) {
            drive_write(stream_, buffer, std::move(handler));
            return;
        }
        if (legacy_stream_) {
            legacy_stream_->async_write(buffer, std::move(handler));
            return;
        }
        boost::asio::async_write(*socket_, buffer, std::move(handler));
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
    // Drives a sender-based handle to completion on the heap, translating the
    // terminal back into the legacy handler call. Unqualified completions:
    // the erased sender invokes the receiver as an lvalue.
    static void drive_read(const std::shared_ptr<io::StreamHandle> &stream,
                           boost::asio::mutable_buffer buffer,
                           core::StreamHandle::ReadHandler handler) {
        struct Receiver {
            core::StreamHandle::ReadHandler handler;
            void set_value(std::optional<std::size_t> count) noexcept {
                if (count) {
                    std::move(handler)(boost::system::error_code{}, *count);
                } else {
                    std::move(handler)(boost::asio::error::eof, std::size_t{0});
                }
            }
            void set_error(std::exception_ptr error) noexcept {
                std::move(handler)(unpack_error(std::move(error)), std::size_t{0});
            }
            void set_stopped() noexcept {
                std::move(handler)(boost::asio::error::operation_aborted, std::size_t{0});
            }
        };
        async::start_with_receiver(stream->async_read_some(buffer), Receiver{std::move(handler)});
    }

    static void drive_write(const std::shared_ptr<io::StreamHandle> &stream,
                            boost::asio::const_buffer buffer,
                            core::StreamHandle::WriteHandler handler) {
        struct Receiver {
            core::StreamHandle::WriteHandler handler;
            void set_value(std::size_t count) noexcept {
                std::move(handler)(boost::system::error_code{}, count);
            }
            void set_error(std::exception_ptr error) noexcept {
                std::move(handler)(unpack_error(std::move(error)), std::size_t{0});
            }
            void set_stopped() noexcept {
                std::move(handler)(boost::asio::error::operation_aborted, std::size_t{0});
            }
        };
        async::start_with_receiver(stream->async_write(buffer), Receiver{std::move(handler)});
    }

    static boost::system::error_code unpack_error(std::exception_ptr error) noexcept {
        try {
            std::rethrow_exception(std::move(error));
        } catch (const core::Error &failure) {
            if (failure.cause) {
                return {failure.cause.value(), boost::system::system_category()};
            }
            return boost::asio::error::fault;
        } catch (...) {
            return boost::asio::error::fault;
        }
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::shared_ptr<io::StreamHandle> stream_;
    // Transitional: carriers built over not-yet-migrated core:: streams
    // (mux pool, kcptun). Deleted when those paths migrate.
    std::shared_ptr<core::StreamHandle> legacy_stream_;
};

} // namespace clash_native::transport::shadowsocks
