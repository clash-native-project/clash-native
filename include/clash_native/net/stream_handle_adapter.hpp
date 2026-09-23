#pragma once

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/core/outbound.hpp>
#include <clash_native/io/stream_handle.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>

#include <exception>
#include <memory>
#include <optional>
#include <utility>

namespace clash_native::net {

// Unpacks a sender error back into an error_code: core::Error failures
// surface through their preserved cause (mirroring the to_std_error
// conversion used at creation), anything else becomes a generic fault.
// End-of-stream never passes through here (callers map it to eof first).
inline boost::system::error_code unpack_error(std::exception_ptr error) noexcept {
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

// Translates an Asio-style (error_code, size) completion into the
// io::StreamHandle terminal contract: bytes as value, clean EOF as empty,
// anything else as core::Error. Shared by sender-based handle
// implementations so the mapping stays uniform.
template <class Rcvr>
void translate_read(Rcvr &&receiver, const boost::system::error_code &error, std::size_t count,
                    const char *what) {
    if (!error) {
        stdexec::set_value(std::move(receiver), std::optional<std::size_t>(count));
    } else if (error == boost::asio::error::eof) {
        stdexec::set_value(std::move(receiver), std::optional<std::size_t>());
    } else {
        stdexec::set_error(std::move(receiver),
                           std::make_exception_ptr(core::Error{
                               core::ErrorCode::transport_io, what,
                               std::error_code(error.value(), std::system_category())}));
    }
}

template <class Rcvr>
void translate_write(Rcvr &&receiver, const boost::system::error_code &error, std::size_t count,
                     const char *what) {
    if (!error) {
        stdexec::set_value(std::move(receiver), count);
    } else {
        stdexec::set_error(std::move(receiver),
                           std::make_exception_ptr(core::Error{
                               core::ErrorCode::transport_io, what,
                               std::error_code(error.value(), std::system_category())}));
    }
}

// Starts an io:: read pull from handler-style code, translating the terminal
// back into an (error_code, size) call: bytes as success, clean end as eof,
// failures unpacked, cancellation as aborted.
template <class Sender, class Handler>
void start_read_for_handler(Sender &&sender, Handler &&handler) {
    struct Receiver {
        std::decay_t<Handler> handler;
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
    async::start_with_receiver(std::forward<Sender>(sender),
                               Receiver{std::forward<Handler>(handler)});
}

// Starts an io:: write pull from handler-style code. Same contract as above,
// without an end-of-stream mapping (writes have none).
template <class Sender, class Handler>
void start_write_for_handler(Sender &&sender, Handler &&handler) {
    struct Receiver {
        std::decay_t<Handler> handler;
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
    async::start_with_receiver(std::forward<Sender>(sender),
                               Receiver{std::forward<Handler>(handler)});
}

// Adapts an io:: stream handle to the Asio read/write stream concepts.
class StreamHandleAdapter final {
  public:
    using executor_type = boost::asio::any_io_executor;
    using lowest_layer_type = StreamHandleAdapter;

    explicit StreamHandleAdapter(std::unique_ptr<io::StreamHandle> handle)
        : handle_(std::move(handle)) {}

    executor_type get_executor() const noexcept { return handle_->executor(); }

    lowest_layer_type &lowest_layer() noexcept { return *this; }
    const lowest_layer_type &lowest_layer() const noexcept { return *this; }

    template <typename Handler>
    void async_read_some(boost::asio::mutable_buffer buffer, Handler &&handler) {
        read_some(handle_, buffer, std::forward<Handler>(handler));
    }

    template <typename Handler>
    void async_write_some(boost::asio::const_buffer buffer, Handler &&handler) {
        write_some(handle_, buffer, std::forward<Handler>(handler));
    }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        return handle_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept { handle_->shutdown_send(error); }

    void close() noexcept {
        if (handle_) {
            handle_->close();
        }
    }

    std::unique_ptr<io::StreamHandle> release() noexcept { return std::move(handle_); }

  private:
    // Drives the sender to completion on the heap and translates the
    // terminal signal back into a handler call. End-of-stream surfaces as
    // eof (Asio convention); core::Error failures surface through their
    // preserved error_code, falling back to fault when absent.
    template <typename Handler>
    static void read_some(std::unique_ptr<io::StreamHandle> &handle,
                          boost::asio::mutable_buffer buffer, Handler &&handler) {
        struct Receiver {
            using receiver_concept = stdexec::receiver_tag;
            std::decay_t<Handler> handler;
            boost::asio::mutable_buffer buffer;

            void set_value(std::optional<std::size_t> count) && noexcept {
                auto callback = std::move(handler);
                if (count) {
                    callback(boost::system::error_code{}, *count);
                } else {
                    callback(boost::asio::error::eof, 0);
                }
            }

            void set_error(std::exception_ptr error) && noexcept {
                auto callback = std::move(handler);
                callback(unpack_error(error), 0);
            }

            void set_stopped() && noexcept {
                auto callback = std::move(handler);
                callback(boost::asio::error::operation_aborted, 0);
            }
        };
        async::start_with_receiver(handle->async_read_some(buffer),
                                   Receiver{std::forward<Handler>(handler), buffer});
    }

    template <typename Handler>
    static void write_some(std::unique_ptr<io::StreamHandle> &handle,
                           boost::asio::const_buffer buffer, Handler &&handler) {
        struct Receiver {
            using receiver_concept = stdexec::receiver_tag;
            std::decay_t<Handler> handler;

            void set_value(std::size_t count) && noexcept {
                auto callback = std::move(handler);
                callback(boost::system::error_code{}, count);
            }

            void set_error(std::exception_ptr error) && noexcept {
                auto callback = std::move(handler);
                callback(unpack_error(error), 0);
            }

            void set_stopped() && noexcept {
                auto callback = std::move(handler);
                callback(boost::asio::error::operation_aborted, 0);
            }
        };
        async::start_with_receiver(handle->async_write(buffer),
                                   Receiver{std::forward<Handler>(handler)});
    }

    std::unique_ptr<io::StreamHandle> handle_;
};

} // namespace clash_native::net
