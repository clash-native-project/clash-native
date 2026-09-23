#pragma once

#include <clash_native/io/sender.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <memory>
#include <optional>

namespace clash_native::io {

// The universal async byte
// stream. Every async operation returns a sender (connected once, completing
// exactly once) instead of taking a callback:
//
//   set_value(T)              - success; see each operation for T.
//   set_error(exception_ptr)  - failure, carrying a core::Error whose cause
//                               preserves the underlying error_code.
//   set_stopped()             - the operation was cancelled (destroyed while
//                               outstanding, or the stop token fired). Handler
//                               style reported this as operation_aborted; it
//                               is never surfaced as an error here.
//
// At most one outstanding read and one outstanding write per handle (the Asio
// stream contract). Completions may arrive on any thread; implementations
// serialize internally as needed. Callers needing a specific executor use
// executor() with starts_on or their own strand.
class StreamHandle {
  public:
    // Reads some bytes into buffer. Completes set_value(optional<size_t>):
    // engaged with the byte count, or disengaged on clean EOF (the relay
    // pattern maps this to shutdown_send on the peer direction).
    virtual AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) = 0;

    // Writes the whole buffer (Asio async_write semantics: full transfer or
    // failure). Completes set_value(size_t) with the byte count.
    virtual AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) = 0;

    virtual boost::asio::any_io_executor executor() noexcept = 0;
    virtual boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept = 0;
    virtual void shutdown_send(boost::system::error_code &error) noexcept = 0;
    virtual void close() noexcept = 0;

    virtual ~StreamHandle() = default;
};

} // namespace clash_native::io
