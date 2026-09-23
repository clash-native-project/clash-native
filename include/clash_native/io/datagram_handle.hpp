#pragma once

#include <clash_native/io/address.hpp>
#include <clash_native/io/sender.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>

#include <cstddef>
#include <memory>

namespace clash_native::io {

// One received datagram: its payload size within the caller's buffer plus the
// source address (which may carry a domain name).
struct DatagramPacket {
    std::size_t size = 0;
    DatagramAddress address;
};

// Datagram handle. Same completion contract
// as StreamHandle: set_value(T) on success, set_error(exception_ptr) carrying
// a core::Error on failure, set_stopped() on cancellation. Datagrams have no
// EOF: closing the handle aborts outstanding operations (surfaced as
// set_stopped when the operation is destroyed, set_error otherwise).
// At most one outstanding send and one outstanding receive per handle.
class DatagramHandle {
  public:
    // Sends one datagram. Completes set_value(size_t) with the byte count.
    virtual AnySender<std::size_t> async_send_to(boost::asio::const_buffer buffer,
                                                 DatagramAddress destination) = 0;

    // Receives one datagram. The buffer must fit the packet; truncation is
    // reported as an error (message_size), mirroring Asio semantics.
    virtual AnySender<DatagramPacket> async_receive_from(boost::asio::mutable_buffer buffer) = 0;

    virtual boost::asio::any_io_executor executor() noexcept = 0;
    virtual std::size_t max_datagram_size() const noexcept { return 65507; }
    virtual void cancel() noexcept = 0;
    virtual void close() noexcept = 0;

    virtual ~DatagramHandle() = default;
};

} // namespace clash_native::io
