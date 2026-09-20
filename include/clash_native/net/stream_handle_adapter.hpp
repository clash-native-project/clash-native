#pragma once

#include <clash_native/core/outbound.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>

#include <memory>
#include <utility>

namespace clash_native::net {

// Adapts the project stream contract to the Asio read/write stream concepts.
class StreamHandleAdapter final {
  public:
    using executor_type = boost::asio::any_io_executor;
    using lowest_layer_type = StreamHandleAdapter;

    explicit StreamHandleAdapter(std::unique_ptr<core::StreamHandle> handle)
        : handle_(std::move(handle)) {}

    executor_type get_executor() const noexcept { return handle_->executor(); }

    lowest_layer_type &lowest_layer() noexcept { return *this; }
    const lowest_layer_type &lowest_layer() const noexcept { return *this; }

    void async_read_some(boost::asio::mutable_buffer buffer,
                         core::StreamHandle::ReadHandler handler) {
        handle_->async_read_some(buffer, std::move(handler));
    }

    void async_write_some(boost::asio::const_buffer buffer,
                          core::StreamHandle::WriteHandler handler) {
        handle_->async_write(buffer, std::move(handler));
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

    std::unique_ptr<core::StreamHandle> release() noexcept { return std::move(handle_); }

  private:
    std::unique_ptr<core::StreamHandle> handle_;
};

} // namespace clash_native::net
