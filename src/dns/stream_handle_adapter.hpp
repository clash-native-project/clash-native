#pragma once

#include <clash_native/core/outbound.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>

#include <memory>

namespace clash_native::dns {

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

    void close() noexcept {
        if (handle_) {
            handle_->close();
        }
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        if (handle_) {
            handle_->shutdown_send(error);
        }
    }

  private:
    std::unique_ptr<core::StreamHandle> handle_;
};

} // namespace clash_native::dns
