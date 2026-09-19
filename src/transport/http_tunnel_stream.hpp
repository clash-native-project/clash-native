#pragma once

#include <clash_native/core/outbound.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>

#include <algorithm>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace clash_native::transport::detail {

class HttpTunnelStreamState final : public std::enable_shared_from_this<HttpTunnelStreamState> {
  public:
    using Executor = boost::asio::any_io_executor;
    using ReadHandler = core::StreamHandle::ReadHandler;
    using WriteHandler = core::StreamHandle::WriteHandler;
    using WriteFunction = std::function<void(std::vector<std::uint8_t>, WriteHandler)>;
    using Action = std::function<void()>;
    using ConsumeFunction = std::function<void(std::size_t)>;
    using EndpointFunction =
        std::function<boost::asio::ip::tcp::endpoint(boost::system::error_code &)>;

    HttpTunnelStreamState(Executor executor, WriteFunction write, Action shutdown_send,
                          Action close, ConsumeFunction consume, EndpointFunction endpoint = {},
                          std::size_t receive_limit = 256 * 1024)
        : executor_(std::move(executor)), write_(std::move(write)),
          shutdown_send_(std::move(shutdown_send)), close_(std::move(close)),
          consume_(std::move(consume)), endpoint_(std::move(endpoint)),
          receive_limit_(receive_limit) {}

    boost::asio::any_io_executor executor() noexcept { return executor_; }

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        if (buffer.size() == 0) {
            boost::asio::post(executor_,
                              [handler = std::move(handler)]() mutable { handler({}, 0); });
            return;
        }
        const auto self = shared_from_this();
        boost::asio::dispatch(executor_, [self, buffer, handler = std::move(handler)]() mutable {
            if (self->read_handler_) {
                self->post_read(std::move(handler), boost::asio::error::already_started, 0);
                return;
            }
            if (!self->incoming_.empty()) {
                self->deliver_read(buffer, std::move(handler));
                return;
            }
            if (self->read_closed_) {
                self->post_read(std::move(handler), self->read_error_, 0);
                return;
            }
            self->read_buffer_ = buffer;
            self->read_handler_ = std::move(handler);
        });
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) {
        std::vector<std::uint8_t> bytes(buffer.size());
        boost::asio::buffer_copy(boost::asio::buffer(bytes), buffer);
        const auto self = shared_from_this();
        boost::asio::dispatch(
            executor_, [self, bytes = std::move(bytes), handler = std::move(handler)]() mutable {
                if (self->write_handler_ || self->local_closed_ || self->closed_) {
                    self->post_write(std::move(handler), boost::asio::error::operation_aborted, 0);
                    return;
                }
                if (bytes.empty()) {
                    self->post_write(std::move(handler), {}, 0);
                    return;
                }
                self->write_size_ = bytes.size();
                self->write_handler_ = std::move(handler);
                self->write_(std::move(bytes),
                             [self](const boost::system::error_code &error, std::size_t size) {
                                 self->finish_write(error, size);
                             });
            });
    }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        if (endpoint_) {
            return endpoint_(error);
        }
        error = boost::asio::error::operation_not_supported;
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        error.clear();
        if (closed_ || local_closed_) {
            return;
        }
        shutdown_requested_ = true;
        if (!write_handler_) {
            shutdown_requested_ = false;
            local_closed_ = true;
            if (shutdown_send_) {
                shutdown_send_();
            }
        }
    }

    void close() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        local_closed_ = true;
        read_closed_ = true;
        read_error_ = boost::asio::error::operation_aborted;
        if (close_) {
            close_();
        }
        if (read_handler_) {
            auto handler = std::move(read_handler_);
            post_read(std::move(handler), read_error_, 0);
        }
        if (write_handler_) {
            auto handler = std::move(write_handler_);
            post_write(std::move(handler), boost::asio::error::operation_aborted, 0);
        }
        incoming_.clear();
        incoming_offset_ = 0;
        incoming_size_ = 0;
    }

    void receive(const std::uint8_t *data, std::size_t size) {
        if (closed_ || read_closed_ || size == 0) {
            return;
        }
        if (size > receive_limit_ - std::min(incoming_size_, receive_limit_)) {
            fail(boost::asio::error::no_buffer_space);
            return;
        }
        incoming_.emplace_back(data, data + size);
        incoming_size_ += size;
        satisfy_read();
    }

    void remote_close(boost::system::error_code error = boost::asio::error::eof) {
        if (closed_ || read_closed_) {
            return;
        }
        read_closed_ = true;
        read_error_ = error;
        satisfy_read();
    }

    void fail(boost::system::error_code error) {
        if (closed_) {
            return;
        }
        closed_ = true;
        local_closed_ = true;
        read_closed_ = true;
        read_error_ = error ? error : boost::asio::error::operation_aborted;
        if (close_) {
            close_();
        }
        if (read_handler_) {
            auto handler = std::move(read_handler_);
            post_read(std::move(handler), read_error_, 0);
        }
        if (write_handler_) {
            auto handler = std::move(write_handler_);
            post_write(std::move(handler), read_error_, 0);
        }
        incoming_.clear();
        incoming_offset_ = 0;
        incoming_size_ = 0;
    }

  private:
    void satisfy_read() {
        if (!read_handler_) {
            return;
        }
        if (!incoming_.empty()) {
            auto handler = std::move(read_handler_);
            deliver_read(read_buffer_, std::move(handler));
        } else if (read_closed_) {
            auto handler = std::move(read_handler_);
            post_read(std::move(handler), read_error_, 0);
        }
    }

    void deliver_read(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        std::size_t copied = 0;
        while (copied < buffer.size() && !incoming_.empty()) {
            auto &front = incoming_.front();
            const auto available = front.size() - incoming_offset_;
            const auto amount = std::min(buffer.size() - copied, available);
            copied += boost::asio::buffer_copy(
                boost::asio::buffer(static_cast<std::uint8_t *>(buffer.data()) + copied,
                                    buffer.size() - copied),
                boost::asio::buffer(front.data() + incoming_offset_, amount));
            incoming_offset_ += amount;
            incoming_size_ -= amount;
            if (incoming_offset_ == front.size()) {
                incoming_.pop_front();
                incoming_offset_ = 0;
            }
        }
        if (copied != 0 && consume_) {
            consume_(copied);
        }
        post_read(std::move(handler), {}, copied);
    }

    void finish_write(const boost::system::error_code &error, std::size_t size) {
        if (!write_handler_) {
            return;
        }
        auto handler = std::move(write_handler_);
        const auto expected = write_size_;
        write_size_ = 0;
        if (!error && size < expected) {
            post_write(std::move(handler), boost::asio::error::operation_aborted, size);
        } else {
            post_write(std::move(handler), error, size);
        }
        if (shutdown_requested_ && !closed_) {
            shutdown_requested_ = false;
            local_closed_ = true;
            if (shutdown_send_) {
                shutdown_send_();
            }
        }
    }

    void post_read(ReadHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    void post_write(WriteHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    Executor executor_;
    WriteFunction write_;
    Action shutdown_send_;
    Action close_;
    ConsumeFunction consume_;
    EndpointFunction endpoint_;
    const std::size_t receive_limit_;
    std::deque<std::vector<std::uint8_t>> incoming_;
    std::size_t incoming_offset_ = 0;
    std::size_t incoming_size_ = 0;
    boost::asio::mutable_buffer read_buffer_;
    ReadHandler read_handler_;
    WriteHandler write_handler_;
    std::size_t write_size_ = 0;
    boost::system::error_code read_error_;
    bool read_closed_ = false;
    bool local_closed_ = false;
    bool shutdown_requested_ = false;
    bool closed_ = false;
};

class HttpTunnelStream final : public core::StreamHandle {
  public:
    explicit HttpTunnelStream(std::shared_ptr<HttpTunnelStreamState> state)
        : state_(std::move(state)) {}

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        state_->async_read_some(buffer, std::move(handler));
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        state_->async_write(buffer, std::move(handler));
    }

    boost::asio::any_io_executor executor() noexcept override { return state_->executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        return state_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        state_->shutdown_send(error);
    }

    void close() noexcept override { state_->close(); }

  private:
    std::shared_ptr<HttpTunnelStreamState> state_;
};

inline std::unique_ptr<core::StreamHandle>
make_http_tunnel_stream(const std::shared_ptr<HttpTunnelStreamState> &state) {
    return std::make_unique<HttpTunnelStream>(state);
}

} // namespace clash_native::transport::detail
