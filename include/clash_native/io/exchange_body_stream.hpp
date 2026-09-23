#pragma once

// Shared response-body queue for the HTTP sessions: buffers DATA until the
// consumer pulls it. HTTP/2 and HTTP/3 wire flow-control credit is returned
// by on_consume, so a slow consumer also applies backpressure to the peer.
// Pulls are sender-native (empty means EOF, trailers() is then valid);
// the parking machinery underneath stays callback-based.

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/core/error.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/sender.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>

#include <stdexec/execution.hpp>

#include <algorithm>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace clash_native::io::detail {

class QueuedExchangeBodyStream final
    : public ExchangeBodyStream,
      public std::enable_shared_from_this<QueuedExchangeBodyStream> {
  public:
    using Executor = boost::asio::any_io_executor;
    using Action = std::function<void()>;
    using ConsumeHandler = std::function<void(std::size_t)>;
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    QueuedExchangeBodyStream(Executor executor, std::size_t capacity, ConsumeHandler on_consume,
                             Action on_cancel, Action on_drained)
        : executor_(std::move(executor)), capacity_(capacity), on_consume_(std::move(on_consume)),
          on_cancel_(std::move(on_cancel)), on_drained_(std::move(on_drained)) {}

    AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
            [self = shared_from_this(), buffer](auto terminal) mutable {
                self->read_some(buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{size});
                    return;
                }
                if (error == boost::asio::error::eof) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{});
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(std::move(receiver), std::make_exception_ptr(core::Error{
                                                            core::ErrorCode::transport_io,
                                                            "exchange body read failed", error}));
            })};
    }

    std::vector<ExchangeField> trailers() const override {
        std::lock_guard lock(trailers_mutex_);
        return trailers_;
    }

    void cancel() noexcept override {
        const auto self = shared_from_this();
        boost::asio::post(executor_, [self] {
            if (self->drained_signalled_ || self->cancelled_) {
                return;
            }
            self->cancelled_ = true;
            self->terminal_ = true;
            self->terminal_error_ = boost::asio::error::operation_aborted;
            self->chunks_.clear();
            self->queued_bytes_ = 0;
            if (self->on_cancel_) {
                self->on_cancel_();
            }
            if (self->read_handler_) {
                auto handler = std::move(self->read_handler_);
                self->read_buffer_ = {};
                self->post_read(std::move(handler), self->terminal_error_, 0);
            }
        });
    }

    // Owner-executor operations called by the HTTP/2 or HTTP/3 session.
    bool receive(const std::uint8_t *data, std::size_t size) {
        if (terminal_ || size > capacity_ - std::min(queued_bytes_, capacity_)) {
            return false;
        }
        if (size == 0) {
            return true;
        }
        std::vector<std::uint8_t> chunk(data, data + size);
        queued_bytes_ += size;
        chunks_.push_back(std::move(chunk));
        if (read_handler_) {
            auto handler = std::move(read_handler_);
            const auto buffer = read_buffer_;
            read_buffer_ = {};
            deliver(buffer, std::move(handler));
        }
        return true;
    }

    void finish(std::vector<ExchangeField> trailers) {
        if (terminal_) {
            return;
        }
        terminal_ = true;
        terminal_error_ = boost::asio::error::eof;
        {
            std::lock_guard lock(trailers_mutex_);
            trailers_ = std::move(trailers);
        }
        if (chunks_.empty() && read_handler_) {
            auto handler = std::move(read_handler_);
            read_buffer_ = {};
            finish_read(std::move(handler));
        }
    }

    void fail(boost::system::error_code error) {
        if (terminal_) {
            return;
        }
        terminal_ = true;
        terminal_error_ = error ? error : boost::asio::error::connection_reset;
        chunks_.clear();
        queued_bytes_ = 0;
        if (read_handler_) {
            auto handler = std::move(read_handler_);
            read_buffer_ = {};
            post_read(std::move(handler), terminal_error_, 0);
        }
    }

  private:
    void read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        const auto self = shared_from_this();
        boost::asio::dispatch(executor_, [self, buffer, handler = std::move(handler)]() mutable {
            if (!handler) {
                return;
            }
            if (buffer.size() == 0) {
                self->post_read(std::move(handler), {}, 0);
                return;
            }
            if (self->read_handler_) {
                self->post_read(std::move(handler), boost::asio::error::already_started, 0);
                return;
            }
            if (!self->chunks_.empty()) {
                self->deliver(buffer, std::move(handler));
                return;
            }
            if (self->terminal_) {
                self->finish_read(std::move(handler));
                return;
            }
            self->read_buffer_ = buffer;
            self->read_handler_ = std::move(handler);
        });
    }

    void deliver(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        if (chunks_.empty()) {
            finish_read(std::move(handler));
            return;
        }
        auto &front = chunks_.front();
        const auto amount = std::min(buffer.size(), front.size() - front_offset_);
        const auto copied = boost::asio::buffer_copy(
            buffer, boost::asio::buffer(front.data() + front_offset_, amount));
        front_offset_ += copied;
        queued_bytes_ -= copied;
        if (front_offset_ == front.size()) {
            chunks_.pop_front();
            front_offset_ = 0;
        }
        if (copied != 0 && on_consume_) {
            const auto consume = on_consume_;
            boost::asio::post(executor_, [consume, copied] { consume(copied); });
        }
        post_read(std::move(handler), {}, copied);
        if (chunks_.empty() && terminal_) {
            signal_drained();
        }
    }

    void finish_read(ReadHandler handler) {
        const auto error = terminal_error_ ? terminal_error_ : boost::asio::error::eof;
        post_read(std::move(handler), error, 0);
        if (error == boost::asio::error::eof) {
            signal_drained();
        }
    }

    void signal_drained() {
        if (drained_signalled_) {
            return;
        }
        drained_signalled_ = true;
        if (on_drained_) {
            const auto drained = on_drained_;
            boost::asio::post(executor_, drained);
        }
    }

    void post_read(ReadHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    Executor executor_;
    std::size_t capacity_;
    ConsumeHandler on_consume_;
    Action on_cancel_;
    Action on_drained_;
    std::deque<std::vector<std::uint8_t>> chunks_;
    std::size_t queued_bytes_ = 0;
    std::size_t front_offset_ = 0;
    boost::asio::mutable_buffer read_buffer_;
    ReadHandler read_handler_;
    boost::system::error_code terminal_error_;
    bool terminal_ = false;
    bool drained_signalled_ = false;
    bool cancelled_ = false;
    mutable std::mutex trailers_mutex_;
    std::vector<ExchangeField> trailers_;
};

} // namespace clash_native::io::detail
