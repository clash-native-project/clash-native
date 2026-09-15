#include <clash_native/proxy/tcp_relay.hpp>

#include <boost/asio/error.hpp>

#include <chrono>
#include <utility>

namespace clash_native::proxy {

namespace {

constexpr auto kRelayIdleTimeout = std::chrono::minutes(5);

} // namespace

std::shared_ptr<TcpRelay> TcpRelay::start(std::unique_ptr<core::StreamHandle> left,
                                          std::unique_ptr<core::StreamHandle> right,
                                          CompletionHandler handler,
                                          std::vector<std::uint8_t> initial_left_data) {
    auto relay = std::shared_ptr<TcpRelay>(
        new TcpRelay(std::move(left), std::move(right), std::move(handler)));
    relay->start_impl(std::move(initial_left_data));
    return relay;
}

TcpRelay::TcpRelay(std::unique_ptr<core::StreamHandle> left,
                   std::unique_ptr<core::StreamHandle> right, CompletionHandler handler)
    : left_(std::move(left)), right_(std::move(right)), idle_timer_(left_->executor()),
      completion_handler_(std::move(handler)) {}

void TcpRelay::start_impl(std::vector<std::uint8_t> initial_left_data) {
    initial_left_data_ = std::move(initial_left_data);
    reset_idle_timer();
    if (initial_left_data_.empty()) {
        read_left();
    } else {
        write_initial_left_data();
    }
    read_right();
}

void TcpRelay::stop() noexcept { finish(); }

void TcpRelay::reset_idle_timer() {
    if (finished_) {
        return;
    }

    idle_timer_.expires_after(kRelayIdleTimeout);
    auto self = shared_from_this();
    idle_timer_.async_wait([self](const boost::system::error_code &error) {
        if (!error) {
            self->finish();
        }
    });
}

void TcpRelay::read_left() {
    if (finished_ || left_read_closed_) {
        return;
    }

    auto self = shared_from_this();
    left_->async_read_some(
        boost::asio::buffer(left_buffer_),
        [self](const boost::system::error_code &error, std::size_t size) {
            if (self->finished_) {
                return;
            }
            if (error) {
                if (error == boost::asio::error::eof) {
                    self->left_read_closed_ = true;
                    boost::system::error_code ignored;
                    self->right_->shutdown_send(ignored);
                    self->maybe_finish();
                } else {
                    self->finish();
                }
                return;
            }

            self->reset_idle_timer();

            auto payload = std::make_shared<std::vector<std::uint8_t>>(
                self->left_buffer_.begin(), self->left_buffer_.begin() + size);
            self->right_->async_write(
                boost::asio::buffer(*payload),
                [self, payload](const boost::system::error_code &write_error, std::size_t written) {
                    if (self->finished_) {
                        return;
                    }
                    if (write_error) {
                        self->finish();
                        return;
                    }
                    self->reset_idle_timer();
                    self->stats_.left_to_right_bytes += written;
                    self->read_left();
                });
        });
}

void TcpRelay::read_right() {
    if (finished_ || right_read_closed_) {
        return;
    }

    auto self = shared_from_this();
    right_->async_read_some(
        boost::asio::buffer(right_buffer_),
        [self](const boost::system::error_code &error, std::size_t size) {
            if (self->finished_) {
                return;
            }
            if (error) {
                if (error == boost::asio::error::eof) {
                    self->right_read_closed_ = true;
                    boost::system::error_code ignored;
                    self->left_->shutdown_send(ignored);
                    self->maybe_finish();
                } else {
                    self->finish();
                }
                return;
            }

            self->reset_idle_timer();

            auto payload = std::make_shared<std::vector<std::uint8_t>>(
                self->right_buffer_.begin(), self->right_buffer_.begin() + size);
            self->left_->async_write(
                boost::asio::buffer(*payload),
                [self, payload](const boost::system::error_code &write_error, std::size_t written) {
                    if (self->finished_) {
                        return;
                    }
                    if (write_error) {
                        self->finish();
                        return;
                    }
                    self->reset_idle_timer();
                    self->stats_.right_to_left_bytes += written;
                    self->read_right();
                });
        });
}

void TcpRelay::write_initial_left_data() {
    auto self = shared_from_this();
    right_->async_write(boost::asio::buffer(initial_left_data_),
                        [self](const boost::system::error_code &error, std::size_t written) {
                            if (self->finished_) {
                                return;
                            }
                            if (error) {
                                self->finish();
                                return;
                            }
                            self->reset_idle_timer();
                            self->stats_.left_to_right_bytes += written;
                            self->initial_left_data_.clear();
                            self->read_left();
                        });
}

void TcpRelay::maybe_finish() noexcept {
    if (left_read_closed_ && right_read_closed_) {
        finish();
    }
}

void TcpRelay::finish() noexcept {
    if (finished_) {
        return;
    }
    finished_ = true;

    boost::system::error_code ignored;
    idle_timer_.cancel();

    if (left_) {
        left_->close();
    }
    if (right_) {
        right_->close();
    }

    if (completion_handler_) {
        auto handler = std::move(completion_handler_);
        handler(stats_);
    }
}

} // namespace clash_native::proxy
