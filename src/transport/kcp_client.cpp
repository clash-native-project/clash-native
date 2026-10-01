#include <clash_native/transport/kcp_client.hpp>

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/timer.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include <ikcp.h>

#include <exec/async_scope.hpp>

#include <stdexec/execution.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>

#include <array>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <utility>
#include <vector>

namespace clash_native::transport {

namespace {

constexpr std::size_t kMaximumDatagramSize = 65507;
constexpr int kKcpOverhead = 24;

boost::system::error_code protocol_error() {
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

class KcpStreamState final : public std::enable_shared_from_this<KcpStreamState> {
  public:
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
    using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    KcpStreamState(std::unique_ptr<io::DatagramHandle> datagram,
                   boost::asio::ip::udp::endpoint remote_endpoint, KcpClientOptions options,
                   ikcpcb *kcp)
        : datagram_(std::move(datagram)), remote_endpoint_(std::move(remote_endpoint)),
          options_(std::move(options)), kcp_(kcp), executor_(datagram_->executor()) {
        if (options_.rate_limit > 0) {
            rate_capacity_ = std::max<std::size_t>(
                static_cast<std::size_t>(options_.rate_limit),
                static_cast<std::size_t>(16 * std::max(options_.mtu, kKcpOverhead)));
            rate_tokens_ = rate_capacity_;
        }
    }

    ~KcpStreamState() { close(); }

    void start() {
        scope_.spawn(run_receive_loop(shared_from_this()));
        scope_.spawn(run_update_loop(shared_from_this()));
    }

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        if (closed_) {
            post_read(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (read_handler_) {
            post_read(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_read(std::move(handler), {}, 0);
            return;
        }
        if (buffer.size() > static_cast<std::size_t>(INT_MAX)) {
            post_read(std::move(handler), boost::asio::error::message_size, 0);
            return;
        }

        read_buffer_ = buffer;
        read_handler_ = std::move(handler);
        deliver_read();
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) {
        if (closed_) {
            post_write(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (write_handler_) {
            post_write(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_write(std::move(handler), {}, 0);
            return;
        }
        if (buffer.size() > static_cast<std::size_t>(INT_MAX)) {
            post_write(std::move(handler), boost::asio::error::message_size, 0);
            return;
        }

        write_size_ = buffer.size();
        write_handler_ = std::move(handler);
        const auto *data = static_cast<const char *>(buffer.data());
        const auto max_chunk = std::max<std::size_t>(1, static_cast<std::size_t>(kcp_->mss) * 100);
        for (std::size_t offset = 0; offset < buffer.size();) {
            const auto chunk_size = std::min(buffer.size() - offset, max_chunk);
            const auto result = ikcp_send(kcp_, data + offset, static_cast<int>(chunk_size));
            if (result <= 0) {
                fail(protocol_error());
                return;
            }
            offset += static_cast<std::size_t>(result);
        }
        update_now();
        if (!closed_) {
            finish_write({}, write_size_);
        }
    }
    boost::asio::any_io_executor executor() noexcept { return executor_; }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        error = boost::asio::error::operation_not_supported;
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        error = boost::asio::error::operation_not_supported;
    }

    // Retires a parked read without closing the datagram: the lower
    // receives keep landing in KCP's internal buffers, so dropping the
    // caller buffer ref is safe. Dispatched to the datagram executor
    // because the parked state is strand-private. The late lower
    // completion finds no parked handler and is dropped.
    void cancel_read() noexcept {
        try {
            auto self = shared_from_this();
            boost::asio::dispatch(self->executor(), [self] {
                auto handler = std::move(self->read_handler_);
                if (!handler) {
                    return;
                }
                // Caller buffer ref; the memory belongs to the caller frame.
                self->read_buffer_ = {};
                self->post_read(std::move(handler), boost::asio::error::operation_aborted, 0);
            });
        } catch (...) {
            // Aborter contract: never throw. A parked handler (if any) is
            // retired by the late lower completion or close().
        }
    }

    // Retires a parked write without closing the datagram. The KCP send
    // queue drains on its own; the late completion finds no parked handler
    // and is dropped.
    void cancel_write() noexcept {
        try {
            auto self = shared_from_this();
            boost::asio::dispatch(self->executor(), [self] {
                auto handler = std::move(self->write_handler_);
                if (!handler) {
                    return;
                }
                self->write_size_ = 0;
                self->post_write(std::move(handler), boost::asio::error::operation_aborted, 0);
            });
        } catch (...) {
            // Aborter contract: never throw; see cancel_read.
        }
    }

    void close() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (datagram_) {
            datagram_->cancel();
            datagram_->close();
        }
        if (kcp_) {
            ikcp_release(kcp_);
            kcp_ = nullptr;
        }
        send_queue_.clear();
        finish_read(boost::asio::error::operation_aborted, 0);
        finish_write(boost::asio::error::operation_aborted, 0);
    }

  public:
    static int output(const char *data, int length, ikcpcb *, void *user) {
        auto *state = static_cast<KcpStreamState *>(user);
        if (state == nullptr || state->closed_ || length < 0 ||
            static_cast<std::size_t>(length) > kMaximumDatagramSize) {
            return -1;
        }
        const auto packet = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(data), static_cast<std::size_t>(length));
        std::vector<std::vector<std::uint8_t>> encoded;
        if (state->options_.encode_packet) {
            encoded = state->options_.encode_packet(packet);
        } else {
            encoded.emplace_back(packet.begin(), packet.end());
        }
        for (auto &wire : encoded) {
            if (wire.size() > kMaximumDatagramSize) {
                return -1;
            }
            state->send_queue_.push_back(
                std::make_shared<std::vector<std::uint8_t>>(std::move(wire)));
        }
        state->pump_output();
        return 0;
    }

  private:
    // UDP receive loop: data moves into ikcp inside the loop body; C-library
    // boundary is ikcp_input/ikcp_flush below (thin, no sender wrapping).
    static stdexec::task<void> run_receive_loop(std::shared_ptr<KcpStreamState> self) {
        while (!self->closed_) {
            io::DatagramPacket packet{0, {}};
            std::exception_ptr failure;
            try {
                packet = co_await self->datagram_->async_receive_from(
                    boost::asio::buffer(self->receive_buffer_));
            } catch (...) {
                failure = std::current_exception();
            }
            if (failure) {
                if (self->closed_) {
                    co_return;
                }
                self->fail(unpack_udp_error(failure));
                co_return;
            }
            if (self->closed_) {
                co_return;
            }
            if (!packet.address.is_address() ||
                packet.address.address() != self->remote_endpoint_.address() ||
                packet.address.port() != self->remote_endpoint_.port()) {
                continue;
            }
            const auto wire =
                std::span<const std::uint8_t>(self->receive_buffer_.data(), packet.size);
            std::vector<std::vector<std::uint8_t>> decoded;
            if (self->options_.decode_packet) {
                decoded = self->options_.decode_packet(wire);
            } else {
                decoded.emplace_back(wire.begin(), wire.end());
            }
            for (const auto &payload : decoded) {
                if (payload.empty() ||
                    ikcp_input(self->kcp_, reinterpret_cast<const char *>(payload.data()),
                               static_cast<long>(payload.size())) < 0) {
                    continue;
                }
            }
            if (self->options_.ack_nodelay) {
                ikcp_flush(self->kcp_);
            }
            self->deliver_read();
            self->update_now();
        }
    }

    // ikcp update loop: sleep races close via scope stop/drop; interval is a
    // sender (async::sleep_after), not a steady_timer.async_wait leaf.
    static stdexec::task<void> run_update_loop(std::shared_ptr<KcpStreamState> self) {
        while (!self->closed_) {
            try {
                co_await async::sleep_after(self->executor_,
                                            std::chrono::milliseconds(self->options_.interval_ms));
            } catch (...) {
                co_return;
            }
            if (self->closed_) {
                co_return;
            }
            self->update_now();
        }
    }

    static boost::system::error_code unpack_udp_error(std::exception_ptr error) noexcept {
        try {
            std::rethrow_exception(std::move(error));
        } catch (const core::Error &failure) {
            if (failure.cause) {
                return failure.cause;
            }
        } catch (const boost::system::system_error &failure) {
            return failure.code();
        } catch (...) {
        }
        return boost::asio::error::fault;
    }

    void update_now() {
        if (closed_) {
            return;
        }
        ikcp_update(kcp_, current_millis());
        pump_output();
        deliver_read();
    }

    IUINT32 current_millis() const noexcept {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time_);
        return static_cast<IUINT32>(elapsed.count());
    }

    void pump_output() {
        if (closed_ || send_in_progress_ || send_queue_.empty()) {
            return;
        }
        send_in_progress_ = true;
        // Send chain runs as a task: rate wait is sleep_after; the UDP send
        // is a direct co_await on the datagram sender (cancellable via
        // scope/stop). Thin C boundary: ikcp byte movement stays in output().
        scope_.spawn(run_send_chain(shared_from_this()));
    }

    static stdexec::task<void> run_send_chain(std::shared_ptr<KcpStreamState> self) {
        while (!self->closed_ && !self->send_queue_.empty()) {
            auto packet = self->send_queue_.front();
            if (self->options_.rate_limit > 0) {
                self->refill_rate_tokens();
                if (self->rate_tokens_ < packet->size()) {
                    const auto missing = packet->size() - self->rate_tokens_;
                    const auto micros =
                        (static_cast<std::uint64_t>(missing) * 1'000'000ULL +
                         static_cast<std::uint64_t>(self->options_.rate_limit) - 1ULL) /
                        static_cast<std::uint64_t>(self->options_.rate_limit);
                    try {
                        co_await async::sleep_after(self->executor_,
                                                    std::chrono::microseconds(micros));
                    } catch (...) {
                        self->send_in_progress_ = false;
                        co_return;
                    }
                    continue;
                }
                self->rate_tokens_ -= packet->size();
            }
            std::exception_ptr failure;
            try {
                co_await self->datagram_->async_send_to(
                    boost::asio::buffer(*packet),
                    io::DatagramAddress::from_endpoint(self->remote_endpoint_));
            } catch (...) {
                failure = std::current_exception();
            }
            if (failure) {
                self->send_in_progress_ = false;
                if (!self->closed_) {
                    self->fail(unpack_udp_error(failure));
                }
                co_return;
            }
            if (self->closed_) {
                self->send_in_progress_ = false;
                co_return;
            }
            if (!self->send_queue_.empty()) {
                self->send_queue_.pop_front();
            }
        }
        self->send_in_progress_ = false;
    }

    void refill_rate_tokens() {
        const auto now = std::chrono::steady_clock::now();
        if (rate_last_refill_.time_since_epoch().count() == 0) {
            rate_last_refill_ = now;
        }
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(now - rate_last_refill_);
        if (elapsed.count() > 0) {
            const auto refill =
                static_cast<std::size_t>((static_cast<std::uint64_t>(elapsed.count()) *
                                          static_cast<std::uint64_t>(options_.rate_limit)) /
                                         1'000'000ULL);
            rate_tokens_ = std::min(rate_capacity_, rate_tokens_ + refill);
            rate_last_refill_ = now;
        }
    }

    void deliver_read() {
        if (closed_ || !read_handler_ || kcp_ == nullptr || read_buffer_.size() > INT_MAX) {
            return;
        }
        if (pending_read_offset_ == pending_read_.size()) {
            pending_read_.clear();
            pending_read_offset_ = 0;
        }
        if (!pending_read_.empty()) {
            const auto size =
                std::min(read_buffer_.size(), pending_read_.size() - pending_read_offset_);
            std::memcpy(read_buffer_.data(), pending_read_.data() + pending_read_offset_, size);
            pending_read_offset_ += size;
            finish_read({}, size);
            return;
        }

        const auto peek_size = ikcp_peeksize(kcp_);
        if (peek_size <= 0) {
            return;
        }
        pending_read_.resize(static_cast<std::size_t>(peek_size));
        const auto result =
            ikcp_recv(kcp_, reinterpret_cast<char *>(pending_read_.data()), peek_size);
        if (result < 0) {
            pending_read_.clear();
            pending_read_offset_ = 0;
            return;
        }
        pending_read_.resize(static_cast<std::size_t>(result));
        const auto size = std::min(read_buffer_.size(), pending_read_.size());
        std::memcpy(read_buffer_.data(), pending_read_.data(), size);
        pending_read_offset_ = size;
        finish_read({}, size);
    }

    void fail(const boost::system::error_code &error) {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (datagram_) {
            datagram_->cancel();
            datagram_->close();
        }
        if (kcp_) {
            ikcp_release(kcp_);
            kcp_ = nullptr;
        }
        send_queue_.clear();
        finish_read(error, 0);
        finish_write(error, 0);
    }

    void finish_read(const boost::system::error_code &error, std::size_t size) {
        if (!read_handler_) {
            return;
        }
        auto handler = std::move(read_handler_);
        read_buffer_ = {};
        handler(error, size);
    }

    void finish_write(const boost::system::error_code &error, std::size_t size) {
        if (!write_handler_) {
            return;
        }
        auto handler = std::move(write_handler_);
        write_size_ = 0;
        handler(error, size);
    }

    void post_read(ReadHandler handler, const boost::system::error_code &error, std::size_t size) {
        boost::asio::post(executor(), [handler = std::move(handler), error, size]() mutable {
            handler(error, size);
        });
    }

    void post_write(WriteHandler handler, const boost::system::error_code &error,
                    std::size_t size) {
        boost::asio::post(executor(), [handler = std::move(handler), error, size]() mutable {
            handler(error, size);
        });
    }

    std::unique_ptr<io::DatagramHandle> datagram_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    KcpClientOptions options_;
    ikcpcb *kcp_ = nullptr;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    boost::asio::any_io_executor executor_;
    exec::async_scope scope_;
    std::array<std::uint8_t, kMaximumDatagramSize> receive_buffer_{};
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>> send_queue_;
    boost::asio::mutable_buffer read_buffer_;
    std::vector<std::uint8_t> pending_read_;
    std::size_t pending_read_offset_ = 0;
    ReadHandler read_handler_;
    WriteHandler write_handler_;
    std::size_t write_size_ = 0;
    bool send_in_progress_ = false;
    std::size_t rate_capacity_ = 0;
    std::size_t rate_tokens_ = 0;
    std::chrono::steady_clock::time_point rate_last_refill_{};
    bool closed_ = false;
};

class KcpStream final : public io::StreamHandle {
  public:
    explicit KcpStream(std::shared_ptr<KcpStreamState> state) : state_(std::move(state)) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
            [state = state_, buffer](auto terminal) mutable {
                state->async_read_some(
                    buffer, [terminal = std::move(terminal)](const boost::system::error_code &error,
                                                             std::size_t size) mutable {
                        terminal(error, size);
                    });
                return async::CallbackAbortFn{[state] { state->cancel_read(); }};
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                net::translate_read(std::move(receiver), error, size, "kcp stream read");
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        return io::AnySender<std::size_t>{async::callback_sender<Signatures>(
            [state = state_, buffer](auto terminal) mutable {
                state->async_write(
                    buffer, [terminal = std::move(terminal)](const boost::system::error_code &error,
                                                             std::size_t size) mutable {
                        terminal(error, size);
                    });
                return async::CallbackAbortFn{[state] { state->cancel_write(); }};
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                net::translate_write(std::move(receiver), error, size, "kcp stream write");
            })};
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
    std::shared_ptr<KcpStreamState> state_;
};

core::Error configuration_error(const char *message) {
    return {core::ErrorCode::configuration, message, {}};
}

} // namespace

core::Result<std::unique_ptr<io::StreamHandle>>
make_kcp_client_stream(std::unique_ptr<io::DatagramHandle> datagram,
                       boost::asio::ip::udp::endpoint remote_endpoint, KcpClientOptions options) {
    if (!datagram) {
        return core::fail(configuration_error("KCP stream requires a datagram handle"));
    }
    if (options.conversation_id == 0 || options.mtu <= kKcpOverhead ||
        options.mtu > static_cast<int>(kMaximumDatagramSize) || options.send_window <= 0 ||
        options.receive_window <= 0 || options.interval_ms <= 0 || options.interval_ms > 1000 ||
        options.nodelay < 0 || options.fast_resend < 0 || options.rate_limit < 0 ||
        (options.disable_congestion_control != 0 && options.disable_congestion_control != 1)) {
        return core::fail(configuration_error("invalid KCP stream options"));
    }

    auto *kcp = ikcp_create(options.conversation_id, nullptr);
    if (kcp == nullptr) {
        return core::fail({core::ErrorCode::transport_io, "failed to create KCP state", {}});
    }
    if (ikcp_setmtu(kcp, options.mtu) < 0 ||
        ikcp_wndsize(kcp, options.send_window, options.receive_window) < 0 ||
        ikcp_nodelay(kcp, options.nodelay, options.interval_ms, options.fast_resend,
                     options.disable_congestion_control) < 0) {
        ikcp_release(kcp);
        return core::fail(configuration_error("failed to configure KCP stream"));
    }
    kcp->stream = 1;

    auto state = std::make_shared<KcpStreamState>(std::move(datagram), std::move(remote_endpoint),
                                                  options, kcp);
    kcp->user = state.get();
    ikcp_setoutput(kcp, &KcpStreamState::output);
    state->start();
    return std::unique_ptr<io::StreamHandle>(std::make_unique<KcpStream>(std::move(state)));
}

} // namespace clash_native::transport
