#include <clash_native/transport/kcp_client.hpp>

#include <ikcp.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
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
    KcpStreamState(std::unique_ptr<core::DatagramHandle> datagram,
                   boost::asio::ip::udp::endpoint remote_endpoint, KcpClientOptions options,
                   ikcpcb *kcp)
        : datagram_(std::move(datagram)), remote_endpoint_(std::move(remote_endpoint)),
          options_(options), kcp_(kcp), timer_(datagram_->executor()) {}

    ~KcpStreamState() { close(); }

    void start() {
        start_receive();
        schedule_update();
    }

    void async_read_some(boost::asio::mutable_buffer buffer,
                         core::StreamHandle::ReadHandler handler) {
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

    void async_write(boost::asio::const_buffer buffer, core::StreamHandle::WriteHandler handler) {
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

    boost::asio::any_io_executor executor() noexcept { return datagram_->executor(); }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        error = boost::asio::error::operation_not_supported;
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        error = boost::asio::error::operation_not_supported;
    }

    void close() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        boost::system::error_code ignored;
        timer_.cancel();
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
        state->send_queue_.push_back(std::make_shared<std::vector<std::uint8_t>>(
            reinterpret_cast<const std::uint8_t *>(data),
            reinterpret_cast<const std::uint8_t *>(data) + length));
        state->pump_output();
        return 0;
    }

  private:
    void start_receive() {
        if (closed_) {
            return;
        }
        auto self = shared_from_this();
        datagram_->async_receive_from(
            boost::asio::buffer(receive_buffer_),
            [self](const boost::system::error_code &error, std::size_t size,
                   core::DatagramAddress sender) {
                if (self->closed_) {
                    return;
                }
                if (error) {
                    self->fail(error);
                    return;
                }
                if (!sender.is_address() || sender.address() != self->remote_endpoint_.address() ||
                    sender.port() != self->remote_endpoint_.port()) {
                    self->start_receive();
                    return;
                }
                if (ikcp_input(self->kcp_,
                               reinterpret_cast<const char *>(self->receive_buffer_.data()),
                               static_cast<long>(size)) < 0) {
                    self->start_receive();
                    return;
                }
                self->deliver_read();
                self->update_now();
                self->start_receive();
            });
    }

    void schedule_update() {
        if (closed_) {
            return;
        }
        timer_.expires_after(std::chrono::milliseconds(options_.interval_ms));
        auto self = shared_from_this();
        timer_.async_wait([self](const boost::system::error_code &error) {
            if (error || self->closed_) {
                return;
            }
            self->update_now();
            self->schedule_update();
        });
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
        auto packet = send_queue_.front();
        auto self = shared_from_this();
        datagram_->async_send_to(
            boost::asio::buffer(*packet), core::DatagramAddress::from_endpoint(remote_endpoint_),
            [self, packet](const boost::system::error_code &error, std::size_t) {
                self->send_in_progress_ = false;
                if (self->closed_) {
                    return;
                }
                if (error) {
                    self->fail(error);
                    return;
                }
                if (!self->send_queue_.empty()) {
                    self->send_queue_.pop_front();
                }
                self->pump_output();
            });
    }

    void deliver_read() {
        if (closed_ || !read_handler_ || kcp_ == nullptr || read_buffer_.size() > INT_MAX) {
            return;
        }
        const auto result = ikcp_recv(kcp_, static_cast<char *>(read_buffer_.data()),
                                      static_cast<int>(read_buffer_.size()));
        if (result >= 0) {
            finish_read({}, static_cast<std::size_t>(result));
        }
    }

    void fail(const boost::system::error_code &error) {
        if (closed_) {
            return;
        }
        closed_ = true;
        boost::system::error_code ignored;
        timer_.cancel();
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

    void post_read(core::StreamHandle::ReadHandler handler, const boost::system::error_code &error,
                   std::size_t size) {
        boost::asio::post(executor(), [handler = std::move(handler), error, size]() mutable {
            handler(error, size);
        });
    }

    void post_write(core::StreamHandle::WriteHandler handler,
                    const boost::system::error_code &error, std::size_t size) {
        boost::asio::post(executor(), [handler = std::move(handler), error, size]() mutable {
            handler(error, size);
        });
    }

    std::unique_ptr<core::DatagramHandle> datagram_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    KcpClientOptions options_;
    ikcpcb *kcp_ = nullptr;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    boost::asio::steady_timer timer_;
    std::array<std::uint8_t, kMaximumDatagramSize> receive_buffer_{};
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>> send_queue_;
    boost::asio::mutable_buffer read_buffer_;
    core::StreamHandle::ReadHandler read_handler_;
    core::StreamHandle::WriteHandler write_handler_;
    std::size_t write_size_ = 0;
    bool send_in_progress_ = false;
    bool closed_ = false;
};

class KcpStream final : public core::StreamHandle {
  public:
    explicit KcpStream(std::shared_ptr<KcpStreamState> state) : state_(std::move(state)) {}

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
    std::shared_ptr<KcpStreamState> state_;
};

core::Error configuration_error(const char *message) {
    return {core::ErrorCode::configuration, message, {}};
}

} // namespace

core::Result<std::unique_ptr<core::StreamHandle>>
make_kcp_client_stream(std::unique_ptr<core::DatagramHandle> datagram,
                       boost::asio::ip::udp::endpoint remote_endpoint, KcpClientOptions options) {
    if (!datagram) {
        return core::fail(configuration_error("KCP stream requires a datagram handle"));
    }
    if (options.conversation_id == 0 || options.mtu <= kKcpOverhead ||
        options.mtu > static_cast<int>(kMaximumDatagramSize) || options.send_window <= 0 ||
        options.receive_window <= 0 || options.interval_ms <= 0 || options.interval_ms > 1000 ||
        options.nodelay < 0 || options.fast_resend < 0 ||
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
    return std::unique_ptr<core::StreamHandle>(std::make_unique<KcpStream>(std::move(state)));
}

} // namespace clash_native::transport
