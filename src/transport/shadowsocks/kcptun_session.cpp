#include <clash_native/transport/shadowsocks/kcptun_session.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kHeaderSize = 8;
constexpr std::uint8_t kSyn = 0;
constexpr std::uint8_t kFin = 1;
constexpr std::uint8_t kPush = 2;
constexpr std::uint8_t kNop = 3;
constexpr std::uint8_t kUpdate = 4;
constexpr std::size_t kMaximumFrameSize = std::numeric_limits<std::uint16_t>::max();
constexpr std::uint32_t kInitialPeerWindow = 262144;
constexpr auto kScavengePeriod = std::chrono::seconds(5);

boost::system::error_code protocol_error() {
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

boost::system::error_code pool_closed_error() { return boost::asio::error::operation_aborted; }

void put_u16(std::uint8_t *output, std::uint16_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8);
}

void put_u32(std::uint8_t *output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8);
    output[2] = static_cast<std::uint8_t>(value >> 16);
    output[3] = static_cast<std::uint8_t>(value >> 24);
}

std::uint16_t get_u16(const std::uint8_t *input) {
    return static_cast<std::uint16_t>(input[0] | (static_cast<std::uint16_t>(input[1]) << 8));
}

std::uint32_t get_u32(const std::uint8_t *input) {
    return static_cast<std::uint32_t>(input[0]) | (static_cast<std::uint32_t>(input[1]) << 8) |
           (static_cast<std::uint32_t>(input[2]) << 16) |
           (static_cast<std::uint32_t>(input[3]) << 24);
}

class KcptunMuxSession;
class KcptunMuxStreamState;

class KcptunMuxStream final : public core::StreamHandle {
  public:
    explicit KcptunMuxStream(std::shared_ptr<KcptunMuxStreamState> state)
        : state_(std::move(state)) {}
    ~KcptunMuxStream() override;

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override;
    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override;
    boost::asio::any_io_executor executor() noexcept override;
    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override;
    void shutdown_send(boost::system::error_code &error) noexcept override;
    void close() noexcept override;

  private:
    std::shared_ptr<KcptunMuxStreamState> state_;
};

class KcptunMuxSession final : public std::enable_shared_from_this<KcptunMuxSession> {
  public:
    KcptunMuxSession(std::unique_ptr<core::StreamHandle> carrier, KcptunClientOptions options)
        : carrier_(std::move(carrier)), options_(std::move(options)),
          keepalive_timer_(carrier_->executor()) {}

    ~KcptunMuxSession() { close(); }

    void start() {
        read_header();
        schedule_keepalive();
    }

    void async_open_stream(core::StreamOpenHandler handler);
    void enqueue_frame(std::uint8_t command, std::uint32_t stream_id,
                       std::vector<std::uint8_t> payload,
                       std::function<void(const boost::system::error_code &)> completed = {});
    void remove_stream(std::uint32_t stream_id);
    void close_stream(std::uint32_t stream_id);
    void fail(const boost::system::error_code &error);
    void close() noexcept;
    bool closed() const noexcept { return closed_; }
    std::size_t stream_count() const noexcept { return streams_.size(); }
    boost::asio::any_io_executor executor() noexcept { return carrier_->executor(); }

    void register_stream(std::uint32_t stream_id,
                         const std::shared_ptr<KcptunMuxStreamState> &stream) {
        streams_.emplace(stream_id, stream);
    }

  private:
    struct QueuedFrame {
        std::shared_ptr<std::vector<std::uint8_t>> bytes;
        std::function<void(const boost::system::error_code &)> completed;
    };

    using ReadExactHandler = std::function<void(const boost::system::error_code &)>;

    std::vector<std::uint8_t> make_frame(std::uint8_t command, std::uint32_t stream_id,
                                         std::vector<std::uint8_t> payload) const {
        std::vector<std::uint8_t> frame(kHeaderSize + payload.size());
        frame[0] = static_cast<std::uint8_t>(options_.smux_version);
        frame[1] = command;
        put_u16(frame.data() + 2, static_cast<std::uint16_t>(payload.size()));
        put_u32(frame.data() + 4, stream_id);
        std::copy(payload.begin(), payload.end(), frame.begin() + kHeaderSize);
        return frame;
    }

    void pump_write();
    void read_header();
    void read_payload(const std::array<std::uint8_t, kHeaderSize> &header,
                      std::shared_ptr<std::vector<std::uint8_t>> payload);
    void handle_frame(const std::array<std::uint8_t, kHeaderSize> &header,
                      const std::vector<std::uint8_t> &payload);
    void read_exact(boost::asio::mutable_buffer buffer, ReadExactHandler handler,
                    std::size_t offset = 0);
    void schedule_keepalive();

    std::unique_ptr<core::StreamHandle> carrier_;
    KcptunClientOptions options_;
    boost::asio::steady_timer keepalive_timer_;
    std::array<std::uint8_t, kHeaderSize> header_buffer_{};
    std::deque<QueuedFrame> queued_frames_;
    std::unordered_map<std::uint32_t, std::shared_ptr<KcptunMuxStreamState>> streams_;
    std::uint32_t next_stream_id_ = 1;
    bool write_in_progress_ = false;
    bool closed_ = false;
};

class KcptunMuxStreamState final : public std::enable_shared_from_this<KcptunMuxStreamState> {
  public:
    KcptunMuxStreamState(std::shared_ptr<KcptunMuxSession> session, std::uint32_t stream_id,
                         KcptunClientOptions options)
        : session_(std::move(session)), stream_id_(stream_id), options_(std::move(options)) {}

    ~KcptunMuxStreamState() { close(); }

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
        read_buffer_ = buffer;
        read_handler_ = std::move(handler);
        deliver_read();
    }

    void async_write(boost::asio::const_buffer buffer, core::StreamHandle::WriteHandler handler) {
        if (closed_ || local_closed_) {
            post_write(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (write_pending_) {
            post_write(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_write(std::move(handler), {}, 0);
            return;
        }
        write_pending_ = std::make_shared<PendingWrite>();
        write_pending_->handler = std::move(handler);
        write_pending_->size = buffer.size();
        write_pending_->data = std::make_shared<std::vector<std::uint8_t>>(
            static_cast<const std::uint8_t *>(buffer.data()),
            static_cast<const std::uint8_t *>(buffer.data()) + buffer.size());
        pump_write();
    }

    boost::asio::any_io_executor executor() noexcept { return session_->executor(); }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        error = boost::asio::error::operation_not_supported;
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        if (closed_ || local_closed_) {
            error = boost::asio::error::operation_aborted;
            return;
        }
        local_closed_ = true;
        fin_requested_ = true;
        pump_write();
        error.clear();
    }

    void close() noexcept {
        if (closed_) {
            return;
        }
        const auto notify_peer = session_ && !session_->closed() && !local_closed_;
        closed_ = true;
        local_closed_ = true;
        finish_read(boost::asio::error::operation_aborted, 0);
        finish_write(boost::asio::error::operation_aborted, 0);
        if (session_) {
            if (notify_peer) {
                session_->enqueue_frame(kFin, stream_id_, {});
            }
            session_->remove_stream(stream_id_);
        }
    }

    void on_push(const std::vector<std::uint8_t> &payload) {
        if (closed_ || remote_closed_) {
            return;
        }
        if (!payload.empty()) {
            incoming_.push_back(std::make_shared<std::vector<std::uint8_t>>(payload));
        }
        deliver_read();
    }

    void on_fin() {
        if (closed_) {
            return;
        }
        remote_closed_ = true;
        deliver_read();
    }

    void on_update(const std::vector<std::uint8_t> &payload) {
        if (options_.smux_version != 2 || payload.size() != 8 || closed_) {
            if (session_) {
                session_->fail(protocol_error());
            }
            return;
        }
        peer_consumed_ = get_u32(payload.data());
        peer_window_ = get_u32(payload.data() + 4);
        pump_write();
    }

    void on_session_error(const boost::system::error_code &error) {
        if (closed_) {
            return;
        }
        closed_ = true;
        finish_read(error, 0);
        finish_write(error, 0);
    }

    std::uint32_t stream_id() const noexcept { return stream_id_; }

  private:
    struct PendingWrite {
        core::StreamHandle::WriteHandler handler;
        std::shared_ptr<std::vector<std::uint8_t>> data;
        std::size_t size = 0;
        std::size_t offset = 0;
        bool failed = false;
    };

    void pump_write() {
        if (closed_ || !session_ || session_->closed()) {
            return;
        }
        if (!write_pending_) {
            if (fin_requested_ && !fin_enqueued_) {
                fin_enqueued_ = true;
                auto self = shared_from_this();
                session_->enqueue_frame(kFin, stream_id_, {},
                                        [self](const boost::system::error_code &error) {
                                            if (error) {
                                                self->on_session_error(error);
                                            }
                                        });
            }
            return;
        }
        if (write_pending_->offset == write_pending_->size) {
            auto pending = write_pending_;
            finish_write({});
            if (fin_requested_ && !fin_enqueued_) {
                fin_enqueued_ = true;
                auto self = shared_from_this();
                session_->enqueue_frame(kFin, stream_id_, {},
                                        [self](const boost::system::error_code &error) {
                                            if (error) {
                                                self->on_session_error(error);
                                            }
                                        });
            }
            (void)pending;
            return;
        }

        auto &pending = *write_pending_;
        auto available = pending.size - pending.offset;
        if (options_.smux_version == 2) {
            const auto in_flight = bytes_sent_ - peer_consumed_;
            if (in_flight >= peer_window_) {
                return;
            }
            available = std::min<std::size_t>(available,
                                              static_cast<std::size_t>(peer_window_ - in_flight));
        }
        if (available == 0) {
            return;
        }
        const auto chunk_size = std::min<std::size_t>(options_.frame_size, available);
        std::vector<std::uint8_t> payload(
            pending.data->begin() + static_cast<std::ptrdiff_t>(pending.offset),
            pending.data->begin() + static_cast<std::ptrdiff_t>(pending.offset + chunk_size));
        pending.offset += chunk_size;
        if (options_.smux_version == 2) {
            bytes_sent_ += static_cast<std::uint32_t>(chunk_size);
        }
        auto self = shared_from_this();
        session_->enqueue_frame(kPush, stream_id_, std::move(payload),
                                [self](const boost::system::error_code &error) {
                                    if (error) {
                                        self->on_session_error(error);
                                        return;
                                    }
                                    self->pump_write();
                                });
    }

    void deliver_read() {
        if (closed_ || !read_handler_) {
            return;
        }
        if (incoming_.empty()) {
            if (remote_closed_) {
                finish_read(boost::asio::error::eof, 0);
            }
            return;
        }
        const auto first_read = bytes_consumed_ == 0;
        std::size_t copied = 0;
        while (copied < read_buffer_.size() && !incoming_.empty()) {
            auto &front = incoming_.front();
            const auto available = front->size() - incoming_offset_;
            const auto count = std::min(available, read_buffer_.size() - copied);
            std::memcpy(static_cast<std::uint8_t *>(read_buffer_.data()) + copied,
                        front->data() + incoming_offset_, count);
            copied += count;
            incoming_offset_ += count;
            if (options_.smux_version == 2) {
                bytes_consumed_ += static_cast<std::uint32_t>(count);
                consumed_since_update_ += static_cast<std::uint32_t>(count);
            }
            if (incoming_offset_ == front->size()) {
                incoming_.pop_front();
                incoming_offset_ = 0;
            }
        }
        finish_read({}, copied);
        if (!closed_ && options_.smux_version == 2 &&
            (first_read ||
             consumed_since_update_ >= static_cast<std::uint32_t>(options_.stream_buffer / 2))) {
            consumed_since_update_ = 0;
            std::vector<std::uint8_t> update(8);
            put_u32(update.data(), bytes_consumed_);
            put_u32(update.data() + 4, static_cast<std::uint32_t>(options_.stream_buffer));
            session_->enqueue_frame(kUpdate, stream_id_, std::move(update));
        }
    }

    void finish_read(const boost::system::error_code &error, std::size_t size) {
        if (!read_handler_) {
            return;
        }
        auto handler = std::move(read_handler_);
        read_buffer_ = {};
        handler(error, size);
    }

    void finish_write(const boost::system::error_code &error, std::size_t size = 0) {
        if (!write_pending_) {
            return;
        }
        auto pending = std::move(write_pending_);
        pending->failed = static_cast<bool>(error);
        auto handler = std::move(pending->handler);
        if (handler) {
            handler(error, error ? 0 : (size == 0 ? pending->size : size));
        }
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

    std::shared_ptr<KcptunMuxSession> session_;
    std::uint32_t stream_id_ = 0;
    KcptunClientOptions options_;
    boost::asio::mutable_buffer read_buffer_;
    core::StreamHandle::ReadHandler read_handler_;
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>> incoming_;
    std::size_t incoming_offset_ = 0;
    std::shared_ptr<PendingWrite> write_pending_;
    std::uint32_t peer_consumed_ = 0;
    std::uint32_t peer_window_ = kInitialPeerWindow;
    std::uint32_t bytes_sent_ = 0;
    std::uint32_t bytes_consumed_ = 0;
    std::uint32_t consumed_since_update_ = 0;
    bool fin_requested_ = false;
    bool fin_enqueued_ = false;
    bool local_closed_ = false;
    bool remote_closed_ = false;
    bool closed_ = false;
};

KcptunMuxStream::~KcptunMuxStream() { close(); }

void KcptunMuxStream::async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) {
    state_->async_read_some(buffer, std::move(handler));
}

void KcptunMuxStream::async_write(boost::asio::const_buffer buffer, WriteHandler handler) {
    state_->async_write(buffer, std::move(handler));
}

boost::asio::any_io_executor KcptunMuxStream::executor() noexcept { return state_->executor(); }

boost::asio::ip::tcp::endpoint
KcptunMuxStream::local_endpoint(boost::system::error_code &error) const noexcept {
    return state_->local_endpoint(error);
}

void KcptunMuxStream::shutdown_send(boost::system::error_code &error) noexcept {
    state_->shutdown_send(error);
}

void KcptunMuxStream::close() noexcept { state_->close(); }

void KcptunMuxSession::async_open_stream(core::StreamOpenHandler handler) {
    if (closed_) {
        boost::asio::post(executor(), [handler = std::move(handler)]() mutable {
            handler(core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "kcptun session is closed", {}}));
        });
        return;
    }
    if (next_stream_id_ > std::numeric_limits<std::uint32_t>::max() - 2) {
        handler(core::StreamOpenResult::failed(
            {core::ErrorCode::transport_io, "kcptun SMUX stream ID space exhausted", {}}));
        return;
    }
    const auto stream_id = next_stream_id_;
    next_stream_id_ += 2;
    auto stream = std::make_shared<KcptunMuxStreamState>(shared_from_this(), stream_id, options_);
    register_stream(stream_id, stream);
    enqueue_frame(kSyn, stream_id, {});
    handler(core::StreamOpenResult::opened(
        std::unique_ptr<core::StreamHandle>(std::make_unique<KcptunMuxStream>(stream))));
}

void KcptunMuxSession::enqueue_frame(
    std::uint8_t command, std::uint32_t stream_id, std::vector<std::uint8_t> payload,
    std::function<void(const boost::system::error_code &)> completed) {
    if (closed_) {
        if (completed) {
            completed(pool_closed_error());
        }
        return;
    }
    if (payload.size() > kMaximumFrameSize) {
        if (completed) {
            completed(boost::asio::error::message_size);
        }
        return;
    }
    queued_frames_.push_back({std::make_shared<std::vector<std::uint8_t>>(
                                  make_frame(command, stream_id, std::move(payload))),
                              std::move(completed)});
    pump_write();
}

void KcptunMuxSession::pump_write() {
    if (closed_ || write_in_progress_ || queued_frames_.empty()) {
        return;
    }
    write_in_progress_ = true;
    auto frame = std::move(queued_frames_.front());
    queued_frames_.pop_front();
    auto bytes = frame.bytes;
    auto completed = std::move(frame.completed);
    auto self = shared_from_this();
    const auto buffer = boost::asio::buffer(*bytes);
    carrier_->async_write(buffer, [self, bytes, completed = std::move(completed)](
                                      const boost::system::error_code &error, std::size_t) mutable {
        self->write_in_progress_ = false;
        if (completed) {
            completed(error);
        }
        if (error) {
            self->fail(error);
            return;
        }
        self->pump_write();
    });
}

void KcptunMuxSession::read_header() {
    if (closed_) {
        return;
    }
    auto self = shared_from_this();
    read_exact(boost::asio::buffer(header_buffer_), [self](const boost::system::error_code &error) {
        if (error) {
            self->fail(error);
            return;
        }
        if (self->header_buffer_[0] != static_cast<std::uint8_t>(self->options_.smux_version)) {
            self->fail(protocol_error());
            return;
        }
        const auto length = get_u16(self->header_buffer_.data() + 2);
        if (length > self->options_.frame_size) {
            self->fail(boost::asio::error::message_size);
            return;
        }
        auto payload = std::make_shared<std::vector<std::uint8_t>>(length);
        self->read_payload(self->header_buffer_, std::move(payload));
    });
}

void KcptunMuxSession::read_payload(const std::array<std::uint8_t, kHeaderSize> &header,
                                    std::shared_ptr<std::vector<std::uint8_t>> payload) {
    auto self = shared_from_this();
    read_exact(boost::asio::buffer(*payload),
               [self, header, payload](const boost::system::error_code &error) {
                   if (error) {
                       self->fail(error);
                       return;
                   }
                   self->handle_frame(header, *payload);
                   if (!self->closed_) {
                       self->read_header();
                   }
               });
}

void KcptunMuxSession::handle_frame(const std::array<std::uint8_t, kHeaderSize> &header,
                                    const std::vector<std::uint8_t> &payload) {
    const auto command = header[1];
    const auto stream_id = get_u32(header.data() + 4);
    if (command == kNop) {
        return;
    }
    const auto iterator = streams_.find(stream_id);
    if (iterator == streams_.end()) {
        if (command == kSyn) {
            // A client does not accept remotely initiated streams. This is a
            // protocol error rather than silently allocating an unowned stream.
            fail(protocol_error());
        }
        return;
    }
    if (command == kPush) {
        iterator->second->on_push(payload);
    } else if (command == kFin) {
        iterator->second->on_fin();
    } else if (command == kUpdate) {
        iterator->second->on_update(payload);
    } else if (command != kSyn) {
        fail(protocol_error());
    }
}

void KcptunMuxSession::read_exact(boost::asio::mutable_buffer buffer, ReadExactHandler handler,
                                  std::size_t offset) {
    if (closed_) {
        handler(boost::asio::error::operation_aborted);
        return;
    }
    if (offset == buffer.size()) {
        handler({});
        return;
    }
    auto self = shared_from_this();
    carrier_->async_read_some(
        boost::asio::buffer(static_cast<std::uint8_t *>(buffer.data()) + offset,
                            buffer.size() - offset),
        [self, buffer, handler = std::move(handler), offset](const boost::system::error_code &error,
                                                             std::size_t size) mutable {
            if (error) {
                handler(error);
                return;
            }
            if (size == 0) {
                handler(boost::asio::error::eof);
                return;
            }
            self->read_exact(buffer, std::move(handler), offset + size);
        });
}

void KcptunMuxSession::schedule_keepalive() {
    if (closed_ || options_.keepalive_seconds <= 0) {
        return;
    }
    keepalive_timer_.expires_after(std::chrono::seconds(options_.keepalive_seconds));
    auto self = shared_from_this();
    keepalive_timer_.async_wait([self](const boost::system::error_code &error) {
        if (error || self->closed_) {
            return;
        }
        self->enqueue_frame(kNop, 0, {});
        self->schedule_keepalive();
    });
}

void KcptunMuxSession::remove_stream(std::uint32_t stream_id) { streams_.erase(stream_id); }

void KcptunMuxSession::close_stream(std::uint32_t stream_id) {
    if (closed_) {
        return;
    }
    enqueue_frame(kFin, stream_id, {});
    remove_stream(stream_id);
}

void KcptunMuxSession::fail(const boost::system::error_code &error) {
    if (closed_) {
        return;
    }
    closed_ = true;
    keepalive_timer_.cancel();
    queued_frames_.clear();
    if (carrier_) {
        carrier_->close();
    }
    auto streams = std::move(streams_);
    for (auto &[id, stream] : streams) {
        (void)id;
        stream->on_session_error(error);
    }
}

void KcptunMuxSession::close() noexcept {
    if (closed_) {
        return;
    }
    closed_ = true;
    keepalive_timer_.cancel();
    queued_frames_.clear();
    if (carrier_) {
        carrier_->close();
    }
    auto streams = std::move(streams_);
    for (auto &[id, stream] : streams) {
        (void)id;
        stream->on_session_error(boost::asio::error::operation_aborted);
    }
}

} // namespace

struct KcptunClientPool::Impl final : public std::enable_shared_from_this<KcptunClientPool::Impl> {
    struct Slot {
        std::shared_ptr<KcptunMuxSession> session;
        std::chrono::steady_clock::time_point created;
    };

    Impl(runtime::AsioRuntime &runtime, KcptunClientOptions options)
        : runtime(runtime), options(std::move(options)), scavenger(runtime.context()) {
        slots.resize(static_cast<std::size_t>(this->options.connection_count));
    }

    void open_stream(boost::asio::ip::udp::endpoint endpoint, core::StreamOpenHandler handler) {
        if (closed) {
            boost::asio::post(runtime.context(), [handler = std::move(handler)]() mutable {
                handler(core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "kcptun client pool is closed", {}}));
            });
            return;
        }
        if (!remote_endpoint || *remote_endpoint != endpoint) {
            for (auto &slot : slots) {
                if (slot.session) {
                    slot.session->close();
                }
                slot = {};
            }
            remote_endpoint = endpoint;
        }
        if (slots.empty()) {
            handler(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration, "kcptun session pool has no slots", {}}));
            return;
        }
        const auto now = std::chrono::steady_clock::now();
        for (std::size_t attempt = 0; attempt < slots.size(); ++attempt) {
            auto &slot = slots[(round_robin++) % slots.size()];
            if (slot.session && slot.session->closed()) {
                slot.session.reset();
            }
            if (slot.session && options.auto_expire_seconds > 0 &&
                now - slot.created >= std::chrono::seconds(options.auto_expire_seconds)) {
                slot.session->close();
                slot.session.reset();
            }
            if (!slot.session) {
                auto carrier = make_kcptun_carrier(runtime, endpoint, options);
                if (!carrier) {
                    handler(core::StreamOpenResult::failed(carrier.error()));
                    return;
                }
                slot.session =
                    std::make_shared<KcptunMuxSession>(std::move(carrier.value()), options);
                slot.created = now;
                slot.session->start();
            }
            slot.session->async_open_stream(std::move(handler));
            return;
        }
        handler(core::StreamOpenResult::failed(
            {core::ErrorCode::transport_io, "unable to allocate kcptun session", {}}));
    }

    void close() noexcept {
        if (closed) {
            return;
        }
        closed = true;
        scavenger.cancel();
        for (auto &slot : slots) {
            if (slot.session) {
                slot.session->close();
            }
            slot = {};
        }
    }

    void schedule_scavenge() {
        if (closed) {
            return;
        }
        scavenger.expires_after(kScavengePeriod);
        auto self = shared_from_this();
        scavenger.async_wait([self](const boost::system::error_code &error) {
            if (error || self->closed) {
                return;
            }
            const auto now = std::chrono::steady_clock::now();
            for (auto &slot : self->slots) {
                if (slot.session && slot.session->closed()) {
                    slot.session.reset();
                } else if (slot.session && self->options.auto_expire_seconds > 0 &&
                           now - slot.created >=
                               std::chrono::seconds(self->options.auto_expire_seconds +
                                                    self->options.scavenge_ttl_seconds)) {
                    slot.session->close();
                    slot.session.reset();
                }
            }
            self->schedule_scavenge();
        });
    }

    runtime::AsioRuntime &runtime;
    KcptunClientOptions options;
    boost::asio::steady_timer scavenger;
    std::vector<Slot> slots;
    std::optional<boost::asio::ip::udp::endpoint> remote_endpoint;
    std::size_t round_robin = 0;
    bool closed = false;
};

KcptunClientPool::KcptunClientPool(runtime::AsioRuntime &runtime, KcptunClientOptions options)
    : impl_(std::make_shared<Impl>(runtime, std::move(options))) {
    impl_->schedule_scavenge();
}

KcptunClientPool::~KcptunClientPool() { close(); }

void KcptunClientPool::async_open_stream(boost::asio::ip::udp::endpoint endpoint,
                                         core::StreamOpenHandler handler) {
    impl_->open_stream(endpoint, std::move(handler));
}

void KcptunClientPool::close() noexcept {
    if (impl_) {
        impl_->close();
    }
}

} // namespace clash_native::transport::shadowsocks
