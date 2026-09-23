#include <clash_native/transport/shadowsocks/websocket_mux.hpp>

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/oneshot.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include <stdexec/execution.hpp>

#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/errc.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::uint8_t kV2rayNew = 0x01;
constexpr std::uint8_t kV2rayKeep = 0x02;
constexpr std::uint8_t kV2rayEnd = 0x03;
constexpr std::uint8_t kV2rayKeepAlive = 0x04;
constexpr std::uint8_t kV2rayNone = 0x00;
constexpr std::uint8_t kV2rayData = 0x01;
constexpr std::uint8_t kV2rayError = 0x02;

constexpr std::uint8_t kSmuxSyn = 0;
constexpr std::uint8_t kSmuxFin = 1;
constexpr std::uint8_t kSmuxPush = 2;
constexpr std::uint8_t kSmuxNop = 3;
constexpr std::uint8_t kSmuxUpdate = 4;
constexpr std::size_t kSmuxHeaderSize = 8;
constexpr std::size_t kV2rayMaximumMetadataSize = 512;
constexpr std::size_t kV2rayMaximumStreamId = 0xffff;
constexpr std::size_t kMaximumMuxFrameSize = 0xffff;
constexpr std::uint32_t kSmuxInitialPeerWindow = 262144;

boost::system::error_code protocol_error() {
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

core::Error stream_error(const boost::system::error_code &error, std::string context) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

core::Error mux_error(const boost::system::error_code &error, std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

void put_be16(std::uint8_t *output, std::uint16_t value) {
    output[0] = static_cast<std::uint8_t>(value >> 8);
    output[1] = static_cast<std::uint8_t>(value);
}

std::uint16_t get_be16(const std::uint8_t *input) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(input[0]) << 8) | input[1]);
}

void put_le16(std::uint8_t *output, std::uint16_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8);
}

std::uint16_t get_le16(const std::uint8_t *input) {
    return static_cast<std::uint16_t>(input[0] | (static_cast<std::uint16_t>(input[1]) << 8));
}

void put_le32(std::uint8_t *output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8);
    output[2] = static_cast<std::uint8_t>(value >> 16);
    output[3] = static_cast<std::uint8_t>(value >> 24);
}

std::uint32_t get_le32(const std::uint8_t *input) {
    return static_cast<std::uint32_t>(input[0]) | (static_cast<std::uint32_t>(input[1]) << 8) |
           (static_cast<std::uint32_t>(input[2]) << 16) |
           (static_cast<std::uint32_t>(input[3]) << 24);
}

class WebSocketMuxSession;

class WebSocketMuxStreamState final : public std::enable_shared_from_this<WebSocketMuxStreamState> {
  public:
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
    using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    WebSocketMuxStreamState(std::shared_ptr<WebSocketMuxSession> session,
                            io::MultiplexedSession::StreamId operation_id, std::uint32_t wire_id)
        : session_(std::move(session)), operation_id_(operation_id), wire_id_(wire_id) {}

    ~WebSocketMuxStreamState() { close(); }

    void read_some(boost::asio::mutable_buffer buffer, ReadHandler handler);
    void write_some(boost::asio::const_buffer buffer, WriteHandler handler);
    boost::asio::any_io_executor executor() noexcept;
    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept;
    void shutdown_send(boost::system::error_code &error) noexcept;
    void close() noexcept;

    void on_data(std::vector<std::uint8_t> data);
    void on_remote_end();
    void on_update(const std::vector<std::uint8_t> &payload);
    void on_session_error(const boost::system::error_code &error);
    void on_open_error(const boost::system::error_code &error);

    io::MultiplexedSession::StreamId operation_id() const noexcept { return operation_id_; }
    std::uint32_t wire_id() const noexcept { return wire_id_; }
    bool closed() const noexcept { return closed_; }
    bool local_closed() const noexcept { return local_closed_; }
    bool end_enqueued() const noexcept { return end_enqueued_; }
    void mark_end_enqueued() noexcept { end_enqueued_ = true; }

  private:
    struct PendingWrite {
        std::shared_ptr<std::vector<std::uint8_t>> data;
        std::size_t offset = 0;
        WriteHandler handler;
    };

    void deliver_read();
    void finish_read(const boost::system::error_code &error, std::size_t size);
    void finish_write(const boost::system::error_code &error, std::size_t size = 0);
    void post_read(ReadHandler handler, const boost::system::error_code &error, std::size_t size);
    void post_write(WriteHandler handler, const boost::system::error_code &error, std::size_t size);
    void pump_write();

    std::shared_ptr<WebSocketMuxSession> session_;
    io::MultiplexedSession::StreamId operation_id_ = 0;
    std::uint32_t wire_id_ = 0;
    boost::asio::mutable_buffer read_buffer_;
    ReadHandler read_handler_;
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>> incoming_;
    std::size_t incoming_offset_ = 0;
    std::shared_ptr<PendingWrite> pending_write_;
    bool local_closed_ = false;
    bool remote_closed_ = false;
    bool end_requested_ = false;
    bool end_enqueued_ = false;
    bool closed_ = false;
    std::uint32_t peer_consumed_ = 0;
    std::uint32_t peer_window_ = kSmuxInitialPeerWindow;
    std::uint32_t bytes_sent_ = 0;
    std::uint32_t bytes_consumed_ = 0;
    std::uint32_t consumed_since_update_ = 0;
};

class WebSocketMuxStream final : public io::StreamHandle {
  public:
    explicit WebSocketMuxStream(std::shared_ptr<WebSocketMuxStreamState> state)
        : state_(std::move(state)) {}
    ~WebSocketMuxStream() override { close(); }

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
            [state = state_, buffer](auto terminal) mutable {
                state->read_some(buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                net::translate_read(std::move(receiver), error, size, "mux stream read");
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        return io::AnySender<std::size_t>{async::callback_sender<Signatures>(
            [state = state_, buffer](auto terminal) mutable {
                state->write_some(buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                net::translate_write(std::move(receiver), error, size, "mux stream write");
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
    std::shared_ptr<WebSocketMuxStreamState> state_;
};

// Terminal captured into a oneshot per open; the entry wrapper rethrows
// failures per the io:: sender contract.
using MuxOpenTerminal = core::Result<std::unique_ptr<io::StreamHandle>>;

class WebSocketMuxSession final : public io::MultiplexedSession,
                                  public std::enable_shared_from_this<WebSocketMuxSession> {
  public:
    WebSocketMuxSession(std::unique_ptr<io::StreamHandle> carrier, WebSocketMuxOptions options)
        : carrier_(std::move(carrier)), options_(std::move(options)),
          executor_(this->carrier_->executor()) {}

    ~WebSocketMuxSession() override { stop(); }

    void start() { read_more(); }

    io::AnySender<std::unique_ptr<io::StreamHandle>>
    open_stream(io::MultiplexedStreamRequest request,
                std::chrono::steady_clock::time_point deadline) override;
    void cancel(StreamId stream_id) noexcept override;
    std::size_t active_streams() const noexcept override { return streams_.size(); }
    std::optional<std::size_t> max_concurrent_streams() const noexcept override {
        return options_.max_concurrent_streams;
    }
    void stop() noexcept override;
    bool retired() const noexcept override { return closed_; }

    boost::asio::any_io_executor executor() noexcept { return executor_; }
    std::size_t frame_size() const noexcept {
        return std::min<std::size_t>(options_.max_frame_size, kMaximumMuxFrameSize);
    }
    WebSocketMuxProtocol protocol() const noexcept { return options_.protocol; }
    bool smux_v2() const noexcept {
        return options_.protocol == WebSocketMuxProtocol::smux && options_.smux_version == 2;
    }
    std::size_t smux_stream_buffer() const noexcept { return options_.smux_stream_buffer; }

    void stream_close(const std::shared_ptr<WebSocketMuxStreamState> &stream);
    void stream_update(const std::shared_ptr<WebSocketMuxStreamState> &stream,
                       std::uint32_t consumed, std::uint32_t window);

  private:
    friend class WebSocketMuxStreamState;

    struct QueuedFrame {
        std::shared_ptr<std::vector<std::uint8_t>> bytes;
        std::function<void(const boost::system::error_code &)> completed;
    };

    struct PendingOpen {
        std::shared_ptr<WebSocketMuxStreamState> stream;
        async::oneshot::Sender<MuxOpenTerminal> handler;
    };

    io::AnySender<std::unique_ptr<io::StreamHandle>>
    wrap_open(StreamId operation_id, async::oneshot::Receiver<MuxOpenTerminal> receiver) {
        auto sender =
            std::move(receiver) |
            stdexec::then(
                [](std::optional<MuxOpenTerminal> terminal) -> std::unique_ptr<io::StreamHandle> {
                    if (!terminal) {
                        throw core::Error{core::ErrorCode::cancelled,
                                          "WebSocket mux stream open was abandoned"};
                    }
                    if (!*terminal) {
                        throw terminal->error();
                    }
                    return std::move(terminal->value());
                }) |
            stdexec::let_stopped([self = shared_from_this(), operation_id] {
                self->cancel(operation_id);
                return stdexec::just_stopped();
            });
        return io::AnySender<std::unique_ptr<io::StreamHandle>>{std::move(sender)};
    }

    std::vector<std::uint8_t> make_open_frame(std::uint32_t wire_id) const;
    std::vector<std::uint8_t> make_data_frame(std::uint32_t wire_id, const std::uint8_t *data,
                                              std::size_t size) const;
    std::vector<std::uint8_t> make_close_frame(std::uint32_t wire_id) const;
    std::vector<std::uint8_t> make_update_frame(std::uint32_t wire_id, std::uint32_t consumed,
                                                std::uint32_t window) const;
    std::vector<std::uint8_t> make_nop_frame() const;
    void enqueue_frame(std::vector<std::uint8_t> frame,
                       std::function<void(const boost::system::error_code &)> completed = {});
    void pump_write();
    void read_more();
    void parse_frames();
    bool parse_v2ray_frame();
    bool parse_smux_frame();
    void fail(const boost::system::error_code &error);
    void fail_pending(const boost::system::error_code &error);
    std::optional<std::uint32_t> allocate_wire_id();
    std::shared_ptr<WebSocketMuxStreamState> find_stream(std::uint32_t wire_id);

    std::unique_ptr<io::StreamHandle> carrier_;
    WebSocketMuxOptions options_;
    boost::asio::any_io_executor executor_;
    std::array<std::uint8_t, 16 * 1024> read_buffer_{};
    std::vector<std::uint8_t> input_;
    std::deque<QueuedFrame> writes_;
    std::unordered_map<std::uint32_t, std::shared_ptr<WebSocketMuxStreamState>> streams_;
    std::unordered_map<StreamId, PendingOpen> pending_opens_;
    StreamId next_operation_id_ = 1;
    std::uint32_t next_wire_id_ = 1;
    bool reading_ = false;
    bool writing_ = false;
    bool closed_ = false;
};

boost::asio::any_io_executor WebSocketMuxStreamState::executor() noexcept {
    return session_->executor();
}

boost::asio::ip::tcp::endpoint
WebSocketMuxStreamState::local_endpoint(boost::system::error_code &error) const noexcept {
    if (!session_) {
        error = boost::asio::error::operation_aborted;
        return {};
    }
    // The underlying WebSocket carrier still has a TCP local endpoint, but
    // the session deliberately keeps that detail behind the common stream API.
    error = boost::asio::error::operation_not_supported;
    return {};
}

void WebSocketMuxStreamState::read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) {
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

void WebSocketMuxStreamState::write_some(boost::asio::const_buffer buffer, WriteHandler handler) {
    if (closed_ || local_closed_) {
        post_write(std::move(handler), boost::asio::error::operation_aborted, 0);
        return;
    }
    if (pending_write_) {
        post_write(std::move(handler), boost::asio::error::already_started, 0);
        return;
    }
    auto data = std::make_shared<std::vector<std::uint8_t>>(buffer.size());
    if (buffer.size() != 0) {
        std::memcpy(data->data(), buffer.data(), buffer.size());
    }
    pending_write_ = std::make_shared<PendingWrite>();
    pending_write_->data = std::move(data);
    pending_write_->handler = std::move(handler);
    pump_write();
}

void WebSocketMuxStreamState::shutdown_send(boost::system::error_code &error) noexcept {
    if (closed_ || local_closed_) {
        error = boost::asio::error::operation_aborted;
        return;
    }
    local_closed_ = true;
    end_requested_ = true;
    pump_write();
    error.clear();
}

void WebSocketMuxStreamState::close() noexcept {
    if (closed_) {
        return;
    }
    closed_ = true;
    local_closed_ = true;
    finish_read(boost::asio::error::operation_aborted, 0);
    finish_write(boost::asio::error::operation_aborted, 0);
    if (session_) {
        session_->stream_close(shared_from_this());
    }
}

void WebSocketMuxStreamState::on_data(std::vector<std::uint8_t> data) {
    if (closed_ || remote_closed_) {
        return;
    }
    if (!data.empty()) {
        incoming_.push_back(std::make_shared<std::vector<std::uint8_t>>(std::move(data)));
    }
    deliver_read();
}

void WebSocketMuxStreamState::on_remote_end() {
    if (closed_) {
        return;
    }
    remote_closed_ = true;
    deliver_read();
}

void WebSocketMuxStreamState::on_update(const std::vector<std::uint8_t> &payload) {
    if (!session_ || !session_->smux_v2() || payload.size() != 8 || closed_) {
        if (session_) {
            session_->fail(protocol_error());
        }
        return;
    }
    peer_consumed_ = get_le32(payload.data());
    peer_window_ = get_le32(payload.data() + 4);
    pump_write();
}

void WebSocketMuxStreamState::on_session_error(const boost::system::error_code &error) {
    if (closed_) {
        return;
    }
    closed_ = true;
    finish_read(error, 0);
    finish_write(error, 0);
    session_.reset();
}

void WebSocketMuxStreamState::on_open_error(const boost::system::error_code &error) {
    on_session_error(error);
}

void WebSocketMuxStreamState::deliver_read() {
    if (closed_ || !read_handler_) {
        return;
    }
    if (incoming_.empty()) {
        if (remote_closed_) {
            finish_read(boost::asio::error::eof, 0);
        }
        return;
    }
    const auto first_read = session_ && session_->smux_v2() && bytes_consumed_ == 0;
    std::size_t copied = 0;
    while (copied < read_buffer_.size() && !incoming_.empty()) {
        auto &front = incoming_.front();
        const auto available = front->size() - incoming_offset_;
        const auto count = std::min(available, read_buffer_.size() - copied);
        std::memcpy(static_cast<std::uint8_t *>(read_buffer_.data()) + copied,
                    front->data() + incoming_offset_, count);
        copied += count;
        incoming_offset_ += count;
        if (session_ && session_->smux_v2()) {
            bytes_consumed_ += static_cast<std::uint32_t>(count);
            consumed_since_update_ += static_cast<std::uint32_t>(count);
        }
        if (incoming_offset_ == front->size()) {
            incoming_.pop_front();
            incoming_offset_ = 0;
        }
    }
    finish_read({}, copied);
    if (session_ && session_->smux_v2() &&
        (first_read || consumed_since_update_ >=
                           static_cast<std::uint32_t>(session_->smux_stream_buffer() / 2))) {
        consumed_since_update_ = 0;
        session_->stream_update(shared_from_this(), bytes_consumed_,
                                static_cast<std::uint32_t>(session_->smux_stream_buffer()));
    }
}

void WebSocketMuxStreamState::finish_read(const boost::system::error_code &error,
                                          std::size_t size) {
    if (!read_handler_) {
        return;
    }
    auto handler = std::move(read_handler_);
    read_buffer_ = {};
    handler(error, size);
}

void WebSocketMuxStreamState::finish_write(const boost::system::error_code &error,
                                           std::size_t size) {
    if (!pending_write_) {
        return;
    }
    auto pending = std::move(pending_write_);
    auto handler = std::move(pending->handler);
    if (handler) {
        handler(error, error ? 0 : (size == 0 ? pending->data->size() : size));
    }
}

void WebSocketMuxStreamState::post_read(ReadHandler handler, const boost::system::error_code &error,
                                        std::size_t size) {
    boost::asio::post(executor(), [handler = std::move(handler), error, size]() mutable {
        handler(error, size);
    });
}

void WebSocketMuxStreamState::post_write(WriteHandler handler,
                                         const boost::system::error_code &error, std::size_t size) {
    boost::asio::post(executor(), [handler = std::move(handler), error, size]() mutable {
        handler(error, size);
    });
}

void WebSocketMuxStreamState::pump_write() {
    if (closed_ || !session_) {
        return;
    }
    if (!pending_write_) {
        if (end_requested_ && !end_enqueued_) {
            end_enqueued_ = true;
            session_->enqueue_frame(session_->make_close_frame(wire_id_));
        }
        return;
    }
    if (pending_write_->offset == pending_write_->data->size()) {
        finish_write({});
        if (end_requested_ && !end_enqueued_) {
            end_enqueued_ = true;
            session_->enqueue_frame(session_->make_close_frame(wire_id_));
        }
        return;
    }
    auto available = pending_write_->data->size() - pending_write_->offset;
    if (session_->smux_v2()) {
        const auto in_flight = bytes_sent_ - peer_consumed_;
        if (in_flight >= peer_window_) {
            return;
        }
        available =
            std::min<std::size_t>(available, static_cast<std::size_t>(peer_window_ - in_flight));
    }
    if (available == 0) {
        return;
    }
    const auto size = std::min(available, session_->frame_size());
    const auto offset = pending_write_->offset;
    pending_write_->offset += size;
    if (session_->smux_v2()) {
        bytes_sent_ += static_cast<std::uint32_t>(size);
    }
    auto self = shared_from_this();
    session_->enqueue_frame(
        session_->make_data_frame(wire_id_, pending_write_->data->data() + offset, size),
        [self](const boost::system::error_code &error) {
            if (error) {
                self->finish_write(error, 0);
                self->on_session_error(error);
                return;
            }
            self->pump_write();
        });
}

std::optional<std::uint32_t> WebSocketMuxSession::allocate_wire_id() {
    const auto maximum = options_.protocol == WebSocketMuxProtocol::v2ray
                             ? static_cast<std::uint32_t>(kV2rayMaximumStreamId)
                             : std::numeric_limits<std::uint32_t>::max() - 1;
    for (std::size_t attempt = 0; attempt < maximum; ++attempt) {
        auto candidate = next_wire_id_;
        if (options_.protocol == WebSocketMuxProtocol::v2ray) {
            next_wire_id_ = (next_wire_id_ >= maximum - 1) ? 1 : next_wire_id_ + 1;
        } else {
            next_wire_id_ = (next_wire_id_ >= maximum - 1) ? 1 : next_wire_id_ + 2;
        }
        if (candidate != 0 && !streams_.contains(candidate)) {
            return candidate;
        }
    }
    return std::nullopt;
}

std::shared_ptr<WebSocketMuxStreamState> WebSocketMuxSession::find_stream(std::uint32_t wire_id) {
    const auto found = streams_.find(wire_id);
    return found == streams_.end() ? nullptr : found->second;
}

std::vector<std::uint8_t> WebSocketMuxSession::make_open_frame(std::uint32_t wire_id) const {
    if (options_.protocol == WebSocketMuxProtocol::v2ray) {
        // Mihomo's v2ray-plugin mux uses a small big-endian metadata record.
        // The destination is deliberately the neutral 127.0.0.1:0 value;
        // Shadowsocks carries the real target in its own stream handshake.
        constexpr std::size_t metadata_size = 12;
        std::vector<std::uint8_t> frame(2 + metadata_size);
        put_be16(frame.data(), static_cast<std::uint16_t>(metadata_size));
        put_be16(frame.data() + 2, static_cast<std::uint16_t>(wire_id));
        frame[4] = kV2rayNew;
        frame[5] = kV2rayNone;
        frame[6] = 0x01; // TCP
        put_be16(frame.data() + 7, 0);
        frame[9] = 0x01; // IPv4
        frame[10] = 127;
        frame[11] = 0;
        frame[12] = 0;
        frame[13] = 1;
        return frame;
    }

    std::vector<std::uint8_t> frame(kSmuxHeaderSize);
    frame[0] = options_.smux_version;
    frame[1] = kSmuxSyn;
    put_le16(frame.data() + 2, 0);
    put_le32(frame.data() + 4, wire_id);
    return frame;
}

std::vector<std::uint8_t> WebSocketMuxSession::make_data_frame(std::uint32_t wire_id,
                                                               const std::uint8_t *data,
                                                               std::size_t size) const {
    if (options_.protocol == WebSocketMuxProtocol::v2ray) {
        std::vector<std::uint8_t> frame(2 + 4 + 2 + size);
        put_be16(frame.data(), 4);
        put_be16(frame.data() + 2, static_cast<std::uint16_t>(wire_id));
        frame[4] = kV2rayKeep;
        frame[5] = kV2rayData;
        put_be16(frame.data() + 6, static_cast<std::uint16_t>(size));
        if (size != 0) {
            std::memcpy(frame.data() + 8, data, size);
        }
        return frame;
    }

    std::vector<std::uint8_t> frame(kSmuxHeaderSize + size);
    frame[0] = options_.smux_version;
    frame[1] = kSmuxPush;
    put_le16(frame.data() + 2, static_cast<std::uint16_t>(size));
    put_le32(frame.data() + 4, wire_id);
    if (size != 0) {
        std::memcpy(frame.data() + kSmuxHeaderSize, data, size);
    }
    return frame;
}

std::vector<std::uint8_t> WebSocketMuxSession::make_close_frame(std::uint32_t wire_id) const {
    if (options_.protocol == WebSocketMuxProtocol::v2ray) {
        std::vector<std::uint8_t> frame(2 + 4);
        put_be16(frame.data(), 4);
        put_be16(frame.data() + 2, static_cast<std::uint16_t>(wire_id));
        frame[4] = kV2rayEnd;
        frame[5] = kV2rayNone;
        return frame;
    }
    std::vector<std::uint8_t> frame(kSmuxHeaderSize);
    frame[0] = options_.smux_version;
    frame[1] = kSmuxFin;
    put_le16(frame.data() + 2, 0);
    put_le32(frame.data() + 4, wire_id);
    return frame;
}

std::vector<std::uint8_t> WebSocketMuxSession::make_update_frame(std::uint32_t wire_id,
                                                                 std::uint32_t consumed,
                                                                 std::uint32_t window) const {
    std::vector<std::uint8_t> frame(kSmuxHeaderSize + 8);
    frame[0] = options_.smux_version;
    frame[1] = kSmuxUpdate;
    put_le16(frame.data() + 2, 8);
    put_le32(frame.data() + 4, wire_id);
    put_le32(frame.data() + kSmuxHeaderSize, consumed);
    put_le32(frame.data() + kSmuxHeaderSize + 4, window);
    return frame;
}

std::vector<std::uint8_t> WebSocketMuxSession::make_nop_frame() const {
    if (options_.protocol == WebSocketMuxProtocol::v2ray) {
        std::vector<std::uint8_t> frame(2 + 4);
        put_be16(frame.data(), 4);
        put_be16(frame.data() + 2, 0);
        frame[4] = kV2rayKeepAlive;
        frame[5] = kV2rayNone;
        return frame;
    }
    std::vector<std::uint8_t> frame(kSmuxHeaderSize);
    frame[0] = options_.smux_version;
    frame[1] = kSmuxNop;
    put_le16(frame.data() + 2, 0);
    put_le32(frame.data() + 4, 0);
    return frame;
}

void WebSocketMuxSession::enqueue_frame(
    std::vector<std::uint8_t> frame,
    std::function<void(const boost::system::error_code &)> completed) {
    if (closed_) {
        if (completed) {
            completed(boost::asio::error::operation_aborted);
        }
        return;
    }
    if (frame.empty() || frame.size() > kMaximumMuxFrameSize + kSmuxHeaderSize) {
        if (completed) {
            completed(boost::asio::error::message_size);
        }
        return;
    }
    writes_.push_back(
        {std::make_shared<std::vector<std::uint8_t>>(std::move(frame)), std::move(completed)});
    pump_write();
}

void WebSocketMuxSession::pump_write() {
    if (closed_ || writing_ || writes_.empty()) {
        return;
    }
    writing_ = true;
    auto pending = std::move(writes_.front());
    writes_.pop_front();
    auto self = shared_from_this();
    auto frame = pending.bytes;
    struct WriteReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<WebSocketMuxSession> self;
        QueuedFrame pending;
        void set_value(std::size_t) && noexcept {
            self->writing_ = false;
            if (pending.completed) {
                pending.completed({});
            }
            self->pump_write();
        }
        void set_error(std::exception_ptr error) && noexcept {
            self->writing_ = false;
            boost::system::error_code code = boost::asio::error::fault;
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &failure) {
                if (failure.cause) {
                    code = {failure.cause.value(), boost::system::system_category()};
                }
            } catch (...) {
            }
            if (pending.completed) {
                pending.completed(code);
            }
            self->fail(code);
        }
        void set_stopped() && noexcept {
            self->writing_ = false;
            if (pending.completed) {
                pending.completed(boost::asio::error::operation_aborted);
            }
            self->fail(boost::asio::error::operation_aborted);
        }
    };
    // NOTE: name the sender first; argument order is unspecified.
    auto sender = carrier_->async_write(boost::asio::buffer(*frame));
    async::start_with_receiver(std::move(sender), WriteReceiver{self, std::move(pending)});
}

void WebSocketMuxSession::read_more() {
    if (closed_ || reading_) {
        return;
    }
    reading_ = true;
    struct ReadReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<WebSocketMuxSession> self;
        void set_value(std::optional<std::size_t> size) && noexcept {
            self->reading_ = false;
            if (!size || *size == 0) {
                self->fail(boost::asio::error::eof);
                return;
            }
            self->input_.insert(self->input_.end(), self->read_buffer_.begin(),
                                self->read_buffer_.begin() + static_cast<std::ptrdiff_t>(*size));
            self->parse_frames();
            if (!self->closed_) {
                self->read_more();
            }
        }
        void set_error(std::exception_ptr error) && noexcept {
            self->reading_ = false;
            boost::system::error_code code = boost::asio::error::fault;
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &failure) {
                if (failure.cause) {
                    code = {failure.cause.value(), boost::system::system_category()};
                }
            } catch (...) {
            }
            self->fail(code);
        }
        void set_stopped() && noexcept {
            self->reading_ = false;
            self->fail(boost::asio::error::operation_aborted);
        }
    };
    auto self = shared_from_this();
    // NOTE: name the sender first; argument order is unspecified.
    auto sender = carrier_->async_read_some(boost::asio::buffer(read_buffer_));
    async::start_with_receiver(std::move(sender), ReadReceiver{self});
}

void WebSocketMuxSession::parse_frames() {
    while (!closed_) {
        const auto parsed = options_.protocol == WebSocketMuxProtocol::v2ray ? parse_v2ray_frame()
                                                                             : parse_smux_frame();
        if (!parsed) {
            break;
        }
    }
}

bool WebSocketMuxSession::parse_v2ray_frame() {
    if (input_.size() < 2) {
        return false;
    }
    const auto metadata_size = static_cast<std::size_t>(get_be16(input_.data()));
    if (metadata_size < 4 || metadata_size > kV2rayMaximumMetadataSize) {
        fail(protocol_error());
        return false;
    }
    if (input_.size() < 2 + metadata_size) {
        return false;
    }
    const auto metadata_offset = 2;
    const auto status = input_[metadata_offset + 2];
    const auto option = input_[metadata_offset + 3];
    std::size_t total = 2 + metadata_size;
    std::size_t payload_size = 0;
    if (status == kV2rayKeep && option == kV2rayData) {
        if (input_.size() < total + 2) {
            return false;
        }
        payload_size = get_be16(input_.data() + total);
        if (payload_size > frame_size()) {
            fail(boost::asio::error::message_size);
            return false;
        }
        total += 2;
        if (input_.size() < total + payload_size) {
            return false;
        }
    }
    const auto wire_id = static_cast<std::uint32_t>(get_be16(input_.data() + metadata_offset));
    std::vector<std::uint8_t> payload;
    if (payload_size != 0) {
        payload.assign(input_.begin() + static_cast<std::ptrdiff_t>(total),
                       input_.begin() + static_cast<std::ptrdiff_t>(total + payload_size));
    }
    total += payload_size;
    input_.erase(input_.begin(), input_.begin() + static_cast<std::ptrdiff_t>(total));

    auto stream = find_stream(wire_id);
    if (status == kV2rayEnd) {
        if (stream) {
            stream->on_remote_end();
        }
    } else if (status == kV2rayKeep && option == kV2rayData) {
        if (stream) {
            stream->on_data(std::move(payload));
        }
    } else if (status == kV2rayError) {
        if (stream) {
            stream->on_session_error(protocol_error());
        }
    }
    return true;
}

bool WebSocketMuxSession::parse_smux_frame() {
    if (input_.size() < kSmuxHeaderSize) {
        return false;
    }
    if (input_[0] != options_.smux_version) {
        fail(protocol_error());
        return false;
    }
    const auto command = input_[1];
    const auto payload_size = static_cast<std::size_t>(get_le16(input_.data() + 2));
    if (payload_size > frame_size()) {
        fail(boost::asio::error::message_size);
        return false;
    }
    const auto total = kSmuxHeaderSize + payload_size;
    if (input_.size() < total) {
        return false;
    }
    const auto wire_id = get_le32(input_.data() + 4);
    std::vector<std::uint8_t> payload;
    if (payload_size != 0) {
        payload.assign(input_.begin() + static_cast<std::ptrdiff_t>(kSmuxHeaderSize),
                       input_.begin() + static_cast<std::ptrdiff_t>(total));
    }
    input_.erase(input_.begin(), input_.begin() + static_cast<std::ptrdiff_t>(total));
    auto stream = find_stream(wire_id);
    if (command == kSmuxPush) {
        if (stream) {
            stream->on_data(std::move(payload));
        }
    } else if (command == kSmuxFin) {
        if (stream) {
            stream->on_remote_end();
        }
    } else if (command == kSmuxUpdate) {
        if (stream) {
            stream->on_update(payload);
        } else if (!smux_v2() || payload.size() != 8) {
            fail(protocol_error());
        }
    } else if (command == kSmuxSyn) {
        // The outbound side only accepts streams that it opened itself.
        fail(protocol_error());
    } else if (command != kSmuxNop) {
        fail(protocol_error());
    }
    return true;
}

io::AnySender<std::unique_ptr<io::StreamHandle>>
WebSocketMuxSession::open_stream(io::MultiplexedStreamRequest request,
                                 std::chrono::steady_clock::time_point deadline) {
    auto channel = async::oneshot::channel<MuxOpenTerminal>();
    const auto operation_id = next_operation_id_++;
    // Shared: the failure paths below post copyable closures; the pending
    // fulfiller crosses into the posted lambda through shared ownership.
    auto sender =
        std::make_shared<async::oneshot::Sender<MuxOpenTerminal>>(std::move(channel.sender));
    auto fail_post = [this, sender](core::Error error) {
        boost::asio::post(executor_, [sender, error = std::move(error)]() mutable {
            sender->send(core::fail(std::move(error)));
        });
    };
    if (!request.bidirectional) {
        fail_post({core::ErrorCode::unsupported,
                   "WebSocket mux only supports bidirectional streams",
                   {}});
        return wrap_open(operation_id, std::move(channel.receiver));
    }
    if (closed_) {
        fail_post({core::ErrorCode::transport_io, "WebSocket mux session is closed", {}});
        return wrap_open(operation_id, std::move(channel.receiver));
    }
    if (deadline <= std::chrono::steady_clock::now()) {
        fail_post({core::ErrorCode::timeout, "WebSocket mux stream open timed out", {}});
        return wrap_open(operation_id, std::move(channel.receiver));
    }
    if (streams_.size() >= options_.max_concurrent_streams) {
        fail_post(
            {core::ErrorCode::transport_io, "WebSocket mux stream capacity is exhausted", {}});
        return wrap_open(operation_id, std::move(channel.receiver));
    }
    const auto wire_id = allocate_wire_id();
    if (!wire_id) {
        fail_post(
            {core::ErrorCode::transport_io, "WebSocket mux stream ID space is exhausted", {}});
        return wrap_open(operation_id, std::move(channel.receiver));
    }
    auto stream =
        std::make_shared<WebSocketMuxStreamState>(shared_from_this(), operation_id, *wire_id);
    streams_.emplace(*wire_id, stream);
    pending_opens_.emplace(operation_id, PendingOpen{stream, std::move(*sender)});
    enqueue_frame(make_open_frame(*wire_id), [self = shared_from_this(), operation_id](
                                                 const boost::system::error_code &error) {
        const auto pending = self->pending_opens_.find(operation_id);
        if (pending == self->pending_opens_.end()) {
            return;
        }
        auto entry = std::move(pending->second);
        self->pending_opens_.erase(pending);
        if (error) {
            self->streams_.erase(entry.stream->wire_id());
            entry.stream->on_open_error(error);
            entry.handler.send(core::fail(stream_error(error, "WebSocket mux stream open failed")));
            return;
        }
        entry.handler.send(
            MuxOpenTerminal{std::make_unique<WebSocketMuxStream>(std::move(entry.stream))});
    });
    return wrap_open(operation_id, std::move(channel.receiver));
}

void WebSocketMuxSession::cancel(StreamId stream_id) noexcept {
    const auto pending = pending_opens_.find(stream_id);
    if (pending != pending_opens_.end()) {
        auto entry = std::move(pending->second);
        pending_opens_.erase(pending);
        streams_.erase(entry.stream->wire_id());
        entry.stream->on_open_error(boost::asio::error::operation_aborted);
        entry.handler.send(core::fail(
            {core::ErrorCode::cancelled, "WebSocket mux stream open was cancelled", {}}));
        return;
    }
    for (const auto &[wire_id, stream] : streams_) {
        if (stream->operation_id() == stream_id) {
            stream->close();
            (void)wire_id;
            return;
        }
    }
}

void WebSocketMuxSession::stream_update(const std::shared_ptr<WebSocketMuxStreamState> &stream,
                                        std::uint32_t consumed, std::uint32_t window) {
    if (closed_ || !smux_v2() || stream->closed()) {
        return;
    }
    enqueue_frame(make_update_frame(stream->wire_id(), consumed, window));
}

void WebSocketMuxSession::stream_close(const std::shared_ptr<WebSocketMuxStreamState> &stream) {
    streams_.erase(stream->wire_id());
    pending_opens_.erase(stream->operation_id());
    if (!closed_ && !stream->end_enqueued()) {
        stream->mark_end_enqueued();
        enqueue_frame(make_close_frame(stream->wire_id()));
    }
}

void WebSocketMuxSession::fail_pending(const boost::system::error_code &error) {
    auto pending = std::move(pending_opens_);
    pending_opens_.clear();
    for (auto &[id, entry] : pending) {
        (void)id;
        entry.stream->on_open_error(error);
        entry.handler.send(core::fail(stream_error(error, "WebSocket mux stream open failed")));
    }
}

void WebSocketMuxSession::fail(const boost::system::error_code &error) {
    if (closed_) {
        return;
    }
    closed_ = true;
    writes_.clear();
    fail_pending(error);
    auto streams = std::move(streams_);
    streams_.clear();
    if (carrier_) {
        carrier_->close();
    }
    for (auto &[wire_id, stream] : streams) {
        (void)wire_id;
        stream->on_session_error(error);
    }
}

void WebSocketMuxSession::stop() noexcept {
    if (closed_) {
        return;
    }
    fail(boost::asio::error::operation_aborted);
}

class WebSocketMuxHandshakeOperation final
    : public WebSocketMuxHandshake,
      public std::enable_shared_from_this<WebSocketMuxHandshakeOperation> {
  public:
    WebSocketMuxHandshakeOperation(std::unique_ptr<io::StreamHandle> websocket,
                                   WebSocketMuxOptions options, WebSocketMuxHandler handler)
        : executor_(websocket->executor()), websocket_(std::move(websocket)),
          options_(std::move(options)), handler_(std::move(handler)) {}

    void start() {
        auto self = shared_from_this();
        boost::asio::post(executor_, [self] {
            if (self->options_.max_frame_size == 0 ||
                self->options_.max_frame_size > kMaximumMuxFrameSize ||
                (self->options_.protocol == WebSocketMuxProtocol::smux &&
                 (self->options_.smux_version < 1 || self->options_.smux_version > 2)) ||
                (self->options_.protocol == WebSocketMuxProtocol::smux &&
                 (self->options_.smux_stream_buffer == 0 ||
                  self->options_.smux_stream_buffer > std::numeric_limits<std::uint32_t>::max())) ||
                self->options_.max_concurrent_streams == 0) {
                self->finish_failure(
                    {core::ErrorCode::configuration, "WebSocket mux options are invalid", {}});
                return;
            }
            auto session =
                std::make_shared<WebSocketMuxSession>(std::move(self->websocket_), self->options_);
            session->start();
            self->finish_success(std::move(session));
        });
    }

    void cancel() noexcept override {
        try {
            auto self = shared_from_this();
            boost::asio::post(executor_, [self] {
                if (self->completed_) {
                    return;
                }
                if (self->websocket_) {
                    self->websocket_->close();
                }
                self->finish_failure(
                    {core::ErrorCode::cancelled, "WebSocket mux handshake was cancelled", {}});
            });
        } catch (...) {
            if (websocket_) {
                websocket_->close();
            }
        }
    }

  private:
    using Session = clash_native::io::MultiplexedSession;

    void finish_success(std::shared_ptr<Session> session) {
        finish(core::Result<std::shared_ptr<Session>>(std::move(session)));
    }

    void finish_failure(core::Error error) {
        finish(core::Result<std::shared_ptr<Session>>(core::fail(std::move(error))));
    }

    void finish(core::Result<std::shared_ptr<Session>> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        auto handler = std::move(handler_);
        if (handler) {
            boost::asio::post(executor_,
                              [handler = std::move(handler), result = std::move(result)]() mutable {
                                  handler(std::move(result));
                              });
        }
    }

    boost::asio::any_io_executor executor_;
    std::unique_ptr<io::StreamHandle> websocket_;
    WebSocketMuxOptions options_;
    WebSocketMuxHandler handler_;
    bool completed_ = false;
};

} // namespace

std::shared_ptr<WebSocketMuxHandshake>
async_open_websocket_mux(std::unique_ptr<io::StreamHandle> websocket, WebSocketMuxOptions options,
                         WebSocketMuxHandler handler) {
    if (!websocket || !handler) {
        if (websocket) {
            websocket->close();
        }
        if (handler) {
            handler(core::fail({core::ErrorCode::configuration,
                                "WebSocket mux requires a stream and completion handler",
                                {}}));
        }
        return {};
    }
    auto operation = std::make_shared<WebSocketMuxHandshakeOperation>(
        std::move(websocket), std::move(options), std::move(handler));
    operation->start();
    return operation;
}

} // namespace clash_native::transport::shadowsocks
