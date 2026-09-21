#include <clash_native/transport/shadowsocks/kcptun.hpp>

#include <clash_native/net/udp_stream.hpp>
#include <clash_native/transport/kcp_client.hpp>
#include <clash_native/transport/shadowsocks/crypto.hpp>
#include <clash_native/transport/shadowsocks/kcptun_packet_codec.hpp>
#include <clash_native/transport/shadowsocks/kcptun_snappy.hpp>

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
#include <string>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kSmuxHeaderSize = 8;
constexpr std::uint8_t kSmuxSyn = 0;
constexpr std::uint8_t kSmuxFin = 1;
constexpr std::uint8_t kSmuxPush = 2;
constexpr std::uint8_t kSmuxNop = 3;
constexpr std::uint8_t kSmuxUpdate = 4;
constexpr std::size_t kMaximumSmuxFrameSize = std::numeric_limits<std::uint16_t>::max();
constexpr std::uint32_t kSmuxInitialPeerWindow = 262144;

boost::system::error_code protocol_error() {
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

core::Error configuration_error(std::string message) {
    return {core::ErrorCode::configuration, std::move(message), {}};
}

core::Error unsupported_error(std::string message) {
    return {core::ErrorCode::unsupported, std::move(message), {}};
}

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

class SmuxStreamState final : public std::enable_shared_from_this<SmuxStreamState> {
  public:
    SmuxStreamState(std::unique_ptr<core::StreamHandle> transport, KcptunClientOptions options)
        : transport_(std::move(transport)), options_(std::move(options)),
          timer_(transport_->executor()) {}

    void start() {
        auto syn = make_frame(kSmuxSyn, {});
        enqueue_packet(std::move(syn), {});
        pump_write();
        read_header();
        schedule_keepalive();
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
        read_buffer_ = buffer;
        read_handler_ = std::move(handler);
        deliver_read();
    }

    void async_write(boost::asio::const_buffer buffer, core::StreamHandle::WriteHandler handler) {
        if (closed_ || local_closed_) {
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

        const auto size = buffer.size();
        auto pending = std::make_shared<PendingWrite>();
        pending->handler = std::move(handler);
        pending->size = size;
        pending->data = std::make_shared<std::vector<std::uint8_t>>(
            static_cast<const std::uint8_t *>(buffer.data()),
            static_cast<const std::uint8_t *>(buffer.data()) + size);
        write_handler_ = pending;
        pump_write();
    }

    boost::asio::any_io_executor executor() noexcept { return transport_->executor(); }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        return transport_->local_endpoint(error);
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
        closed_ = true;
        timer_.cancel();
        if (transport_) {
            transport_->close();
        }
        queued_writes_.clear();
        finish_read(boost::asio::error::operation_aborted, 0);
        finish_write(boost::asio::error::operation_aborted, 0);
    }

  private:
    struct PendingWrite {
        core::StreamHandle::WriteHandler handler;
        std::size_t size = 0;
        std::size_t offset = 0;
        std::shared_ptr<std::vector<std::uint8_t>> data;
        bool failed = false;
    };

    struct QueuedWrite {
        std::shared_ptr<std::vector<std::uint8_t>> packet;
        std::shared_ptr<PendingWrite> pending;
    };

    std::vector<std::uint8_t> make_frame(std::uint8_t command,
                                         std::vector<std::uint8_t> payload) const {
        std::vector<std::uint8_t> frame(kSmuxHeaderSize + payload.size());
        frame[0] = static_cast<std::uint8_t>(options_.smux_version);
        frame[1] = command;
        put_u16(frame.data() + 2, static_cast<std::uint16_t>(payload.size()));
        put_u32(frame.data() + 4, stream_id_);
        std::copy(payload.begin(), payload.end(), frame.begin() + kSmuxHeaderSize);
        return frame;
    }

    void enqueue_packet(std::vector<std::uint8_t> packet, std::shared_ptr<PendingWrite> pending) {
        queued_writes_.push_back(
            {std::make_shared<std::vector<std::uint8_t>>(std::move(packet)), std::move(pending)});
    }

    void pump_write() {
        if (closed_ || write_in_progress_) {
            return;
        }
        if (queued_writes_.empty()) {
            if (write_handler_ && write_handler_->offset < write_handler_->size) {
                auto &pending = *write_handler_;
                auto available = pending.size - pending.offset;
                if (options_.smux_version == 2) {
                    const auto in_flight = bytes_sent_ - peer_consumed_;
                    if (in_flight >= peer_window_) {
                        return;
                    }
                    available = std::min<std::size_t>(
                        available, static_cast<std::size_t>(peer_window_ - in_flight));
                }
                const auto chunk_size = std::min<std::size_t>(options_.frame_size, available);
                std::vector<std::uint8_t> payload(
                    pending.data->begin() + static_cast<std::ptrdiff_t>(pending.offset),
                    pending.data->begin() +
                        static_cast<std::ptrdiff_t>(pending.offset + chunk_size));
                pending.offset += chunk_size;
                if (options_.smux_version == 2) {
                    bytes_sent_ += static_cast<std::uint32_t>(chunk_size);
                }
                enqueue_packet(make_frame(kSmuxPush, std::move(payload)), write_handler_);
            } else if (write_handler_ && write_handler_->offset == write_handler_->size) {
                auto pending = write_handler_;
                finish_pending_write(pending, {});
            }
            if (queued_writes_.empty() && fin_requested_ && !fin_enqueued_) {
                fin_enqueued_ = true;
                enqueue_packet(make_frame(kSmuxFin, {}), {});
            }
        }
        if (queued_writes_.empty()) {
            return;
        }
        write_in_progress_ = true;
        auto queued = std::move(queued_writes_.front());
        queued_writes_.pop_front();
        auto packet = std::move(queued.packet);
        auto pending = std::move(queued.pending);
        auto self = shared_from_this();
        transport_->async_write(
            boost::asio::buffer(*packet),
            [self, packet, pending](const boost::system::error_code &error, std::size_t) mutable {
                self->write_in_progress_ = false;
                if (error) {
                    self->close_with_error(error);
                    return;
                }
                self->pump_write();
            });
    }

    void read_header() {
        if (closed_) {
            return;
        }
        auto header = std::make_shared<std::array<std::uint8_t, kSmuxHeaderSize>>();
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(*header),
                   [self, header](const boost::system::error_code &error) {
                       if (error) {
                           self->close_with_error(error);
                           return;
                       }
                       if ((*header)[0] != static_cast<std::uint8_t>(self->options_.smux_version)) {
                           self->close_with_error(protocol_error());
                           return;
                       }
                       const auto length = get_u16(header->data() + 2);
                       if (length > self->options_.frame_size) {
                           self->close_with_error(boost::asio::error::message_size);
                           return;
                       }
                       auto payload = std::make_shared<std::vector<std::uint8_t>>(length);
                       self->read_payload(*header, std::move(payload));
                   });
    }

    void read_payload(const std::array<std::uint8_t, kSmuxHeaderSize> &header,
                      std::shared_ptr<std::vector<std::uint8_t>> payload) {
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(*payload),
                   [self, header, payload](const boost::system::error_code &error) {
                       if (error) {
                           self->close_with_error(error);
                           return;
                       }
                       self->handle_frame(header, *payload);
                       if (!self->closed_) {
                           self->read_header();
                       }
                   });
    }

    void handle_frame(const std::array<std::uint8_t, kSmuxHeaderSize> &header,
                      const std::vector<std::uint8_t> &payload) {
        const auto command = header[1];
        const auto stream_id = get_u32(header.data() + 4);
        if (command == kSmuxNop) {
            return;
        }
        if (command == kSmuxPush) {
            if (stream_id != stream_id_ || payload.empty()) {
                return;
            }
            incoming_.push_back(std::make_shared<std::vector<std::uint8_t>>(payload));
            deliver_read();
            return;
        }
        if (command == kSmuxFin) {
            if (stream_id == stream_id_) {
                remote_closed_ = true;
                deliver_read();
            }
            return;
        }
        if (command == kSmuxUpdate) {
            if (options_.smux_version != 2 || stream_id != stream_id_ || payload.size() != 8) {
                close_with_error(protocol_error());
                return;
            }
            peer_consumed_ = get_u32(payload.data());
            peer_window_ = get_u32(payload.data() + 4);
            pump_write();
            return;
        }
        if (command == kSmuxSyn) {
            return;
        }
        close_with_error(protocol_error());
    }

    using ReadExactHandler = std::function<void(const boost::system::error_code &)>;

    void read_exact(boost::asio::mutable_buffer buffer, ReadExactHandler handler,
                    std::size_t offset = 0) {
        if (closed_) {
            handler(boost::asio::error::operation_aborted);
            return;
        }
        if (offset == buffer.size()) {
            handler({});
            return;
        }
        auto self = shared_from_this();
        transport_->async_read_some(
            boost::asio::buffer(static_cast<std::uint8_t *>(buffer.data()) + offset,
                                buffer.size() - offset),
            [self, buffer, handler = std::move(handler),
             offset](const boost::system::error_code &error, std::size_t size) mutable {
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

    void deliver_read() {
        if (!read_handler_) {
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
            enqueue_packet(make_frame(kSmuxUpdate, std::move(update)), {});
            pump_write();
        }
    }

    void schedule_keepalive() {
        if (closed_ || options_.keepalive_seconds <= 0) {
            return;
        }
        timer_.expires_after(std::chrono::seconds(options_.keepalive_seconds));
        auto self = shared_from_this();
        timer_.async_wait([self](const boost::system::error_code &error) {
            if (error || self->closed_) {
                return;
            }
            self->enqueue_packet(self->make_frame(kSmuxNop, {}), {});
            self->pump_write();
            self->schedule_keepalive();
        });
    }

    void close_with_error(const boost::system::error_code &error) {
        if (closed_) {
            return;
        }
        finish_read(error, 0);
        finish_write(error, 0);
        close();
    }

    void finish_read(const boost::system::error_code &error, std::size_t size) {
        if (!read_handler_) {
            return;
        }
        auto handler = std::move(read_handler_);
        read_buffer_ = {};
        handler(error, size);
    }

    void finish_pending_write(const std::shared_ptr<PendingWrite> &pending,
                              const boost::system::error_code &error) {
        if (!pending || pending->failed) {
            return;
        }
        pending->failed = static_cast<bool>(error);
        auto handler = std::move(pending->handler);
        if (write_handler_ == pending) {
            write_handler_.reset();
        }
        if (handler) {
            handler(error, error ? 0 : pending->size);
        }
    }

    void finish_write(const boost::system::error_code &error, std::size_t) {
        if (write_handler_) {
            finish_pending_write(write_handler_, error);
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

    std::unique_ptr<core::StreamHandle> transport_;
    KcptunClientOptions options_;
    boost::asio::steady_timer timer_;
    boost::asio::mutable_buffer read_buffer_;
    core::StreamHandle::ReadHandler read_handler_;
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>> incoming_;
    std::size_t incoming_offset_ = 0;
    std::deque<QueuedWrite> queued_writes_;
    std::shared_ptr<PendingWrite> write_handler_;
    const std::uint32_t stream_id_ = 1;
    std::uint32_t peer_consumed_ = 0;
    std::uint32_t peer_window_ = kSmuxInitialPeerWindow;
    std::uint32_t bytes_sent_ = 0;
    std::uint32_t bytes_consumed_ = 0;
    std::uint32_t consumed_since_update_ = 0;
    bool fin_requested_ = false;
    bool fin_enqueued_ = false;
    bool write_in_progress_ = false;
    bool local_closed_ = false;
    bool remote_closed_ = false;
    bool closed_ = false;
};

class SmuxStream final : public core::StreamHandle {
  public:
    explicit SmuxStream(std::shared_ptr<SmuxStreamState> state) : state_(std::move(state)) {}

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
    std::shared_ptr<SmuxStreamState> state_;
};

core::Status validate_options(const KcptunClientOptions &options) {
    static constexpr std::array<std::string_view, 15> crypt_methods{
        "null",    "none",  "aes",  "aes-128", "aes-192", "tea",         "xor", "blowfish",
        "twofish", "cast5", "3des", "xtea",    "salsa20", "aes-128-gcm", ""};
    if (std::find(crypt_methods.begin(), crypt_methods.end(), options.crypt) ==
        crypt_methods.end()) {
        return core::fail(unsupported_error("unsupported kcptun packet crypt method"));
    }
    if ((options.data_shard == 0) != (options.parity_shard == 0) || options.data_shard < 0 ||
        options.parity_shard < 0 || options.data_shard + options.parity_shard > 256) {
        return core::fail(configuration_error("invalid kcptun FEC shard counts"));
    }
    if (options.smux_version != 1 && options.smux_version != 2) {
        return core::fail(configuration_error("Shadowsocks kcptun SMUX version must be 1 or 2"));
    }
    if (options.mode != "normal" && options.mode != "fast" && options.mode != "fast2" &&
        options.mode != "fast3") {
        return core::fail(configuration_error("unsupported Shadowsocks kcptun mode"));
    }
    if (options.connection_count <= 0 || options.auto_expire_seconds < 0 ||
        options.scavenge_ttl_seconds <= 0 || options.rate_limit < 0 || options.dscp < 0 ||
        options.dscp > 63 || options.socket_buffer < 0) {
        return core::fail(configuration_error("invalid Shadowsocks kcptun session options"));
    }
    if (options.mtu <= 24 || options.mtu > 1400 || options.send_window <= 0 ||
        options.receive_window <= 0 || options.interval_ms <= 0 || options.interval_ms > 1000 ||
        options.nodelay < 0 || options.fast_resend < 0 ||
        (options.disable_congestion_control != 0 && options.disable_congestion_control != 1) ||
        options.frame_size <= 0 || options.frame_size > static_cast<int>(kMaximumSmuxFrameSize) ||
        options.smux_buffer <= 0 || options.stream_buffer <= 0 ||
        options.stream_buffer > options.smux_buffer) {
        return core::fail(configuration_error("invalid Shadowsocks kcptun options"));
    }
    return {};
}

void apply_mode_defaults(KcptunClientOptions &options) {
    if (options.mode == "normal") {
        options.nodelay = 0;
        options.interval_ms = 40;
        options.fast_resend = 2;
        options.disable_congestion_control = 1;
    } else if (options.mode == "fast") {
        options.nodelay = 0;
        options.interval_ms = 30;
        options.fast_resend = 2;
        options.disable_congestion_control = 1;
    } else if (options.mode == "fast2") {
        options.nodelay = 1;
        options.interval_ms = 20;
        options.fast_resend = 2;
        options.disable_congestion_control = 1;
    } else if (options.mode == "fast3") {
        options.nodelay = 1;
        options.interval_ms = 10;
        options.fast_resend = 2;
        options.disable_congestion_control = 1;
    }
}

} // namespace

core::Status validate_kcptun_client_options(const KcptunClientOptions &options) {
    return validate_options(options);
}

core::Result<std::unique_ptr<core::StreamHandle>>
make_kcptun_carrier(runtime::AsioRuntime &runtime, boost::asio::ip::udp::endpoint remote_endpoint,
                    KcptunClientOptions options) {
    apply_mode_defaults(options);
    if (const auto validation = validate_options(options); !validation) {
        return core::fail(validation.error());
    }

    auto packet_codec = KcptunPacketCodec::create(options.key, options.crypt, options.data_shard,
                                                  options.parity_shard);
    if (!packet_codec) {
        return core::fail(packet_codec.error());
    }

    auto socket = std::make_unique<net::UdpStream>(runtime.context().get_executor());
    boost::system::error_code error;
    socket->open(remote_endpoint.protocol(), error);
    if (!error) {
        socket->bind({remote_endpoint.address().is_v4()
                          ? boost::asio::ip::address(boost::asio::ip::address_v4::any())
                          : boost::asio::ip::address(boost::asio::ip::address_v6::any()),
                      0},
                     error);
    }
    if (error) {
        return core::fail(
            {core::ErrorCode::transport_io, "failed to open Shadowsocks kcptun UDP socket", {}});
    }
    if (options.socket_buffer > 0) {
        socket->set_buffer_size(options.socket_buffer, error);
        if (error) {
            return core::fail({core::ErrorCode::transport_io,
                               "failed to configure kcptun UDP socket buffer",
                               {}});
        }
    }
    if (options.dscp > 0) {
        socket->set_dscp(options.dscp, error);
        if (error) {
            return core::fail(
                {core::ErrorCode::transport_io, "failed to configure kcptun UDP DSCP", {}});
        }
    }

    std::array<std::uint8_t, sizeof(std::uint32_t)> conversation_bytes{};
    if (!random_bytes(conversation_bytes)) {
        return core::fail({core::ErrorCode::authentication,
                           "failed to generate Shadowsocks kcptun conversation ID",
                           {}});
    }
    std::uint32_t conversation_id = 0;
    for (std::size_t index = 0; index < conversation_bytes.size(); ++index) {
        conversation_id |= static_cast<std::uint32_t>(conversation_bytes[index]) << (index * 8);
    }
    if (conversation_id == 0) {
        conversation_id = 1;
    }

    transport::KcpClientOptions kcp_options;
    kcp_options.conversation_id = conversation_id;
    kcp_options.mtu = options.mtu;
    kcp_options.send_window = options.send_window;
    kcp_options.receive_window = options.receive_window;
    kcp_options.nodelay = options.nodelay;
    kcp_options.interval_ms = options.interval_ms;
    kcp_options.fast_resend = options.fast_resend;
    kcp_options.disable_congestion_control = options.disable_congestion_control;
    kcp_options.ack_nodelay = options.ack_nodelay;
    kcp_options.rate_limit = options.rate_limit;
    kcp_options.encode_packet = [codec =
                                     packet_codec.value()](std::span<const std::uint8_t> packet) {
        return codec->encode(packet);
    };
    kcp_options.decode_packet = [codec =
                                     packet_codec.value()](std::span<const std::uint8_t> packet) {
        return codec->decode(packet);
    };
    auto kcp = make_kcp_client_stream(std::move(socket), remote_endpoint, kcp_options);
    if (!kcp) {
        return core::fail(kcp.error());
    }

    std::unique_ptr<core::StreamHandle> carrier = std::move(kcp.value());
    if (!options.no_compression) {
        auto compressed = make_kcptun_snappy_stream(std::move(carrier));
        if (!compressed) {
            return core::fail(compressed.error());
        }
        carrier = std::move(compressed.value());
    }
    return carrier;
}

core::Result<std::unique_ptr<core::StreamHandle>>
make_kcptun_client_stream(runtime::AsioRuntime &runtime,
                          boost::asio::ip::udp::endpoint remote_endpoint,
                          KcptunClientOptions options) {
    auto carrier = make_kcptun_carrier(runtime, remote_endpoint, options);
    if (!carrier) {
        return core::fail(carrier.error());
    }
    auto state = std::make_shared<SmuxStreamState>(std::move(carrier.value()), std::move(options));
    state->start();
    return std::unique_ptr<core::StreamHandle>(std::make_unique<SmuxStream>(std::move(state)));
}

} // namespace clash_native::transport::shadowsocks
