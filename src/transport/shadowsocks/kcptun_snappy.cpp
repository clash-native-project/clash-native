#include <clash_native/transport/shadowsocks/kcptun_snappy.hpp>

#include <snappy.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::array<std::uint8_t, 10> kStreamIdentifier{0xff, 0x06, 0x00, 0x00, 0x73,
                                                         0x4e, 0x61, 0x50, 0x70, 0x59};
constexpr std::size_t kChunkHeaderSize = 4;
constexpr std::size_t kChunkChecksumSize = 4;
// The framed Snappy format uses a three-byte little-endian length.  The
// implementation currently emits 32 KiB chunks, but keep the parser at the
// format limit so extension chunks are not silently truncated.
constexpr std::size_t kMaximumChunkPayload = 0x00ffffff;
constexpr std::size_t kCompressionChunkSize = 32 * 1024;

void put_u24(std::uint8_t *output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8);
    output[2] = static_cast<std::uint8_t>(value >> 16);
}

std::uint32_t get_u24(const std::uint8_t *input) {
    return static_cast<std::uint32_t>(input[0]) | (static_cast<std::uint32_t>(input[1]) << 8) |
           (static_cast<std::uint32_t>(input[2]) << 16);
}

std::uint32_t crc32c(std::span<const std::uint8_t> input) {
    static const auto table = [] {
        std::array<std::uint32_t, 256> result{};
        for (std::uint32_t index = 0; index < result.size(); ++index) {
            auto value = index;
            for (int bit = 0; bit < 8; ++bit) {
                value = (value & 1U) != 0 ? (value >> 1U) ^ 0x82f63b78U : value >> 1U;
            }
            result[index] = value;
        }
        return result;
    }();
    auto value = 0xffffffffU;
    for (const auto byte : input) {
        value = table[(value ^ byte) & 0xffU] ^ (value >> 8U);
    }
    return value ^ 0xffffffffU;
}

std::uint32_t masked_crc32c(std::span<const std::uint8_t> input) {
    const auto value = crc32c(input);
    return ((value >> 15U) | (value << 17U)) + 0xa282ead8U;
}

void put_u32(std::uint8_t *output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8);
    output[2] = static_cast<std::uint8_t>(value >> 16);
    output[3] = static_cast<std::uint8_t>(value >> 24);
}

std::uint32_t get_u32(const std::uint8_t *input) {
    return static_cast<std::uint32_t>(input[0]) | (static_cast<std::uint32_t>(input[1]) << 8) |
           (static_cast<std::uint32_t>(input[2]) << 16) |
           (static_cast<std::uint32_t>(input[3]) << 24);
}

class SnappyStreamState final : public std::enable_shared_from_this<SnappyStreamState> {
  public:
    explicit SnappyStreamState(std::unique_ptr<core::StreamHandle> transport)
        : transport_(std::move(transport)) {}

    void start() { read_identifier(); }

    boost::asio::any_io_executor executor() noexcept { return transport_->executor(); }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        return transport_->local_endpoint(error);
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
        if (closed_) {
            post_write(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_write(std::move(handler), {}, 0);
            return;
        }
        auto packet = std::make_shared<std::vector<std::uint8_t>>();
        if (!write_identifier_sent_) {
            packet->insert(packet->end(), kStreamIdentifier.begin(), kStreamIdentifier.end());
            write_identifier_sent_ = true;
        }
        const auto *data = static_cast<const std::uint8_t *>(buffer.data());
        for (std::size_t offset = 0; offset < buffer.size();) {
            const auto size = std::min(kCompressionChunkSize, buffer.size() - offset);
            append_chunk(*packet, std::span<const std::uint8_t>(data + offset, size));
            offset += size;
        }
        writes_.push_back({std::move(packet), std::move(handler), buffer.size()});
        pump_write();
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        if (closed_) {
            error = boost::asio::error::operation_aborted;
            return;
        }
        transport_->shutdown_send(error);
    }

    void close() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (transport_) {
            transport_->close();
        }
        writes_.clear();
        finish_read(boost::asio::error::operation_aborted, 0);
        finish_write(boost::asio::error::operation_aborted, 0);
    }

  private:
    struct PendingWrite {
        std::shared_ptr<std::vector<std::uint8_t>> packet;
        core::StreamHandle::WriteHandler handler;
        std::size_t size = 0;
    };

    void append_chunk(std::vector<std::uint8_t> &output, std::span<const std::uint8_t> plaintext) {
        std::string compressed;
        snappy::Compress(reinterpret_cast<const char *>(plaintext.data()), plaintext.size(),
                         &compressed);
        const bool use_compressed =
            compressed.size() + kChunkChecksumSize < plaintext.size() + kChunkChecksumSize;
        const auto type = use_compressed ? std::uint8_t{0x00} : std::uint8_t{0x01};
        const auto payload_size =
            (use_compressed ? compressed.size() : plaintext.size()) + kChunkChecksumSize;
        if (payload_size > kMaximumChunkPayload) {
            return;
        }
        const auto old_size = output.size();
        output.resize(old_size + kChunkHeaderSize + payload_size);
        output[old_size] = type;
        put_u24(output.data() + old_size + 1, static_cast<std::uint32_t>(payload_size));
        put_u32(output.data() + old_size + kChunkHeaderSize, masked_crc32c(plaintext));
        if (use_compressed) {
            std::copy(compressed.begin(), compressed.end(),
                      output.begin() + old_size + kChunkHeaderSize + kChunkChecksumSize);
        } else {
            std::copy(plaintext.begin(), plaintext.end(),
                      output.begin() + old_size + kChunkHeaderSize + kChunkChecksumSize);
        }
    }

    void pump_write() {
        if (closed_ || write_in_progress_ || writes_.empty()) {
            return;
        }
        write_in_progress_ = true;
        auto pending = std::move(writes_.front());
        writes_.pop_front();
        auto packet = pending.packet;
        auto self = shared_from_this();
        transport_->async_write(boost::asio::buffer(*packet),
                                [self, pending = std::move(pending)](
                                    const boost::system::error_code &error, std::size_t) mutable {
                                    self->write_in_progress_ = false;
                                    if (error) {
                                        self->close_with_error(error);
                                        return;
                                    }
                                    if (pending.handler) {
                                        pending.handler({}, pending.size);
                                    }
                                    self->pump_write();
                                });
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

    void read_identifier() {
        auto identifier = std::make_shared<std::array<std::uint8_t, kStreamIdentifier.size()>>();
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(*identifier), [self, identifier](const auto &error) {
            if (error) {
                self->close_with_error(error);
                return;
            }
            if (!std::equal(identifier->begin(), identifier->end(), kStreamIdentifier.begin())) {
                self->close_with_error(
                    boost::system::errc::make_error_code(boost::system::errc::protocol_error));
                return;
            }
            self->read_chunk_header();
        });
    }

    void read_chunk_header() {
        if (closed_) {
            return;
        }
        auto header = std::make_shared<std::array<std::uint8_t, kChunkHeaderSize>>();
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(*header), [self, header](const auto &error) {
            if (error) {
                self->close_with_error(error);
                return;
            }
            const auto type = (*header)[0];
            const auto length = get_u24(header->data() + 1);
            if (type >= 0x80 && type <= 0xfe) {
                self->read_skip_chunk(length);
                return;
            }
            if (type != 0x00 && type != 0x01 || length < kChunkChecksumSize) {
                self->close_with_error(
                    boost::system::errc::make_error_code(boost::system::errc::protocol_error));
                return;
            }
            auto payload = std::make_shared<std::vector<std::uint8_t>>(length);
            self->read_exact(boost::asio::buffer(*payload),
                             [self, type, payload](const auto &payload_error) {
                                 if (payload_error) {
                                     self->close_with_error(payload_error);
                                     return;
                                 }
                                 self->handle_chunk(type, *payload);
                             });
        });
    }

    void read_skip_chunk(std::size_t length) {
        auto payload = std::make_shared<std::vector<std::uint8_t>>(length);
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(*payload), [self](const auto &error) {
            if (error) {
                self->close_with_error(error);
                return;
            }
            self->read_chunk_header();
        });
    }

    void handle_chunk(std::uint8_t type, const std::vector<std::uint8_t> &payload) {
        const auto expected_crc = get_u32(payload.data());
        std::vector<std::uint8_t> decoded;
        const auto data = std::span<const std::uint8_t>(payload).subspan(kChunkChecksumSize);
        if (type == 0x00) {
            std::size_t size = 0;
            if (!snappy::GetUncompressedLength(reinterpret_cast<const char *>(data.data()),
                                               data.size(), &size)) {
                close_with_error(
                    boost::system::errc::make_error_code(boost::system::errc::protocol_error));
                return;
            }
            decoded.resize(size);
            if (!snappy::RawUncompress(reinterpret_cast<const char *>(data.data()), data.size(),
                                       reinterpret_cast<char *>(decoded.data()))) {
                close_with_error(
                    boost::system::errc::make_error_code(boost::system::errc::protocol_error));
                return;
            }
        } else {
            decoded.assign(data.begin(), data.end());
        }
        if (masked_crc32c(decoded) != expected_crc) {
            close_with_error(
                boost::system::errc::make_error_code(boost::system::errc::protocol_error));
            return;
        }
        if (!decoded.empty()) {
            incoming_.push_back(std::make_shared<std::vector<std::uint8_t>>(std::move(decoded)));
            deliver_read();
        }
        read_chunk_header();
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
        std::size_t copied = 0;
        while (copied < read_buffer_.size() && !incoming_.empty()) {
            auto &front = incoming_.front();
            const auto count =
                std::min(front->size() - incoming_offset_, read_buffer_.size() - copied);
            std::memcpy(static_cast<std::uint8_t *>(read_buffer_.data()) + copied,
                        front->data() + incoming_offset_, count);
            copied += count;
            incoming_offset_ += count;
            if (incoming_offset_ == front->size()) {
                incoming_.pop_front();
                incoming_offset_ = 0;
            }
        }
        finish_read({}, copied);
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

    void finish_write(const boost::system::error_code &error, std::size_t) {
        for (auto &pending : writes_) {
            if (pending.handler) {
                pending.handler(error, 0);
            }
        }
        writes_.clear();
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
    std::deque<PendingWrite> writes_;
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>> incoming_;
    boost::asio::mutable_buffer read_buffer_;
    core::StreamHandle::ReadHandler read_handler_;
    std::size_t incoming_offset_ = 0;
    bool write_identifier_sent_ = false;
    bool write_in_progress_ = false;
    bool remote_closed_ = false;
    bool closed_ = false;
};

class SnappyStream final : public core::StreamHandle {
  public:
    explicit SnappyStream(std::shared_ptr<SnappyStreamState> state) : state_(std::move(state)) {}

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
    std::shared_ptr<SnappyStreamState> state_;
};

} // namespace

core::Result<std::unique_ptr<core::StreamHandle>>
make_kcptun_snappy_stream(std::unique_ptr<core::StreamHandle> transport) {
    if (!transport) {
        return core::fail({core::ErrorCode::configuration,
                           "kcptun Snappy stream requires an underlying stream",
                           {}});
    }
    auto state = std::make_shared<SnappyStreamState>(std::move(transport));
    state->start();
    return std::unique_ptr<core::StreamHandle>(std::make_unique<SnappyStream>(std::move(state)));
}

} // namespace clash_native::transport::shadowsocks
