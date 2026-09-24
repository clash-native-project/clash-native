#include <clash_native/transport/shadowsocks/shadow_tls.hpp>
#include <clash_native/transport/shadowsocks/shadow_tls_v3.hpp>

#include <clash_native/async/callback_sender.hpp>

#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/transport/proxy/crypto.hpp>
#include <clash_native/transport/tls_client.hpp>
#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <openssl/digest.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

using StreamReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
using StreamWriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

constexpr std::size_t kTlsHeaderSize = 5;
constexpr std::size_t kTlsHmacSize = 4;
constexpr std::size_t kMaxTlsPlaintext = 16384;
constexpr std::uint8_t kApplicationRecord = 23;

core::Error configuration_error(std::string context) {
    return {core::ErrorCode::configuration, std::move(context), {}};
}

core::Error protocol_error(std::string context) {
    return {core::ErrorCode::carrier_handshake, std::move(context), {}};
}

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "Shadow-TLS handshake was cancelled", {}};
}

core::Error io_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

std::vector<std::uint8_t> hmac_sha1(std::string_view key, std::span<const std::uint8_t> data) {
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> output{};
    unsigned int output_size = 0;
    if (!HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
              output.data(), &output_size)) {
        return {};
    }
    return {output.begin(), output.begin() + output_size};
}

class HashingReadStream final : public io::StreamHandle {
  public:
    HashingReadStream(std::unique_ptr<io::StreamHandle> stream, std::string password)
        : stream_(std::move(stream)), password_(std::move(password)) {}

    std::vector<std::uint8_t> digest8() const {
        const auto digest = hmac_sha1(password_, received_);
        if (digest.size() < 8) {
            return {};
        }
        return {digest.begin(), digest.begin() + 8};
    }

    // The inner handle is already sender-based: hash as a side effect in a
    // then-stage. `this` stays alive through the pull by the single
    // outstanding pull contract (same rule as channel state).
    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        return io::AnySender<std::optional<std::size_t>>{
            stream_->async_read_some(buffer) |
            stdexec::then([this, buffer](std::optional<std::size_t> count) {
                if (count && *count != 0) {
                    const auto *bytes = static_cast<const std::uint8_t *>(buffer.data());
                    received_.insert(received_.end(), bytes, bytes + *count);
                }
                return count;
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        return stream_->async_write(buffer);
    }

    boost::asio::any_io_executor executor() noexcept override { return stream_->executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        return stream_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        stream_->shutdown_send(error);
    }

    void close() noexcept override { stream_->close(); }

  private:
    std::unique_ptr<io::StreamHandle> stream_;
    std::string password_;
    std::vector<std::uint8_t> received_;
};

class FramedStreamBase {
  protected:
    explicit FramedStreamBase(std::unique_ptr<io::StreamHandle> stream)
        : stream_(std::move(stream)) {}

    using ExactHandler = std::function<void(const boost::system::error_code &)>;

    void read_exact(boost::asio::mutable_buffer buffer, ExactHandler handler) {
        read_exact_impl(buffer, 0, std::move(handler));
    }

    void read_exact_impl(boost::asio::mutable_buffer buffer, std::size_t offset,
                         ExactHandler handler) {
        if (offset == buffer.size()) {
            boost::asio::post(stream_->executor(),
                              [handler = std::move(handler)]() mutable { handler({}); });
            return;
        }
        auto self = shared_from_this_base();
        net::start_read_for_handler(
            stream_->async_read_some(boost::asio::mutable_buffer(
                static_cast<std::uint8_t *>(buffer.data()) + offset, buffer.size() - offset)),
            [self, buffer, offset, handler = std::move(handler)](
                const boost::system::error_code &error, std::size_t size) mutable {
                if (error) {
                    handler(error);
                    return;
                }
                if (size == 0) {
                    handler(boost::asio::error::eof);
                    return;
                }
                self->read_exact_impl(buffer, offset + size, std::move(handler));
            });
    }

    // The concrete stream supplies this alias so the helper can keep the
    // continuation alive without exposing its implementation type.
    virtual std::shared_ptr<FramedStreamBase> shared_from_this_base() = 0;

    std::unique_ptr<io::StreamHandle> stream_;
};

class ShadowTlsV2Stream final : public io::StreamHandle,
                                public FramedStreamBase,
                                public std::enable_shared_from_this<ShadowTlsV2Stream> {
  public:
    // Internal machinery stays handler-style; only the public overrides below
    // speak senders.
    using ReadHandler = StreamReadHandler;
    using WriteHandler = StreamWriteHandler;
    using ReadSignatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;
    using WriteSignatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                           stdexec::set_error_t(std::exception_ptr),
                                                           stdexec::set_stopped_t()>;

    ShadowTlsV2Stream(std::unique_ptr<io::StreamHandle> stream, std::vector<std::uint8_t> hash)
        : FramedStreamBase(std::move(stream)), hash_(std::move(hash)) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<ReadSignatures>(
            [this, buffer](auto terminal) mutable {
                this->read_impl(buffer, [terminal = std::move(terminal)](
                                            const boost::system::error_code &error,
                                            std::size_t count) mutable { terminal(error, count); });
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
                net::translate_read(std::move(receiver), error, count, "shadow-tls read");
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        return io::AnySender<std::size_t>{async::callback_sender<WriteSignatures>(
            [this, buffer](auto terminal) mutable {
                this->write_impl(
                    buffer, [terminal = std::move(terminal)](const boost::system::error_code &error,
                                                             std::size_t count) mutable {
                        terminal(error, count);
                    });
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
                net::translate_write(std::move(receiver), error, count, "shadow-tls write");
            })};
    }

    void read_impl(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        if (read_busy_) {
            boost::asio::post(executor(), [handler = std::move(handler)]() mutable {
                handler(boost::asio::error::already_started, 0);
            });
            return;
        }
        if (pending_offset_ < pending_.size()) {
            auto pending_handler = std::make_shared<ReadHandler>(std::move(handler));
            if (copy_pending(buffer, pending_handler)) {
                return;
            }
        }
        if (buffer.size() == 0) {
            boost::asio::post(executor(),
                              [handler = std::move(handler)]() mutable { handler({}, 0); });
            return;
        }
        read_busy_ = true;
        read_buffer_ = buffer;
        read_handler_ = std::make_shared<ReadHandler>(std::move(handler));
        read_header();
    }

    void write_impl(boost::asio::const_buffer buffer, WriteHandler handler) {
        if (write_busy_) {
            boost::asio::post(executor(), [handler = std::move(handler)]() mutable {
                handler(boost::asio::error::already_started, 0);
            });
            return;
        }
        if (buffer.size() == 0) {
            boost::asio::post(executor(),
                              [handler = std::move(handler)]() mutable { handler({}, 0); });
            return;
        }
        write_busy_ = true;
        write_handler_ = std::move(handler);
        write_size_ = buffer.size();
        const auto *bytes = static_cast<const std::uint8_t *>(buffer.data());
        std::vector<std::uint8_t> payload(bytes, bytes + buffer.size());
        write_payload(std::move(payload));
    }

    void write_payload(std::vector<std::uint8_t> payload) {
        write_wire_.clear();
        if (!hash_sent_) {
            write_wire_.insert(write_wire_.end(), hash_.begin(), hash_.end());
            hash_sent_ = true;
        }
        write_wire_.insert(write_wire_.end(), payload.begin(), payload.end());
        frame_wire(write_wire_);
        write_frame();
    }

    boost::asio::any_io_executor executor() noexcept override { return stream_->executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        return stream_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        stream_->shutdown_send(error);
    }

    void close() noexcept override { stream_->close(); }

  private:
    std::shared_ptr<FramedStreamBase> shared_from_this_base() override {
        return shared_from_this();
    }

    void frame_wire(const std::vector<std::uint8_t> &payload) {
        std::vector<std::uint8_t> framed;
        framed.reserve(payload.size() + (payload.size() / kMaxTlsPlaintext + 1) * kTlsHeaderSize);
        for (std::size_t offset = 0; offset < payload.size();) {
            const auto size = std::min(kMaxTlsPlaintext, payload.size() - offset);
            framed.insert(framed.end(),
                          {kApplicationRecord, 0x03, 0x03, static_cast<std::uint8_t>(size >> 8),
                           static_cast<std::uint8_t>(size)});
            framed.insert(framed.end(), payload.begin() + static_cast<std::ptrdiff_t>(offset),
                          payload.begin() + static_cast<std::ptrdiff_t>(offset + size));
            offset += size;
        }
        write_wire_ = std::move(framed);
    }

    void write_frame() {
        auto self = shared_from_this();
        net::start_write_for_handler(stream_->async_write(boost::asio::buffer(write_wire_)),
                                     [self](const boost::system::error_code &error, std::size_t) {
                                         self->finish_write(error);
                                     });
    }

    void finish_write(const boost::system::error_code &error) {
        write_busy_ = false;
        auto handler = std::move(write_handler_);
        if (handler) {
            handler(error, error ? 0 : write_size_);
        }
    }

    void read_header() {
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(read_header_),
                   [self](const boost::system::error_code &error) {
                       if (error) {
                           self->finish_read(error, 0);
                           return;
                       }
                       if (self->read_header_[0] != kApplicationRecord ||
                           self->read_header_[1] != 0x03 || self->read_header_[2] != 0x03) {
                           self->finish_read(boost::asio::error::fault, 0);
                           return;
                       }
                       const auto size = (static_cast<std::size_t>(self->read_header_[3]) << 8) |
                                         self->read_header_[4];
                       if (size == 0 || size > 0xffff) {
                           self->finish_read(boost::asio::error::fault, 0);
                           return;
                       }
                       self->read_payload_.resize(size);
                       self->read_payload();
                   });
    }

    void read_payload() {
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(read_payload_),
                   [self](const boost::system::error_code &error) {
                       if (error) {
                           self->finish_read(error, 0);
                           return;
                       }
                       self->pending_ = std::move(self->read_payload_);
                       self->pending_offset_ = 0;
                       self->copy_pending(self->read_buffer_, self->read_handler_);
                   });
    }

    bool copy_pending(boost::asio::mutable_buffer buffer,
                      const std::shared_ptr<ReadHandler> &handler) {
        if (pending_offset_ >= pending_.size()) {
            return false;
        }
        const auto size = std::min(buffer.size(), pending_.size() - pending_offset_);
        std::memcpy(buffer.data(), pending_.data() + pending_offset_, size);
        pending_offset_ += size;
        if (pending_offset_ == pending_.size()) {
            pending_.clear();
            pending_offset_ = 0;
        }
        read_busy_ = false;
        (*handler)({}, size);
        return true;
    }

    void finish_read(const boost::system::error_code &error, std::size_t size) {
        read_busy_ = false;
        auto handler = std::move(read_handler_);
        if (handler && *handler) {
            (*handler)(error, size);
        }
    }

    std::vector<std::uint8_t> hash_;
    bool hash_sent_ = false;
    bool read_busy_ = false;
    bool write_busy_ = false;
    std::array<std::uint8_t, kTlsHeaderSize> read_header_{};
    std::vector<std::uint8_t> read_payload_;
    std::vector<std::uint8_t> pending_;
    std::size_t pending_offset_ = 0;
    boost::asio::mutable_buffer read_buffer_;
    std::shared_ptr<ReadHandler> read_handler_;
    std::vector<std::uint8_t> write_wire_;
    std::size_t write_size_ = 0;
    WriteHandler write_handler_;
};

template <typename T> class SharedStreamAdapter final : public io::StreamHandle {
  public:
    using ReadSignatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;
    using WriteSignatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                           stdexec::set_error_t(std::exception_ptr),
                                                           stdexec::set_stopped_t()>;

    explicit SharedStreamAdapter(std::shared_ptr<T> stream) : stream_(std::move(stream)) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        auto stream = stream_;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<ReadSignatures>(
            [stream, buffer](auto terminal) mutable {
                stream->read_impl(
                    buffer, [terminal = std::move(terminal)](const boost::system::error_code &error,
                                                             std::size_t count) mutable {
                        terminal(error, count);
                    });
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
                net::translate_read(std::move(receiver), error, count, "shadow-tls read");
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        auto stream = stream_;
        return io::AnySender<std::size_t>{async::callback_sender<WriteSignatures>(
            [stream, buffer](auto terminal) mutable {
                stream->write_impl(
                    buffer, [terminal = std::move(terminal)](const boost::system::error_code &error,
                                                             std::size_t count) mutable {
                        terminal(error, count);
                    });
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
                net::translate_write(std::move(receiver), error, count, "shadow-tls write");
            })};
    }

    boost::asio::any_io_executor executor() noexcept override { return stream_->executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        return stream_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        stream_->shutdown_send(error);
    }

    void close() noexcept override { stream_->close(); }

  private:
    std::shared_ptr<T> stream_;
};

class ShadowTlsOpenOperation final : public std::enable_shared_from_this<ShadowTlsOpenOperation> {
  public:
    ShadowTlsOpenOperation(std::unique_ptr<io::StreamHandle> stream, ShadowTlsClientOptions options,
                           ShadowTlsOpenHandler handler)
        : stream_(std::move(stream)), options_(std::move(options)), handler_(std::move(handler)),
          delay_timer_(stream_->executor()) {}

    void start() { scope_.spawn(run_open(shared_from_this())); }

    static exec::task<void> run_open(std::shared_ptr<ShadowTlsOpenOperation> self) {
        if (self->options_.version < 1 || self->options_.version > 3) {
            self->finish(core::fail(configuration_error("Shadow-TLS version must be 1, 2, or 3")));
            co_return;
        }
        if (self->options_.host.empty()) {
            self->finish(core::fail(configuration_error("Shadow-TLS host is required")));
            co_return;
        }
        if (self->options_.version == 2) {
            self->stream_ = std::make_unique<HashingReadStream>(std::move(self->stream_),
                                                                self->options_.password);
        }
        transport::TlsClientOptions tls_options;
        tls_options.server_name = self->options_.host;
        tls_options.verify_peer = !self->options_.skip_cert_verify;
        tls_options.alpn_protocols = self->options_.alpn_protocols;
        tls_options.handoff_raw_transport = true;
        if (self->options_.version == 1 || self->options_.version == 2) {
            tls_options.maximum_tls_version = TLS1_2_VERSION;
        }
        transport::TlsClientConnection established;
        try {
            // No explicit cancel: completion guards drop late terminals.
            established = co_await transport::async_tls_client_handshake(std::move(self->stream_),
                                                                         std::move(tls_options));
        } catch (const core::Error &failure) {
            self->finish(core::fail(failure));
            co_return;
        } catch (...) {
            self->finish(core::fail(protocol_error("Shadow-TLS handshake failed")));
            co_return;
        }
        if (self->completed_) {
            co_return;
        }
        if (self->options_.version == 1) {
            self->finish(std::move(established.stream));
            co_return;
        }
        auto *hashing = dynamic_cast<HashingReadStream *>(established.stream.get());
        if (!hashing) {
            self->finish(
                core::fail(protocol_error("Shadow-TLS v2 handshake lost its hash stream")));
            co_return;
        }
        auto hash = hashing->digest8();
        if (hash.size() != 8) {
            self->finish(core::fail(
                protocol_error("Shadow-TLS v2 handshake did not produce a server hash")));
            co_return;
        }
        auto framed =
            std::make_shared<ShadowTlsV2Stream>(std::move(established.stream), std::move(hash));
        self->delayed_stream_ =
            std::make_unique<SharedStreamAdapter<ShadowTlsV2Stream>>(std::move(framed));
        using DelaySigs = stdexec::completion_signatures<stdexec::set_value_t(bool),
                                                         stdexec::set_error_t(std::exception_ptr),
                                                         stdexec::set_stopped_t()>;
        try {
            co_await async::callback_sender<DelaySigs>(
                [self](auto terminal) mutable {
                    self->delay_timer_.expires_after(std::chrono::milliseconds(20));
                    self->delay_timer_.async_wait(std::move(terminal));
                },
                [](auto receiver, const boost::system::error_code &error) {
                    if (error) {
                        stdexec::set_error(
                            std::move(receiver),
                            std::make_exception_ptr(
                                io_error("Shadow-TLS v2 post-handshake delay failed", error)));
                        return;
                    }
                    stdexec::set_value(std::move(receiver), true);
                });
        } catch (const core::Error &failure) {
            self->finish(core::fail(failure));
            co_return;
        } catch (...) {
            self->finish(core::fail(protocol_error("Shadow-TLS v2 post-handshake delay failed")));
            co_return;
        }
        if (self->completed_) {
            co_return;
        }
        self->finish(std::move(self->delayed_stream_));
    }

    void finish(core::Result<std::unique_ptr<io::StreamHandle>> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        (void)delay_timer_.cancel();
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    void finish(std::unique_ptr<io::StreamHandle> stream) {
        finish(core::Result<std::unique_ptr<io::StreamHandle>>(std::move(stream)));
    }

    std::unique_ptr<io::StreamHandle> stream_;
    ShadowTlsClientOptions options_;
    ShadowTlsOpenHandler handler_;
    boost::asio::steady_timer delay_timer_;
    std::unique_ptr<io::StreamHandle> delayed_stream_;
    bool completed_ = false;
    exec::async_scope scope_;
};

} // namespace

void async_open_shadow_tls(std::unique_ptr<io::StreamHandle> stream, ShadowTlsClientOptions options,
                           ShadowTlsOpenHandler handler) {
    if (!stream || !handler) {
        if (stream) {
            stream->close();
        }
        if (handler) {
            handler(core::fail(
                configuration_error("Shadow-TLS requires a stream and completion handler")));
        }
        return;
    }
    if (options.version == 3) {
        async_open_shadow_tls_v3(std::move(stream), std::move(options), std::move(handler));
        return;
    }
    std::make_shared<ShadowTlsOpenOperation>(std::move(stream), std::move(options),
                                             std::move(handler))
        ->start();
}

} // namespace clash_native::transport::shadowsocks
