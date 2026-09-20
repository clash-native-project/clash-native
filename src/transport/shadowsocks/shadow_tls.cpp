#include <clash_native/transport/shadowsocks/shadow_tls.hpp>

#include <clash_native/net/tls_stream.hpp>
#include <clash_native/transport/shadowsocks/crypto.hpp>
#include <clash_native/transport/shadowsocks/simple_obfs.hpp>
#include <clash_native/transport/tls_client.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <openssl/digest.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kTlsHeaderSize = 5;
constexpr std::size_t kTlsHmacSize = 4;
constexpr std::size_t kTlsSessionIdSize = 32;
constexpr std::size_t kMaxTlsPlaintext = 16384;
constexpr std::uint8_t kHandshakeRecord = 22;
constexpr std::uint8_t kChangeCipherSpecRecord = 20;
constexpr std::uint8_t kApplicationRecord = 23;

core::Error configuration_error(std::string context) {
    return {core::ErrorCode::configuration, std::move(context), {}};
}

core::Error protocol_error(std::string context) {
    return {core::ErrorCode::carrier_handshake, std::move(context), {}};
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

std::array<std::uint8_t, 32> sha256(std::span<const std::uint8_t> data) {
    std::array<std::uint8_t, 32> output{};
    SHA256(data.data(), data.size(), output.data());
    return output;
}

void xor_with_key(std::span<std::uint8_t> data, std::span<const std::uint8_t> key) {
    for (std::size_t index = 0; index < data.size(); ++index) {
        data[index] ^= key[index % key.size()];
    }
}

class HashingReadStream final : public core::StreamHandle {
  public:
    HashingReadStream(std::unique_ptr<core::StreamHandle> stream, std::string password)
        : stream_(std::move(stream)), password_(std::move(password)) {}

    std::vector<std::uint8_t> digest8() const {
        const auto digest = hmac_sha1(password_, received_);
        if (digest.size() < 8) {
            return {};
        }
        return {digest.begin(), digest.begin() + 8};
    }

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        stream_->async_read_some(
            buffer, [this, buffer, handler = std::move(handler)](
                        const boost::system::error_code &error, std::size_t size) mutable {
                if (!error && size != 0) {
                    const auto *bytes = static_cast<const std::uint8_t *>(buffer.data());
                    received_.insert(received_.end(), bytes, bytes + size);
                }
                handler(error, size);
            });
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        stream_->async_write(buffer, std::move(handler));
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
    std::unique_ptr<core::StreamHandle> stream_;
    std::string password_;
    std::vector<std::uint8_t> received_;
};

class FramedStreamBase {
  protected:
    explicit FramedStreamBase(std::unique_ptr<core::StreamHandle> stream)
        : stream_(std::move(stream)) {}

    using ExactHandler = std::function<void(const boost::system::error_code &)>;

    void read_exact(boost::asio::mutable_buffer buffer, ExactHandler handler) {
        read_exact_impl(buffer, 0, std::move(handler));
    }

    void read_exact_impl(boost::asio::mutable_buffer buffer, std::size_t offset,
                         ExactHandler handler) {
        if (offset == buffer.size()) {
            boost::asio::post(stream_->executor(), [handler = std::move(handler)]() mutable {
                handler({});
            });
            return;
        }
        auto self = shared_from_this_base();
        stream_->async_read_some(
            boost::asio::mutable_buffer(static_cast<std::uint8_t *>(buffer.data()) + offset,
                                        buffer.size() - offset),
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

    std::unique_ptr<core::StreamHandle> stream_;
};

class ShadowTlsV2Stream final : public core::StreamHandle,
                                public FramedStreamBase,
                                public std::enable_shared_from_this<ShadowTlsV2Stream> {
  public:
    ShadowTlsV2Stream(std::unique_ptr<core::StreamHandle> stream, std::vector<std::uint8_t> hash)
        : FramedStreamBase(std::move(stream)), hash_(std::move(hash)) {}

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
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
            boost::asio::post(executor(), [handler = std::move(handler)]() mutable {
                handler({}, 0);
            });
            return;
        }
        read_busy_ = true;
        read_buffer_ = buffer;
        read_handler_ = std::make_shared<ReadHandler>(std::move(handler));
        read_header();
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        if (write_busy_) {
            boost::asio::post(executor(), [handler = std::move(handler)]() mutable {
                handler(boost::asio::error::already_started, 0);
            });
            return;
        }
        if (buffer.size() == 0) {
            boost::asio::post(executor(), [handler = std::move(handler)]() mutable {
                handler({}, 0);
            });
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
            framed.insert(framed.end(), {kApplicationRecord, 0x03, 0x03,
                                         static_cast<std::uint8_t>(size >> 8),
                                         static_cast<std::uint8_t>(size)});
            framed.insert(framed.end(), payload.begin() + static_cast<std::ptrdiff_t>(offset),
                          payload.begin() + static_cast<std::ptrdiff_t>(offset + size));
            offset += size;
        }
        write_wire_ = std::move(framed);
    }

    void write_frame() {
        auto self = shared_from_this();
        stream_->async_write(
            boost::asio::buffer(write_wire_),
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
        read_exact(boost::asio::buffer(read_header_), [self](const boost::system::error_code &error) {
            if (error) {
                self->finish_read(error, 0);
                return;
            }
            if (self->read_header_[0] != kApplicationRecord || self->read_header_[1] != 0x03 ||
                self->read_header_[2] != 0x03) {
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
        read_exact(boost::asio::buffer(read_payload_), [self](const boost::system::error_code &error) {
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

class ShadowTlsV3Stream final : public core::StreamHandle,
                                public FramedStreamBase,
                                public std::enable_shared_from_this<ShadowTlsV3Stream> {
  public:
    ShadowTlsV3Stream(std::unique_ptr<core::StreamHandle> stream, std::string password,
                      std::span<const std::uint8_t> server_random)
        : FramedStreamBase(std::move(stream)), password_(std::move(password)),
          server_random_(server_random.begin(), server_random.end()),
          xor_key_(sha256(concat(password_, server_random_))) {
        write_chain_ = server_random_;
        write_chain_.push_back('C');
        read_chain_ = server_random_;
        read_chain_.push_back('S');
    }

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        if (read_busy_) {
            boost::asio::post(executor(), [handler = std::move(handler)]() mutable {
                handler(boost::asio::error::already_started, 0);
            });
            return;
        }
        if (copy_pending(buffer, std::move(handler))) {
            return;
        }
        if (buffer.size() == 0) {
            boost::asio::post(executor(), [handler = std::move(handler)]() mutable {
                handler({}, 0);
            });
            return;
        }
        read_busy_ = true;
        read_buffer_ = buffer;
        read_handler_ = std::move(handler);
        read_frame_header();
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        if (write_busy_) {
            boost::asio::post(executor(), [handler = std::move(handler)]() mutable {
                handler(boost::asio::error::already_started, 0);
            });
            return;
        }
        if (buffer.size() == 0) {
            boost::asio::post(executor(), [handler = std::move(handler)]() mutable {
                handler({}, 0);
            });
            return;
        }
        write_busy_ = true;
        write_size_ = buffer.size();
        write_handler_ = std::move(handler);
        const auto *bytes = static_cast<const std::uint8_t *>(buffer.data());
        write_wire_.clear();
        for (std::size_t offset = 0; offset < buffer.size();) {
            const auto size = std::min(kMaxTlsPlaintext, buffer.size() - offset);
            const auto *payload = bytes + offset;
            write_chain_.insert(write_chain_.end(), payload, payload + size);
            const auto digest = hmac_sha1(password_, write_chain_);
            if (digest.size() < kTlsHmacSize) {
                finish_write(boost::asio::error::fault);
                return;
            }
            write_chain_.insert(write_chain_.end(), digest.begin(), digest.begin() + kTlsHmacSize);
            write_wire_.insert(write_wire_.end(), {kApplicationRecord, 0x03, 0x03,
                                                   static_cast<std::uint8_t>((size + kTlsHmacSize) >> 8),
                                                   static_cast<std::uint8_t>(size + kTlsHmacSize)});
            write_wire_.insert(write_wire_.end(), digest.begin(), digest.begin() + kTlsHmacSize);
            write_wire_.insert(write_wire_.end(), payload, payload + size);
            offset += size;
        }
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
    static std::vector<std::uint8_t> concat(std::string_view password,
                                            std::span<const std::uint8_t> random) {
        std::vector<std::uint8_t> result;
        result.reserve(password.size() + random.size());
        result.insert(result.end(), password.begin(), password.end());
        result.insert(result.end(), random.begin(), random.end());
        return result;
    }

    std::shared_ptr<FramedStreamBase> shared_from_this_base() override {
        return shared_from_this();
    }

    bool copy_pending(boost::asio::mutable_buffer buffer, ReadHandler handler) {
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
        handler({}, size);
        return true;
    }

    void write_frame() {
        auto self = shared_from_this();
        stream_->async_write(
            boost::asio::buffer(write_wire_),
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

    void read_frame_header() {
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(read_header_), [self](const boost::system::error_code &error) {
            if (error) {
                self->finish_read(error, 0);
                return;
            }
            const auto size = (static_cast<std::size_t>(self->read_header_[3]) << 8) |
                              self->read_header_[4];
            if (size == 0 || size > 0xffff) {
                self->finish_read(boost::asio::error::fault, 0);
                return;
            }
            self->read_payload_.resize(size);
            self->read_frame_payload();
        });
    }

    void read_frame_payload() {
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(read_payload_), [self](const boost::system::error_code &error) {
            if (error) {
                self->finish_read(error, 0);
                return;
            }
            if (self->read_header_[0] != kApplicationRecord) {
                self->read_frame_header();
                return;
            }
            if (self->read_payload_.size() < kTlsHmacSize) {
                self->finish_read(boost::asio::error::fault, 0);
                return;
            }
            const auto mac = hmac_sha1(self->password_, self->read_chain_with_payload());
            if (mac.size() < kTlsHmacSize ||
                !std::equal(mac.begin(), mac.begin() + kTlsHmacSize, self->read_payload_.begin())) {
                self->finish_read(boost::asio::error::fault, 0);
                return;
            }
            self->read_chain_.insert(self->read_chain_.end(), self->read_payload_.begin() + kTlsHmacSize,
                                     self->read_payload_.end());
            self->read_chain_.insert(self->read_chain_.end(), self->read_payload_.begin(),
                                     self->read_payload_.begin() + kTlsHmacSize);
            self->pending_.assign(self->read_payload_.begin() + kTlsHmacSize,
                                  self->read_payload_.end());
            self->pending_offset_ = 0;
            self->copy_pending(self->read_buffer_, std::move(self->read_handler_));
        });
    }

    std::vector<std::uint8_t> read_chain_with_payload() const {
        std::vector<std::uint8_t> input = read_chain_;
        input.insert(input.end(), read_payload_.begin() + kTlsHmacSize, read_payload_.end());
        return input;
    }

    void finish_read(const boost::system::error_code &error, std::size_t size) {
        read_busy_ = false;
        auto handler = std::move(read_handler_);
        if (handler) {
            handler(error, size);
        }
    }

    std::string password_;
    std::vector<std::uint8_t> server_random_;
    std::array<std::uint8_t, 32> xor_key_{};
    std::vector<std::uint8_t> write_chain_;
    std::vector<std::uint8_t> read_chain_;
    bool read_busy_ = false;
    bool write_busy_ = false;
    std::array<std::uint8_t, kTlsHeaderSize> read_header_{};
    std::vector<std::uint8_t> read_payload_;
    std::vector<std::uint8_t> pending_;
    std::size_t pending_offset_ = 0;
    boost::asio::mutable_buffer read_buffer_;
    ReadHandler read_handler_;
    std::vector<std::uint8_t> write_wire_;
    std::size_t write_size_ = 0;
    WriteHandler write_handler_;
};

template <typename T>
class SharedStreamAdapter final : public core::StreamHandle {
  public:
    explicit SharedStreamAdapter(std::shared_ptr<T> stream) : stream_(std::move(stream)) {}

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        stream_->async_read_some(buffer, std::move(handler));
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        stream_->async_write(buffer, std::move(handler));
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
    ShadowTlsOpenOperation(std::unique_ptr<core::StreamHandle> stream,
                           ShadowTlsClientOptions options, ShadowTlsOpenHandler handler)
        : stream_(std::move(stream)), options_(std::move(options)), handler_(std::move(handler)),
          delay_timer_(stream_->executor()) {}

    void start() {
        if (options_.version == 3) {
            finish(core::fail(configuration_error(
                "Shadow-TLS v3 is not supported by the current TLS client")));
            return;
        }
        if (options_.version < 1 || options_.version > 3) {
            finish(core::fail(configuration_error("Shadow-TLS version must be 1, 2, or 3")));
            return;
        }
        if (options_.host.empty()) {
            finish(core::fail(configuration_error("Shadow-TLS host is required")));
            return;
        }
        if (options_.version == 2) {
            stream_ = std::make_unique<HashingReadStream>(std::move(stream_), options_.password);
        }
        transport::TlsClientOptions tls_options;
        tls_options.server_name = options_.host;
        tls_options.verify_peer = !options_.skip_cert_verify;
        tls_options.alpn_protocols = options_.alpn_protocols;
        tls_options.handoff_raw_transport = true;
        if (options_.version == 1 || options_.version == 2) {
            tls_options.maximum_tls_version = TLS1_2_VERSION;
        }
        auto self = shared_from_this();
        tls_handshake_ = transport::async_tls_client_handshake(
            std::move(stream_), std::move(tls_options),
            [self](core::Result<transport::TlsClientConnection> result) mutable {
                self->tls_handshake_.reset();
                if (!result) {
                    self->finish(core::fail(result.error()));
                    return;
                }
                if (self->options_.version == 1) {
                    self->finish(std::move(result.value().stream));
                    return;
                }
                auto *hashing = dynamic_cast<HashingReadStream *>(result.value().stream.get());
                if (!hashing) {
                    self->finish(core::fail(protocol_error(
                        "Shadow-TLS v2 handshake lost its hash stream")));
                    return;
                }
                auto hash = hashing->digest8();
                if (hash.size() != 8) {
                    self->finish(core::fail(protocol_error(
                        "Shadow-TLS v2 handshake did not produce a server hash")));
                    return;
                }
                auto raw = std::move(result.value().stream);
                auto framed = std::make_shared<ShadowTlsV2Stream>(std::move(raw), std::move(hash));
                self->delayed_stream_ =
                    std::make_unique<SharedStreamAdapter<ShadowTlsV2Stream>>(std::move(framed));
                self->delay_timer_.expires_after(std::chrono::milliseconds(20));
                self->delay_timer_.async_wait([self](const boost::system::error_code &error) {
                    if (error) {
                        self->finish(core::fail(io_error(
                            "Shadow-TLS v2 post-handshake delay failed", error)));
                        return;
                    }
                    self->finish(std::move(self->delayed_stream_));
                });
            });
    }

  private:
    void start_v3() {
        std::array<std::uint8_t, kTlsSessionIdSize> session_id{};
        if (!random_bytes(session_id)) {
            finish(core::fail({core::ErrorCode::authentication,
                               "failed to generate Shadow-TLS SessionID", {}}));
            return;
        }
        auto hello = make_tls_client_hello({}, options_.host, session_id);
        if (hello.size() < 5 + 1 + 3 + 2 + 32 + 1 + 32) {
            finish(core::fail(protocol_error("failed to build Shadow-TLS ClientHello")));
            return;
        }
        const std::size_t session_id_length_index = 5 + 1 + 3 + 2 + 32;
        const std::size_t hmac_index = session_id_length_index + 1 + 32 - 4;
        std::vector<std::uint8_t> hmac_input;
        hmac_input.reserve(hello.size());
        hmac_input.insert(hmac_input.end(), hello.begin() + 5,
                          hello.begin() + static_cast<std::ptrdiff_t>(hmac_index));
        hmac_input.insert(hmac_input.end(), 4, 0);
        hmac_input.insert(hmac_input.end(), hello.begin() + static_cast<std::ptrdiff_t>(hmac_index + 4),
                          hello.end());
        const auto digest = hmac_sha1(options_.password, hmac_input);
        if (digest.size() < 4) {
            finish(core::fail({core::ErrorCode::authentication,
                               "failed to sign Shadow-TLS ClientHello", {}}));
            return;
        }
        std::copy(digest.begin(), digest.begin() + 4,
                  hello.begin() + static_cast<std::ptrdiff_t>(hmac_index));
        hello_ = std::move(hello);
        auto self = shared_from_this();
        stream_->async_write(
            boost::asio::buffer(hello_),
            [self](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    self->finish(core::fail(io_error("failed to write Shadow-TLS ClientHello", error)));
                    return;
                }
                self->read_server_hello();
            });
    }

    void read_server_hello() {
        read_exact([self = shared_from_this()](core::Result<std::vector<std::uint8_t>> result) {
            if (!result) {
                self->finish(core::fail(result.error()));
                return;
            }
            auto &frame = result.value();
            if (frame.size() >= 5 + 1 + 3 + 2 + 32 && frame[0] == kHandshakeRecord &&
                frame[5] == 2) {
                std::array<std::uint8_t, 32> random{};
                std::copy(frame.begin() + 5 + 1 + 3 + 2,
                          frame.begin() + 5 + 1 + 3 + 2 + 32, random.begin());
                auto raw = std::move(self->stream_);
                auto framed = std::make_shared<ShadowTlsV3Stream>(
                    std::move(raw), self->options_.password, random);
                std::unique_ptr<core::StreamHandle> opened =
                    std::make_unique<SharedStreamAdapter<ShadowTlsV3Stream>>(std::move(framed));
                self->finish(std::move(opened));
                return;
            }
            self->read_server_hello();
        });
    }

    using FrameResult = core::Result<std::vector<std::uint8_t>>;

    void read_exact(std::function<void(FrameResult)> handler) {
        auto header = std::make_shared<std::array<std::uint8_t, kTlsHeaderSize>>();
        read_exact_bytes(boost::asio::buffer(*header),
                         [self = shared_from_this(), header, handler = std::move(handler)](
                             const boost::system::error_code &error) mutable {
                             if (error) {
                                 handler(core::fail(io_error(
                                     "failed to read Shadow-TLS server handshake", error)));
                                 return;
                             }
                             const auto size = (static_cast<std::size_t>((*header)[3]) << 8) |
                                               (*header)[4];
                             if (size > 0xffff) {
                                 handler(core::fail(protocol_error(
                                     "invalid Shadow-TLS server record length")));
                                 return;
                             }
                             auto frame = std::make_shared<std::vector<std::uint8_t>>(kTlsHeaderSize + size);
                             std::copy(header->begin(), header->end(), frame->begin());
                             self->read_exact_bytes(
                                 boost::asio::buffer(frame->data() + kTlsHeaderSize, size),
                                 [frame, handler = std::move(handler)](
                                     const boost::system::error_code &payload_error) mutable {
                                     if (payload_error) {
                                         handler(core::fail(io_error(
                                             "failed to read Shadow-TLS server record", payload_error)));
                                         return;
                                     }
                                     handler(std::move(*frame));
                                 });
                         });
    }

    void read_exact_bytes(boost::asio::mutable_buffer buffer,
                          std::function<void(const boost::system::error_code &)> handler) {
        read_exact_bytes_impl(buffer, 0, std::move(handler));
    }

    void read_exact_bytes_impl(boost::asio::mutable_buffer buffer, std::size_t offset,
                               std::function<void(const boost::system::error_code &)> handler) {
        if (offset == buffer.size()) {
            boost::asio::post(stream_->executor(), [handler = std::move(handler)]() mutable {
                handler({});
            });
            return;
        }
        auto self = shared_from_this();
        stream_->async_read_some(
            boost::asio::mutable_buffer(static_cast<std::uint8_t *>(buffer.data()) + offset,
                                        buffer.size() - offset),
            [self, buffer, offset, handler = std::move(handler)](
                const boost::system::error_code &error, std::size_t size) mutable {
                if (error) {
                    handler(error);
                } else if (size == 0) {
                    handler(boost::asio::error::eof);
                } else {
                    self->read_exact_bytes_impl(buffer, offset + size, std::move(handler));
                }
            });
    }

    void finish(core::Result<std::unique_ptr<core::StreamHandle>> result) {
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

    void finish(std::unique_ptr<core::StreamHandle> stream) {
        finish(core::Result<std::unique_ptr<core::StreamHandle>>(std::move(stream)));
    }

    std::unique_ptr<core::StreamHandle> stream_;
    ShadowTlsClientOptions options_;
    ShadowTlsOpenHandler handler_;
    std::shared_ptr<transport::TlsClientHandshake> tls_handshake_;
    boost::asio::steady_timer delay_timer_;
    std::unique_ptr<core::StreamHandle> delayed_stream_;
    std::vector<std::uint8_t> hello_;
    bool completed_ = false;
};

} // namespace

void async_open_shadow_tls(std::unique_ptr<core::StreamHandle> stream,
                           ShadowTlsClientOptions options, ShadowTlsOpenHandler handler) {
    if (!stream || !handler) {
        if (stream) {
            stream->close();
        }
        if (handler) {
            handler(core::fail(configuration_error(
                "Shadow-TLS requires a stream and completion handler")));
        }
        return;
    }
    std::make_shared<ShadowTlsOpenOperation>(std::move(stream), std::move(options),
                                             std::move(handler))
        ->start();
}

} // namespace clash_native::transport::shadowsocks
