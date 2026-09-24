#include <clash_native/transport/trojan/ss_stream.hpp>

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/transport/proxy/crypto.hpp>

#include <stdexec/execution.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/errc.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace clash_native::transport::trojan {

namespace {

// Bridges one stream push/pull back into a legacy (error, size) handler.
struct StreamWriteBridge {
    using receiver_concept = stdexec::receiver_tag;
    std::function<void(const boost::system::error_code &, std::size_t)> handler;
    void set_value(std::size_t size) && noexcept {
        auto callback = std::move(handler);
        callback({}, size);
    }
    void set_error(std::exception_ptr error) && noexcept {
        auto callback = std::move(handler);
        callback(net::unpack_error(std::move(error)), 0);
    }
    void set_stopped() && noexcept {
        auto callback = std::move(handler);
        callback(boost::asio::error::operation_aborted, 0);
    }
};

struct StreamReadBridge {
    using receiver_concept = stdexec::receiver_tag;
    std::function<void(const boost::system::error_code &, std::size_t)> handler;
    void set_value(std::optional<std::size_t> size) && noexcept {
        auto callback = std::move(handler);
        if (size) {
            callback({}, *size);
        } else {
            callback(boost::asio::error::eof, 0);
        }
    }
    void set_error(std::exception_ptr error) && noexcept {
        auto callback = std::move(handler);
        callback(net::unpack_error(std::move(error)), 0);
    }
    void set_stopped() && noexcept {
        auto callback = std::move(handler);
        callback(boost::asio::error::operation_aborted, 0);
    }
};

constexpr std::size_t kMaxChunkPayload = 0x3fff;

boost::system::error_code protocol_error() {
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

core::Error transport_error(std::string context) {
    return {core::ErrorCode::transport_io, std::move(context)};
}

class TrojanSsStreamState final : public std::enable_shared_from_this<TrojanSsStreamState> {
  public:
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
    using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    TrojanSsStreamState(std::unique_ptr<io::StreamHandle> stream, proxy::CipherMethod method,
                        std::vector<std::uint8_t> key, std::vector<std::uint8_t> salt,
                        std::string password)
        : stream_(std::move(stream)), method_(std::move(method)), key_(std::move(key)),
          salt_(std::move(salt)), password_(std::move(password)) {
        read_nonce_.assign(method_.nonce_size, 0);
        write_nonce_.assign(method_.nonce_size, 0);
    }

    boost::asio::any_io_executor executor() noexcept { return stream_->executor(); }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        return stream_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept { stream_->shutdown_send(error); }

    void send(boost::asio::const_buffer buffer, WriteHandler handler) {
        if (closed_) {
            post_write_result(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        // Seal synchronously so nonce order follows call order. Peers
        // reject zero-length chunks, so an empty payload only carries the
        // not-yet-written salt; otherwise it completes without a write.
        auto wire = std::make_shared<std::vector<std::uint8_t>>();
        try {
            if (!salt_written_) {
                salt_written_ = true;
                wire->insert(wire->end(), salt_.begin(), salt_.end());
            }
            const auto *data = static_cast<const std::uint8_t *>(buffer.data());
            std::size_t offset = 0;
            while (offset < buffer.size()) {
                const auto chunk_size = std::min(kMaxChunkPayload, buffer.size() - offset);
                append_record(std::span<const std::uint8_t>(data + offset, chunk_size), *wire);
                offset += chunk_size;
            }
            if (wire->empty()) {
                post_write_result(std::move(handler), {}, 0);
                return;
            }
        } catch (...) {
            post_write_result(std::move(handler), protocol_error(), 0);
            return;
        }
        const auto size = buffer.size();
        // Single full-transfer write driven straight into the handler.
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = stream_->async_write(boost::asio::buffer(*wire));
        async::start_with_receiver(
            std::move(sender),
            StreamWriteBridge{[wire, handler = std::move(handler),
                               size](const boost::system::error_code &error, std::size_t) mutable {
                if (error) {
                    handler(error, 0);
                } else {
                    handler({}, size);
                }
            }});
    }

    void receive(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        if (closed_) {
            post_read_result(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (read_in_progress_) {
            post_read_result(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (!pending_plaintext_.empty()) {
            const auto size = std::min(buffer.size(), pending_plaintext_.size() - pending_offset_);
            if (size > 0) {
                std::memcpy(buffer.data(), pending_plaintext_.data() + pending_offset_, size);
            }
            pending_offset_ += size;
            if (pending_offset_ == pending_plaintext_.size()) {
                pending_plaintext_.clear();
                pending_offset_ = 0;
            }
            post_read_result(std::move(handler), {}, size);
            return;
        }
        read_in_progress_ = true;
        output_buffer_ = buffer;
        receive_handler_ = std::move(handler);
        if (buffer.size() == 0) {
            finish_receive({}, 0);
            return;
        }
        // Each direction carries its own salt: derive the read key from
        // the peer's salt before the first chunk.
        if (!read_key_ready_) {
            read_peer_salt();
            return;
        }
        read_chunk_length();
    }

    void close() {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (stream_) {
            stream_->close();
            auto executor = stream_->executor();
            if (read_in_progress_) {
                read_in_progress_ = false;
                auto handler = std::move(receive_handler_);
                boost::asio::post(executor, [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::operation_aborted, 0);
                });
            }
        }
    }

  private:
    using Completion = std::function<void(const boost::system::error_code &)>;

    void read_exact(std::shared_ptr<std::vector<std::uint8_t>> buffer, std::size_t offset,
                    Completion completion) {
        auto self = shared_from_this();
        auto read_buffer =
            boost::asio::mutable_buffer(buffer->data() + offset, buffer->size() - offset);
        std::function<void(const boost::system::error_code &, std::size_t)> pull =
            [self, buffer = std::move(buffer), offset, completion = std::move(completion)](
                const boost::system::error_code &error, std::size_t size) mutable {
                if (error) {
                    completion(error);
                    return;
                }
                if (size == 0) {
                    completion(boost::asio::error::eof);
                    return;
                }
                const auto next = offset + size;
                if (next == buffer->size()) {
                    completion({});
                    return;
                }
                self->read_exact(std::move(buffer), next, std::move(completion));
            };
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = stream_->async_read_some(read_buffer);
        async::start_with_receiver(std::move(sender), StreamReadBridge{std::move(pull)});
    }

    void read_peer_salt() {
        auto salt = std::make_shared<std::vector<std::uint8_t>>(method_.key_size);
        auto self = shared_from_this();
        read_exact(salt, 0, [self, salt](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0);
                return;
            }
            auto key = proxy::derive_aead_subkey(self->method_.name, self->password_, *salt);
            if (!key) {
                self->finish_receive(protocol_error(), 0);
                return;
            }
            self->read_key_ = std::move(key.value());
            self->read_key_ready_ = true;
            self->read_chunk_length();
        });
    }

    void read_chunk_length() {
        auto encrypted = std::make_shared<std::vector<std::uint8_t>>(2 + method_.overhead);
        auto self = shared_from_this();
        read_exact(encrypted, 0, [self, encrypted](const boost::system::error_code &error) {
            if (error == boost::asio::error::eof) {
                // Clean EOF at a chunk boundary ends the stream.
                self->finish_receive(boost::asio::error::eof, 0);
                return;
            }
            if (error) {
                self->finish_receive(error, 0);
                return;
            }
            auto length = proxy::aead_decrypt(self->method_.name, self->read_key_,
                                              self->read_nonce_, *encrypted);
            if (!length || length.value().size() != 2) {
                self->finish_receive(protocol_error(), 0);
                return;
            }
            proxy::increment_nonce(self->read_nonce_);
            const auto payload_size =
                (static_cast<std::size_t>(length.value()[0]) << 8) | length.value()[1];
            if (payload_size == 0 || payload_size > kMaxChunkPayload) {
                self->finish_receive(protocol_error(), 0);
                return;
            }
            self->read_chunk_payload(payload_size);
        });
    }

    void read_chunk_payload(std::size_t payload_size) {
        auto encrypted =
            std::make_shared<std::vector<std::uint8_t>>(payload_size + method_.overhead);
        auto self = shared_from_this();
        read_exact(encrypted, 0, [self, encrypted](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(protocol_error(), 0);
                return;
            }
            auto plaintext = proxy::aead_decrypt(self->method_.name, self->read_key_,
                                                 self->read_nonce_, *encrypted);
            if (!plaintext || plaintext.value().empty()) {
                self->finish_receive(protocol_error(), 0);
                return;
            }
            proxy::increment_nonce(self->read_nonce_);
            self->pending_plaintext_ = std::move(plaintext.value());
            self->pending_offset_ = 0;
            const auto size =
                std::min(self->output_buffer_.size(), self->pending_plaintext_.size());
            std::memcpy(self->output_buffer_.data(), self->pending_plaintext_.data(), size);
            self->pending_offset_ = size;
            if (self->pending_offset_ == self->pending_plaintext_.size()) {
                self->pending_plaintext_.clear();
                self->pending_offset_ = 0;
            }
            self->finish_receive({}, size);
        });
    }

    void append_record(std::span<const std::uint8_t> payload, std::vector<std::uint8_t> &wire) {
        const auto payload_size = static_cast<std::uint16_t>(payload.size());
        const std::array<std::uint8_t, 2> length{static_cast<std::uint8_t>(payload_size >> 8),
                                                 static_cast<std::uint8_t>(payload_size & 0xff)};
        auto encrypted_length = proxy::aead_encrypt(method_.name, key_, write_nonce_, length);
        proxy::increment_nonce(write_nonce_);
        auto encrypted_payload = proxy::aead_encrypt(method_.name, key_, write_nonce_, payload);
        proxy::increment_nonce(write_nonce_);
        if (!encrypted_length || !encrypted_payload) {
            throw transport_error("Trojan ss stream failed to seal chunk");
        }
        wire.insert(wire.end(), encrypted_length.value().begin(), encrypted_length.value().end());
        wire.insert(wire.end(), encrypted_payload.value().begin(), encrypted_payload.value().end());
    }

    void post_write_result(WriteHandler handler, const boost::system::error_code &error,
                           std::size_t size) {
        auto executor = stream_->executor();
        boost::asio::post(executor, [handler = std::move(handler), error, size]() mutable {
            handler(error, size);
        });
    }

    void post_read_result(ReadHandler handler, const boost::system::error_code &error,
                          std::size_t size) {
        boost::asio::post(stream_->executor(), [handler = std::move(handler), error,
                                                size]() mutable { handler(error, size); });
    }

    void finish_receive(const boost::system::error_code &error, std::size_t size) {
        read_in_progress_ = false;
        auto handler = std::move(receive_handler_);
        if (handler) {
            handler(error, size);
        }
    }

    std::shared_ptr<io::StreamHandle> stream_;
    proxy::CipherMethod method_;
    std::vector<std::uint8_t> key_;
    std::vector<std::uint8_t> salt_;
    std::string password_;
    std::vector<std::uint8_t> read_key_;
    bool read_key_ready_ = false;
    std::vector<std::uint8_t> read_nonce_;
    std::vector<std::uint8_t> write_nonce_;
    std::vector<std::uint8_t> pending_plaintext_;
    std::size_t pending_offset_ = 0;
    boost::asio::mutable_buffer output_buffer_;
    ReadHandler receive_handler_;
    bool salt_written_ = false;
    bool read_in_progress_ = false;
    bool closed_ = false;
};

class TrojanSsStreamHandle final : public io::StreamHandle {
  public:
    explicit TrojanSsStreamHandle(std::shared_ptr<TrojanSsStreamState> state)
        : state_(std::move(state)) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
            [state = state_, buffer](auto terminal) mutable {
                state->receive(buffer, [terminal = std::move(terminal)](
                                           const boost::system::error_code &error,
                                           std::size_t size) mutable { terminal(error, size); });
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{size});
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                if (error == boost::asio::error::eof) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{});
                    return;
                }
                stdexec::set_error(
                    std::move(receiver),
                    std::make_exception_ptr(core::Error{core::ErrorCode::transport_io,
                                                        "Trojan ss stream read failed", error}));
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        return io::AnySender<std::size_t>{async::callback_sender<Signatures>(
            [state = state_, buffer](auto terminal) mutable {
                state->send(buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), size);
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(
                    std::move(receiver),
                    std::make_exception_ptr(core::Error{core::ErrorCode::transport_io,
                                                        "Trojan ss stream write failed", error}));
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
    std::shared_ptr<TrojanSsStreamState> state_;
};

} // namespace

core::Result<std::unique_ptr<io::StreamHandle>>
make_trojan_ss_stream_handle(std::unique_ptr<io::StreamHandle> stream, std::string_view method,
                             std::string_view password) {
    if (!stream) {
        return core::fail(
            {core::ErrorCode::configuration, "Trojan ss stream requires a transport stream"});
    }
    auto spec = proxy::cipher_method(method);
    if (!spec) {
        return core::fail(spec.error());
    }
    if (spec.value().kind != proxy::CipherKind::aead || spec.value().shadowsocks_2022) {
        return core::fail(
            {core::ErrorCode::configuration, "Trojan ss-opts supports classic AEAD methods only"});
    }
    if (password.empty()) {
        return core::fail(
            {core::ErrorCode::configuration, "Trojan ss-opts password must not be empty"});
    }
    std::vector<std::uint8_t> salt(spec.value().key_size);
    if (!proxy::random_bytes(salt)) {
        return core::fail({core::ErrorCode::authentication, "failed to generate Trojan ss salt"});
    }
    auto key = proxy::derive_aead_subkey(method, password, salt);
    if (!key) {
        return core::fail(key.error());
    }
    auto state = std::make_shared<TrojanSsStreamState>(std::move(stream), std::move(spec.value()),
                                                       std::move(key.value()), std::move(salt),
                                                       std::string(password));
    return std::unique_ptr<io::StreamHandle>(
        std::make_unique<TrojanSsStreamHandle>(std::move(state)));
}

} // namespace clash_native::transport::trojan
