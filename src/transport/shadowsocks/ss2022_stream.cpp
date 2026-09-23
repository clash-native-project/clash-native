#include <clash_native/transport/shadowsocks/ss2022_stream.hpp>

#include <clash_native/async/bridge.hpp>
#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/transport/shadowsocks/crypto.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <exec/asio/use_sender.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

using StreamReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
using StreamWriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

// Bridges one carrier pull/push back into a legacy (error, size) handler.
struct CarrierReadBridge {
    using receiver_concept = stdexec::receiver_tag;
    StreamReadHandler handler;
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

struct CarrierWriteBridge {
    using receiver_concept = stdexec::receiver_tag;
    StreamWriteHandler handler;
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

constexpr std::size_t kMaxChunkPayload = 0x3fff;
constexpr std::size_t kFixedHeaderSize = 1 + sizeof(std::uint64_t) + sizeof(std::uint16_t);
constexpr std::uint8_t kClientHeader = 0;
constexpr std::uint8_t kServerHeader = 1;

boost::system::error_code protocol_error() {
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

boost::system::error_code authentication_error() {
    return boost::system::errc::make_error_code(boost::system::errc::permission_denied);
}

void append_u16(std::vector<std::uint8_t> &output, std::size_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::uint16_t read_u16(std::span<const std::uint8_t> bytes) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8) | bytes[1]);
}

std::uint64_t unix_seconds() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
}

core::Result<std::vector<std::uint8_t>> encrypt_record(std::string_view method,
                                                       std::span<const std::uint8_t> key,
                                                       std::vector<std::uint8_t> &nonce,
                                                       std::span<const std::uint8_t> payload) {
    if (payload.empty() || payload.size() > kMaxChunkPayload) {
        return core::fail(
            {core::ErrorCode::protocol_framing, "invalid Shadowsocks 2022 record payload size"});
    }
    std::array<std::uint8_t, 2> length{static_cast<std::uint8_t>(payload.size() >> 8),
                                       static_cast<std::uint8_t>(payload.size())};
    auto encrypted_length = aead_encrypt(method, key, nonce, length);
    increment_nonce(nonce);
    auto encrypted_payload = aead_encrypt(method, key, nonce, payload);
    increment_nonce(nonce);
    if (!encrypted_length || !encrypted_payload) {
        return core::fail(
            {core::ErrorCode::authentication, "failed to encrypt Shadowsocks 2022 record"});
    }
    std::vector<std::uint8_t> result;
    result.reserve(encrypted_length.value().size() + encrypted_payload.value().size());
    result.insert(result.end(), encrypted_length.value().begin(), encrypted_length.value().end());
    result.insert(result.end(), encrypted_payload.value().begin(), encrypted_payload.value().end());
    return result;
}

core::Result<std::vector<std::uint8_t>> encrypt_chunk(std::string_view method,
                                                      std::span<const std::uint8_t> key,
                                                      std::vector<std::uint8_t> &nonce,
                                                      std::span<const std::uint8_t> payload) {
    auto result = aead_encrypt(method, key, nonce, payload);
    increment_nonce(nonce);
    return result;
}

class Shadowsocks2022StreamState;

class Shadowsocks2022StreamHandle final : public io::StreamHandle {
  public:
    using ReadSignatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;
    using WriteSignatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                           stdexec::set_error_t(std::exception_ptr),
                                                           stdexec::set_stopped_t()>;

    explicit Shadowsocks2022StreamHandle(std::shared_ptr<Shadowsocks2022StreamState> state)
        : state_(std::move(state)) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override;
    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override;
    boost::asio::any_io_executor executor() noexcept override;
    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override;
    void shutdown_send(boost::system::error_code &error) noexcept override;
    void close() noexcept override;

  private:
    std::shared_ptr<Shadowsocks2022StreamState> state_;
};

class Shadowsocks2022StreamState final
    : public std::enable_shared_from_this<Shadowsocks2022StreamState> {
  public:
    Shadowsocks2022StreamState(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                               std::string method, std::string password,
                               std::vector<std::uint8_t> write_key,
                               std::vector<std::uint8_t> write_nonce,
                               std::vector<std::uint8_t> request_salt,
                               std::vector<std::uint8_t> initial_wire, ObfsMode obfs_mode)
        : socket_(std::move(socket)), carrier_(std::make_shared<StreamCarrier>(socket_)),
          method_(std::move(method)), password_(std::move(password)),
          write_key_(std::move(write_key)), write_nonce_(std::move(write_nonce)),
          request_salt_(std::move(request_salt)), initial_wire_(std::move(initial_wire)),
          obfs_mode_(obfs_mode), obfs_response_ready_(obfs_mode == ObfsMode::none) {}

    Shadowsocks2022StreamState(std::shared_ptr<StreamCarrier> carrier, std::string method,
                               std::string password, std::vector<std::uint8_t> write_key,
                               std::vector<std::uint8_t> write_nonce,
                               std::vector<std::uint8_t> request_salt,
                               std::vector<std::uint8_t> initial_wire)
        : socket_(carrier ? carrier->socket() : nullptr), carrier_(std::move(carrier)),
          method_(std::move(method)), password_(std::move(password)),
          write_key_(std::move(write_key)), write_nonce_(std::move(write_nonce)),
          request_salt_(std::move(request_salt)), initial_wire_(std::move(initial_wire)) {}

    void read(boost::asio::mutable_buffer buffer, StreamReadHandler handler) {
        if (read_in_progress_) {
            post_read(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_read(std::move(handler), {}, 0);
            return;
        }
        if (pending_offset_ < pending_plaintext_.size()) {
            copy_pending(buffer, std::move(handler));
            return;
        }
        pending_plaintext_.clear();
        pending_offset_ = 0;
        read_buffer_ = buffer;
        read_handler_ = std::move(handler);
        read_in_progress_ = true;
        if (!obfs_response_ready_) {
            receive_obfs_response();
        } else if (!read_key_) {
            receive_salt();
        } else if (!response_header_ready_) {
            receive_response_fixed();
        } else {
            receive_record_for_payload();
        }
    }

    void write(boost::asio::const_buffer buffer, StreamWriteHandler handler) {
        if (write_in_progress_) {
            post_write(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_write(std::move(handler), {}, 0);
            return;
        }
        const auto *data = static_cast<const std::uint8_t *>(buffer.data());
        std::vector<std::uint8_t> encoded;
        for (std::size_t offset = 0; offset < buffer.size();) {
            const auto size = std::min(kMaxChunkPayload, buffer.size() - offset);
            auto record = encrypt_record(method_, write_key_, write_nonce_,
                                         std::span<const std::uint8_t>(data + offset, size));
            if (!record) {
                post_write(std::move(handler), boost::asio::error::operation_not_supported, 0);
                return;
            }
            encoded.insert(encoded.end(), record.value().begin(), record.value().end());
            offset += size;
        }
        auto wire = std::make_shared<std::vector<std::uint8_t>>(std::move(encoded));
        write_in_progress_ = true;
        auto self = shared_from_this();
        if (obfs_mode_ == ObfsMode::tls) {
            async_write_tls_obfs_records(
                socket_, std::move(*wire),
                [self, handler = std::move(handler), size = buffer.size()](core::Status result) {
                    self->write_in_progress_ = false;
                    handler(result ? boost::system::error_code() : boost::asio::error::fault,
                            result ? size : 0);
                });
            return;
        }
        StreamWriteHandler completion =
            [self, wire, handler = std::move(handler),
             size = buffer.size()](const boost::system::error_code &error, std::size_t) mutable {
                self->write_in_progress_ = false;
                handler(error, error ? 0 : size);
            };
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = carrier_->async_write(boost::asio::buffer(*wire));
        async::start_with_receiver(std::move(sender), CarrierWriteBridge{std::move(completion)});
    }

    boost::asio::any_io_executor executor() noexcept { return carrier_->executor(); }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        return carrier_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        carrier_->shutdown_send(error);
    }

    void close() noexcept {
        carrier_->close();
        finish_read(boost::asio::error::operation_aborted, 0);
    }

  private:
    void receive_obfs_response() {
        auto self = shared_from_this();
        auto handler = [self](core::Result<std::vector<std::uint8_t>> result) {
            if (!result) {
                self->finish_read(boost::asio::error::fault, 0);
                return;
            }
            self->initial_wire_ = std::move(result.value());
            self->initial_wire_offset_ = 0;
            self->obfs_response_ready_ = true;
            self->receive_salt();
        };
        if (obfs_mode_ == ObfsMode::http) {
            async_read_http_obfs_response(socket_, std::move(handler));
        } else {
            async_read_tls_obfs_response(socket_, std::move(handler));
        }
    }

    void receive_salt() {
        const auto method = cipher_method(method_);
        if (!method) {
            finish_read(protocol_error(), 0);
            return;
        }
        read_salt_.resize(method.value().key_size);
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(read_salt_), [self](const boost::system::error_code &error) {
            if (error) {
                self->finish_read(error, 0);
                return;
            }
            auto key = derive_shadowsocks_2022_session_key(self->method_, self->password_,
                                                           self->read_salt_);
            if (!key) {
                self->finish_read(authentication_error(), 0);
                return;
            }
            self->read_key_ = std::move(key.value());
            self->receive_response_fixed();
        });
    }

    void receive_response_fixed() {
        const auto method = cipher_method(method_);
        if (!method || !read_key_) {
            finish_read(protocol_error(), 0);
            return;
        }
        const auto fixed_size = 1 + 8 + request_salt_.size() + 2;
        auto encrypted =
            std::make_shared<std::vector<std::uint8_t>>(fixed_size + method.value().overhead);
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(*encrypted), [self, encrypted, fixed_size](
                                                        const boost::system::error_code &error) {
            if (error) {
                self->finish_read(error, 0);
                return;
            }
            auto fixed =
                aead_decrypt(self->method_, *self->read_key_, self->read_nonce_, *encrypted);
            self->increment_read_nonce();
            if (!fixed || fixed.value().size() != fixed_size || fixed.value()[0] != kServerHeader ||
                !std::equal(self->request_salt_.begin(), self->request_salt_.end(),
                            fixed.value().begin() + 1 + 8)) {
                self->finish_read(authentication_error(), 0);
                return;
            }
            const auto variable_size =
                read_u16(std::span<const std::uint8_t>(fixed.value()).subspan(fixed_size - 2, 2));
            if (variable_size > kMaxChunkPayload) {
                self->finish_read(protocol_error(), 0);
                return;
            }
            if (variable_size == 0) {
                self->response_header_ready_ = true;
                self->finish_pending_or_receive();
                return;
            }
            self->receive_response_variable(variable_size);
        });
    }

    void receive_response_variable(std::size_t variable_size) {
        const auto method = cipher_method(method_);
        auto encrypted =
            std::make_shared<std::vector<std::uint8_t>>(variable_size + method.value().overhead);
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(*encrypted),
                   [self, encrypted, variable_size](const boost::system::error_code &error) {
                       if (error) {
                           self->finish_read(error, 0);
                           return;
                       }
                       auto variable = aead_decrypt(self->method_, *self->read_key_,
                                                    self->read_nonce_, *encrypted);
                       self->increment_read_nonce();
                       if (!variable || variable.value().size() != variable_size) {
                           self->finish_read(authentication_error(), 0);
                           return;
                       }
                       self->pending_plaintext_ = std::move(variable.value());
                       self->pending_offset_ = 0;
                       self->response_header_ready_ = true;
                       self->finish_pending_or_receive();
                   });
    }

    void finish_pending_or_receive() {
        if (!pending_plaintext_.empty()) {
            copy_pending(read_buffer_, std::move(read_handler_));
            return;
        }
        receive_record_for_payload();
    }

    void receive_record_for_payload() {
        read_record([self = shared_from_this()](std::vector<std::uint8_t> payload) {
            self->pending_plaintext_ = std::move(payload);
            self->pending_offset_ = 0;
            self->copy_pending(self->read_buffer_, std::move(self->read_handler_));
        });
    }

    template <typename Handler> void read_record(Handler handler) {
        const auto method = cipher_method(method_);
        if (!method || !read_key_) {
            finish_read(protocol_error(), 0);
            return;
        }
        auto encrypted_length =
            std::make_shared<std::vector<std::uint8_t>>(2 + method.value().overhead);
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(*encrypted_length),
                   [self, encrypted_length,
                    handler = std::move(handler)](const boost::system::error_code &error) mutable {
                       if (error) {
                           self->finish_read(error, 0);
                           return;
                       }
                       auto length = aead_decrypt(self->method_, *self->read_key_,
                                                  self->read_nonce_, *encrypted_length);
                       self->increment_read_nonce();
                       if (!length || length.value().size() != 2) {
                           self->finish_read(authentication_error(), 0);
                           return;
                       }
                       const auto size = read_u16(length.value());
                       if (size == 0 || size > kMaxChunkPayload) {
                           self->finish_read(protocol_error(), 0);
                           return;
                       }
                       const auto method = cipher_method(self->method_);
                       auto encrypted_payload = std::make_shared<std::vector<std::uint8_t>>(
                           size + method.value().overhead);
                       self->read_exact(
                           boost::asio::buffer(*encrypted_payload),
                           [self, encrypted_payload, handler = std::move(handler)](
                               const boost::system::error_code &payload_error) mutable {
                               if (payload_error) {
                                   self->finish_read(payload_error, 0);
                                   return;
                               }
                               auto payload = aead_decrypt(self->method_, *self->read_key_,
                                                           self->read_nonce_, *encrypted_payload);
                               self->increment_read_nonce();
                               if (!payload) {
                                   self->finish_read(authentication_error(), 0);
                                   return;
                               }
                               handler(std::move(payload.value()));
                           });
                   });
    }

    using ExactReadHandler = std::function<void(const boost::system::error_code &)>;

    void read_exact(boost::asio::mutable_buffer buffer, ExactReadHandler handler) {
        if (obfs_mode_ == ObfsMode::tls) {
            read_exact_tls(buffer, std::move(handler), 0);
            return;
        }
        std::size_t copied = 0;
        if (initial_wire_offset_ < initial_wire_.size()) {
            copied = std::min(buffer.size(), initial_wire_.size() - initial_wire_offset_);
            std::memcpy(static_cast<std::uint8_t *>(buffer.data()),
                        initial_wire_.data() + initial_wire_offset_, copied);
            initial_wire_offset_ += copied;
            if (initial_wire_offset_ == initial_wire_.size()) {
                initial_wire_.clear();
                initial_wire_offset_ = 0;
            }
        }
        if (copied == buffer.size()) {
            boost::asio::post(carrier_->executor(),
                              [handler = std::move(handler)]() mutable { handler({}); });
            return;
        }
        auto remaining = boost::asio::mutable_buffer(
            static_cast<std::uint8_t *>(buffer.data()) + copied, buffer.size() - copied);
        read_exact_carrier(remaining, std::move(handler));
    }

    void read_exact_tls(boost::asio::mutable_buffer buffer, ExactReadHandler handler,
                        std::size_t copied) {
        if (initial_wire_offset_ < initial_wire_.size()) {
            const auto count =
                std::min(buffer.size() - copied, initial_wire_.size() - initial_wire_offset_);
            std::memcpy(static_cast<std::uint8_t *>(buffer.data()) + copied,
                        initial_wire_.data() + initial_wire_offset_, count);
            initial_wire_offset_ += count;
            copied += count;
            if (initial_wire_offset_ == initial_wire_.size()) {
                initial_wire_.clear();
                initial_wire_offset_ = 0;
            }
        }
        if (copied == buffer.size()) {
            boost::asio::post(carrier_->executor(),
                              [handler = std::move(handler)]() mutable { handler({}); });
            return;
        }
        auto self = shared_from_this();
        async_read_tls_obfs_record(socket_,
                                   [self, buffer, handler = std::move(handler), copied](
                                       core::Result<std::vector<std::uint8_t>> result) mutable {
                                       if (!result) {
                                           handler(boost::asio::error::fault);
                                           return;
                                       }
                                       self->initial_wire_ = std::move(result.value());
                                       self->initial_wire_offset_ = 0;
                                       self->read_exact_tls(buffer, std::move(handler), copied);
                                   });
    }

    void increment_read_nonce() { increment_nonce(read_nonce_); }

    void copy_pending(boost::asio::mutable_buffer buffer, StreamReadHandler handler) {
        const auto count = std::min(buffer.size(), pending_plaintext_.size() - pending_offset_);
        std::memcpy(buffer.data(), pending_plaintext_.data() + pending_offset_, count);
        pending_offset_ += count;
        if (pending_offset_ == pending_plaintext_.size()) {
            pending_plaintext_.clear();
            pending_offset_ = 0;
        }
        finish_read({}, count, std::move(handler));
    }

    void finish_read(const boost::system::error_code &error, std::size_t size) {
        finish_read(error, size, std::move(read_handler_));
    }

    void finish_read(const boost::system::error_code &error, std::size_t size,
                     StreamReadHandler handler) {
        read_in_progress_ = false;
        if (handler) {
            handler(error, size);
        }
    }

    void post_read(StreamReadHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(carrier_->executor(), [handler = std::move(handler), error,
                                                 size]() mutable { handler(error, size); });
    }

    void post_write(StreamWriteHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(carrier_->executor(), [handler = std::move(handler), error,
                                                 size]() mutable { handler(error, size); });
    }

    void read_exact_carrier(boost::asio::mutable_buffer buffer, ExactReadHandler handler) {
        auto self = shared_from_this();
        StreamReadHandler completion =
            [self, buffer, handler = std::move(handler)](const boost::system::error_code &error,
                                                         std::size_t size) mutable {
                if (error) {
                    handler(error);
                    return;
                }
                if (size == 0) {
                    handler(boost::asio::error::eof);
                    return;
                }
                if (size == buffer.size()) {
                    handler({});
                    return;
                }
                auto remaining = boost::asio::mutable_buffer(
                    static_cast<std::uint8_t *>(buffer.data()) + size, buffer.size() - size);
                self->read_exact_carrier(remaining, std::move(handler));
            };
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = carrier_->async_read_some(buffer);
        async::start_with_receiver(std::move(sender), CarrierReadBridge{std::move(completion)});
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::shared_ptr<StreamCarrier> carrier_;
    std::string method_;
    std::string password_;
    std::vector<std::uint8_t> write_key_;
    std::vector<std::uint8_t> write_nonce_;
    std::vector<std::uint8_t> request_salt_;
    std::vector<std::uint8_t> initial_wire_;
    std::size_t initial_wire_offset_ = 0;
    ObfsMode obfs_mode_ = ObfsMode::none;
    bool obfs_response_ready_ = true;
    std::optional<std::vector<std::uint8_t>> read_key_;
    std::vector<std::uint8_t> read_nonce_ = std::vector<std::uint8_t>(12, 0);
    std::vector<std::uint8_t> read_salt_;
    std::vector<std::uint8_t> pending_plaintext_;
    std::size_t pending_offset_ = 0;
    bool response_header_ready_ = false;
    bool read_in_progress_ = false;
    bool write_in_progress_ = false;
    boost::asio::mutable_buffer read_buffer_;
    StreamReadHandler read_handler_;
};

io::AnySender<std::optional<std::size_t>>
Shadowsocks2022StreamHandle::async_read_some(boost::asio::mutable_buffer buffer) {
    auto state = state_;
    return io::AnySender<std::optional<std::size_t>>{async::callback_sender<ReadSignatures>(
        [state, buffer](auto terminal) mutable {
            state->read(buffer, [terminal = std::move(terminal)](
                                    const boost::system::error_code &error,
                                    std::size_t count) mutable { terminal(error, count); });
        },
        [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
            net::translate_read(std::move(receiver), error, count, "shadowsocks-2022 read");
        })};
}

io::AnySender<std::size_t>
Shadowsocks2022StreamHandle::async_write(boost::asio::const_buffer buffer) {
    auto state = state_;
    return io::AnySender<std::size_t>{async::callback_sender<WriteSignatures>(
        [state, buffer](auto terminal) mutable {
            state->write(buffer, [terminal = std::move(terminal)](
                                     const boost::system::error_code &error,
                                     std::size_t count) mutable { terminal(error, count); });
        },
        [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
            net::translate_write(std::move(receiver), error, count, "shadowsocks-2022 write");
        })};
}

boost::asio::any_io_executor Shadowsocks2022StreamHandle::executor() noexcept {
    return state_->executor();
}

boost::asio::ip::tcp::endpoint
Shadowsocks2022StreamHandle::local_endpoint(boost::system::error_code &error) const noexcept {
    return state_->local_endpoint(error);
}

void Shadowsocks2022StreamHandle::shutdown_send(boost::system::error_code &error) noexcept {
    state_->shutdown_send(error);
}

void Shadowsocks2022StreamHandle::close() noexcept { state_->close(); }

class Shadowsocks2022OpenOperation final
    : public std::enable_shared_from_this<Shadowsocks2022OpenOperation> {
  public:
    Shadowsocks2022OpenOperation(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                 std::string method, std::string password,
                                 std::vector<std::uint8_t> destination,
                                 std::optional<ObfsClientOptions> obfs_options,
                                 Shadowsocks2022OpenHandler handler)
        : socket_(std::move(socket)), method_(std::move(method)), password_(std::move(password)),
          destination_(std::move(destination)), obfs_options_(std::move(obfs_options)),
          handler_(std::move(handler)) {}

    Shadowsocks2022OpenOperation(std::shared_ptr<StreamCarrier> carrier, std::string method,
                                 std::string password, std::vector<std::uint8_t> destination,
                                 Shadowsocks2022OpenHandler handler)
        : carrier_(std::move(carrier)), method_(std::move(method)), password_(std::move(password)),
          destination_(std::move(destination)), handler_(std::move(handler)) {}

    void start() { scope_.spawn(run_open(shared_from_this())); }

    static exec::task<void> run_open(std::shared_ptr<Shadowsocks2022OpenOperation> self) {
        const auto method = cipher_method(self->method_);
        if (!method || !method.value().shadowsocks_2022) {
            self->complete(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration, "unsupported Shadowsocks 2022 method"}));
            co_return;
        }
        self->request_salt_.resize(method.value().key_size);
        if (!random_bytes(self->request_salt_)) {
            self->complete(core::StreamOpenResult::failed(
                {core::ErrorCode::authentication, "failed to generate Shadowsocks 2022 salt"}));
            co_return;
        }
        auto key = derive_shadowsocks_2022_session_key(self->method_, self->password_,
                                                       self->request_salt_);
        if (!key || self->destination_.empty() ||
            self->destination_.size() + 2 > kMaxChunkPayload) {
            self->complete(core::StreamOpenResult::failed(
                key ? core::Error{core::ErrorCode::protocol_framing,
                                  "invalid Shadowsocks destination address"}
                    : key.error()));
            co_return;
        }
        std::vector<std::uint8_t> fixed;
        fixed.reserve(kFixedHeaderSize);
        fixed.push_back(kClientHeader);
        append_u64(fixed, unix_seconds());
        constexpr std::size_t padding_size = 1;
        append_u16(fixed, self->destination_.size() + 2 + padding_size);
        std::vector<std::uint8_t> variable = self->destination_;
        append_u16(variable, padding_size);
        variable.push_back(0);
        std::vector<std::uint8_t> nonce(method.value().nonce_size, 0);
        auto fixed_record = encrypt_chunk(self->method_, key.value(), nonce, fixed);
        auto variable_record = encrypt_chunk(self->method_, key.value(), nonce, variable);
        if (!fixed_record || !variable_record) {
            self->complete(core::StreamOpenResult::failed(
                {core::ErrorCode::authentication, "failed to encrypt Shadowsocks 2022 request"}));
            co_return;
        }
        auto wire = std::make_shared<std::vector<std::uint8_t>>(self->request_salt_);
        wire->insert(wire->end(), fixed_record.value().begin(), fixed_record.value().end());
        wire->insert(wire->end(), variable_record.value().begin(), variable_record.value().end());
        if (self->carrier_) {
            try {
                co_await self->carrier_->async_write(boost::asio::buffer(*wire));
            } catch (const core::Error &failure) {
                self->complete(core::StreamOpenResult::failed(
                    {failure.code, "failed to write Shadowsocks 2022 WebSocket request",
                     failure.cause}));
                co_return;
            } catch (...) {
                self->complete(core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io,
                     "failed to write Shadowsocks 2022 WebSocket request",
                     {}}));
                co_return;
            }
            self->complete(
                core::StreamOpenResult::opened(std::make_unique<Shadowsocks2022StreamHandle>(
                    std::make_shared<Shadowsocks2022StreamState>(
                        self->carrier_, self->method_, self->password_, std::move(key.value()),
                        std::move(nonce), std::move(self->request_salt_),
                        std::vector<std::uint8_t>{}))));
            co_return;
        }
        if (self->obfs_options_) {
            core::Status obfs_result;
            try {
                if (self->obfs_options_->mode == ObfsMode::http) {
                    obfs_result = co_await async::bridge_sender<core::Status>(
                        [self, wire](async::BridgeSender<core::Status>::Handler done) mutable {
                            async_write_http_obfs_request(
                                self->socket_, std::move(*wire),
                                {self->obfs_options_->host, self->obfs_options_->port},
                                [done](core::Status result) mutable { done(std::move(result)); });
                            return async::BridgeSender<core::Status>::AbortFn{};
                        });
                } else {
                    obfs_result = co_await async::bridge_sender<core::Status>(
                        [self, wire](async::BridgeSender<core::Status>::Handler done) mutable {
                            async_write_tls_obfs_request(
                                self->socket_, std::move(*wire), self->obfs_options_->host,
                                [done](core::Status result) mutable { done(std::move(result)); });
                            return async::BridgeSender<core::Status>::AbortFn{};
                        });
                }
            } catch (...) {
                self->complete(core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "Shadowsocks obfs request failed", {}}));
                co_return;
            }
            if (!obfs_result) {
                self->complete(core::StreamOpenResult::failed(obfs_result.error()));
                co_return;
            }
            self->complete(
                core::StreamOpenResult::opened(std::make_unique<Shadowsocks2022StreamHandle>(
                    std::make_shared<Shadowsocks2022StreamState>(
                        self->socket_, self->method_, self->password_, std::move(key.value()),
                        std::move(nonce), std::move(self->request_salt_),
                        std::vector<std::uint8_t>{}, self->obfs_options_->mode))));
            co_return;
        }
        try {
            co_await (
                boost::asio::async_write(*self->socket_, boost::asio::buffer(*wire),
                                         exec::asio::use_sender) |
                stdexec::then([](std::size_t) {}) |
                stdexec::let_error([](std::exception_ptr error) {
                    try {
                        std::rethrow_exception(std::move(error));
                    } catch (const boost::system::system_error &failure) {
                        return stdexec::just_error(std::make_exception_ptr(core::Error{
                            core::ErrorCode::transport_io,
                            "failed to write Shadowsocks 2022 request",
                            std::error_code(failure.code().value(), std::system_category())}));
                    }
                    std::rethrow_exception(std::current_exception());
                }));
        } catch (const core::Error &failure) {
            self->complete(core::StreamOpenResult::failed(failure));
            co_return;
        } catch (...) {
            self->complete(core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "failed to write Shadowsocks 2022 request", {}}));
            co_return;
        }
        self->complete(core::StreamOpenResult::opened(std::make_unique<Shadowsocks2022StreamHandle>(
            std::make_shared<Shadowsocks2022StreamState>(
                self->socket_, self->method_, self->password_, std::move(key.value()),
                std::move(nonce), std::move(self->request_salt_), std::vector<std::uint8_t>{},
                ObfsMode::none))));
    }

  private:
    void complete(core::StreamOpenResult result) {
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::shared_ptr<StreamCarrier> carrier_;
    std::string method_;
    std::string password_;
    std::vector<std::uint8_t> destination_;
    std::vector<std::uint8_t> request_salt_;
    std::optional<ObfsClientOptions> obfs_options_;
    Shadowsocks2022OpenHandler handler_;
    exec::async_scope scope_;
};

} // namespace

void async_open_shadowsocks_2022_stream(runtime::AsioRuntime &,
                                        std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                        std::string method, std::string password,
                                        std::vector<std::uint8_t> destination,
                                        std::optional<ObfsClientOptions> obfs_options,
                                        Shadowsocks2022OpenHandler handler) {
    std::make_shared<Shadowsocks2022OpenOperation>(std::move(socket), std::move(method),
                                                   std::move(password), std::move(destination),
                                                   std::move(obfs_options), std::move(handler))
        ->start();
}

void async_open_shadowsocks_2022_stream(runtime::AsioRuntime &,
                                        std::shared_ptr<StreamCarrier> carrier, std::string method,
                                        std::string password, std::vector<std::uint8_t> destination,
                                        Shadowsocks2022OpenHandler handler) {
    if (!carrier) {
        if (handler) {
            handler(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration, "Shadowsocks 2022 carrier is required"}));
        }
        return;
    }
    std::make_shared<Shadowsocks2022OpenOperation>(std::move(carrier), std::move(method),
                                                   std::move(password), std::move(destination),
                                                   std::move(handler))
        ->start();
}

} // namespace clash_native::transport::shadowsocks
