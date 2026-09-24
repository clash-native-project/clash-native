#include <clash_native/transport/shadowsocks/legacy_stream.hpp>

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/transport/proxy/crypto.hpp>
#include <clash_native/transport/shadowsocks/simple_obfs.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <optional>
#include <span>
#include <utility>

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

class LegacyStreamState final : public std::enable_shared_from_this<LegacyStreamState> {
  public:
    LegacyStreamState(std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::string method,
                      std::string password, transport::proxy::LegacyStreamCipher write_cipher,
                      std::vector<std::uint8_t> initial_wire, ObfsMode obfs_mode)
        : socket_(std::move(socket)), carrier_(std::make_shared<StreamCarrier>(socket_)),
          method_(std::move(method)), password_(std::move(password)),
          write_cipher_(std::move(write_cipher)), initial_wire_(std::move(initial_wire)),
          obfs_mode_(obfs_mode), obfs_response_ready_(obfs_mode == ObfsMode::none) {}

    LegacyStreamState(std::shared_ptr<StreamCarrier> carrier, std::string method,
                      std::string password, transport::proxy::LegacyStreamCipher write_cipher,
                      std::vector<std::uint8_t> initial_wire)
        : socket_(carrier ? carrier->socket() : nullptr), carrier_(std::move(carrier)),
          method_(std::move(method)), password_(std::move(password)),
          write_cipher_(std::move(write_cipher)), initial_wire_(std::move(initial_wire)) {}

    void read(boost::asio::mutable_buffer buffer, StreamReadHandler handler) {
        if (read_in_progress_) {
            post_read(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_read(std::move(handler), {}, 0);
            return;
        }
        read_in_progress_ = true;
        read_buffer_ = buffer;
        read_handler_ = std::move(handler);
        if (!obfs_response_ready_) {
            receive_obfs_response();
        } else if (!read_cipher_) {
            receive_iv();
            return;
        }
        receive_plaintext();
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
        if (buffer.size() > static_cast<std::size_t>(INT_MAX)) {
            post_write(std::move(handler), boost::asio::error::message_size, 0);
            return;
        }
        auto wire = std::make_shared<std::vector<std::uint8_t>>(
            static_cast<const std::uint8_t *>(buffer.data()),
            static_cast<const std::uint8_t *>(buffer.data()) + buffer.size());
        if (const auto result = write_cipher_.update(*wire); !result) {
            post_write(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
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

    void close() noexcept {
        carrier_->close();
        finish_read(boost::asio::error::operation_aborted, 0);
    }

    boost::asio::any_io_executor executor() noexcept { return carrier_->executor(); }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        return carrier_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        carrier_->shutdown_send(error);
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
            self->receive_iv();
        };
        if (obfs_mode_ == ObfsMode::http) {
            async_read_http_obfs_response(socket_, std::move(handler));
        } else {
            async_read_tls_obfs_response(socket_, std::move(handler));
        }
    }

    void receive_iv() {
        const auto spec = transport::proxy::cipher_method(method_);
        if (!spec) {
            finish_read(boost::asio::error::operation_not_supported, 0);
            return;
        }
        receive_iv_buffer_.resize(spec.value().iv_size);
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(receive_iv_buffer_),
                   [self](const boost::system::error_code &error) {
                       if (error) {
                           self->finish_read(error, 0);
                           return;
                       }
                       auto key = transport::proxy::derive_legacy_key(
                           self->method_, self->password_, self->receive_iv_buffer_);
                       if (!key) {
                           self->finish_read(boost::asio::error::operation_not_supported, 0);
                           return;
                       }
                       auto cipher = transport::proxy::LegacyStreamCipher::create(
                           self->method_, key.value(), self->receive_iv_buffer_, false);
                       if (!cipher) {
                           self->finish_read(boost::asio::error::operation_not_supported, 0);
                           return;
                       }
                       self->read_cipher_ = std::move(cipher.value());
                       self->receive_plaintext();
                   });
    }

    void receive_plaintext() {
        auto self = shared_from_this();
        if (initial_wire_offset_ < initial_wire_.size()) {
            const auto count =
                std::min(read_buffer_.size(), initial_wire_.size() - initial_wire_offset_);
            std::memcpy(read_buffer_.data(), initial_wire_.data() + initial_wire_offset_, count);
            initial_wire_offset_ += count;
            if (initial_wire_offset_ == initial_wire_.size()) {
                initial_wire_.clear();
                initial_wire_offset_ = 0;
            }
            process_plaintext({}, count);
            return;
        }
        if (obfs_mode_ == ObfsMode::tls) {
            async_read_tls_obfs_record(socket_,
                                       [self](core::Result<std::vector<std::uint8_t>> result) {
                                           if (!result) {
                                               self->finish_read(boost::asio::error::fault, 0);
                                               return;
                                           }
                                           self->initial_wire_ = std::move(result.value());
                                           self->initial_wire_offset_ = 0;
                                           self->receive_plaintext();
                                       });
            return;
        }
        StreamReadHandler completion = [self](const boost::system::error_code &error,
                                              std::size_t size) {
            if (error && error != boost::asio::error::eof) {
                self->finish_read(error, size);
                return;
            }
            self->process_plaintext(error, size);
        };
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = carrier_->async_read_some(read_buffer_);
        async::start_with_receiver(std::move(sender), CarrierReadBridge{std::move(completion)});
    }

    void process_plaintext(const boost::system::error_code &error, std::size_t size) {
        if (const auto result = read_cipher_->update(
                std::span<std::uint8_t>(static_cast<std::uint8_t *>(read_buffer_.data()), size));
            !result) {
            finish_read(boost::asio::error::operation_not_supported, 0);
            return;
        }
        finish_read(error, size);
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

    void finish_read(const boost::system::error_code &error, std::size_t size) {
        read_in_progress_ = false;
        auto handler = std::move(read_handler_);
        if (handler) {
            handler(error, size);
        }
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

    void post_read(StreamReadHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(carrier_->executor(), [handler = std::move(handler), error,
                                                 size]() mutable { handler(error, size); });
    }

    void post_write(StreamWriteHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(carrier_->executor(), [handler = std::move(handler), error,
                                                 size]() mutable { handler(error, size); });
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::shared_ptr<StreamCarrier> carrier_;
    std::string method_;
    std::string password_;
    transport::proxy::LegacyStreamCipher write_cipher_;
    std::optional<transport::proxy::LegacyStreamCipher> read_cipher_;
    std::vector<std::uint8_t> receive_iv_buffer_;
    std::vector<std::uint8_t> initial_wire_;
    std::size_t initial_wire_offset_ = 0;
    ObfsMode obfs_mode_ = ObfsMode::none;
    bool obfs_response_ready_ = true;
    boost::asio::mutable_buffer read_buffer_;
    StreamReadHandler read_handler_;
    bool read_in_progress_ = false;
    bool write_in_progress_ = false;
};

class LegacyStreamHandle final : public io::StreamHandle {
  public:
    using ReadSignatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;
    using WriteSignatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                           stdexec::set_error_t(std::exception_ptr),
                                                           stdexec::set_stopped_t()>;

    explicit LegacyStreamHandle(std::shared_ptr<LegacyStreamState> state)
        : state_(std::move(state)) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        auto state = state_;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<ReadSignatures>(
            [state, buffer](auto terminal) mutable {
                state->read(buffer, [terminal = std::move(terminal)](
                                        const boost::system::error_code &error,
                                        std::size_t count) mutable { terminal(error, count); });
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
                net::translate_read(std::move(receiver), error, count, "legacy read");
            })};
    }
    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        auto state = state_;
        return io::AnySender<std::size_t>{async::callback_sender<WriteSignatures>(
            [state, buffer](auto terminal) mutable {
                state->write(buffer, [terminal = std::move(terminal)](
                                         const boost::system::error_code &error,
                                         std::size_t count) mutable { terminal(error, count); });
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
                net::translate_write(std::move(receiver), error, count, "legacy write");
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
    std::shared_ptr<LegacyStreamState> state_;
};

} // namespace

core::Result<std::unique_ptr<io::StreamHandle>>
make_legacy_stream_handle(std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::string method,
                          std::string password, transport::proxy::LegacyStreamCipher write_cipher,
                          std::vector<std::uint8_t> initial_wire, ObfsMode obfs_mode) {
    auto state = std::make_shared<LegacyStreamState>(std::move(socket), std::move(method),
                                                     std::move(password), std::move(write_cipher),
                                                     std::move(initial_wire), obfs_mode);
    return std::unique_ptr<io::StreamHandle>(
        std::make_unique<LegacyStreamHandle>(std::move(state)));
}

core::Result<std::unique_ptr<io::StreamHandle>>
make_legacy_stream_handle(std::shared_ptr<StreamCarrier> carrier, std::string method,
                          std::string password, transport::proxy::LegacyStreamCipher write_cipher,
                          std::vector<std::uint8_t> initial_wire) {
    if (!carrier) {
        return core::fail(
            {core::ErrorCode::configuration, "legacy Shadowsocks carrier is required", {}});
    }
    auto state = std::make_shared<LegacyStreamState>(std::move(carrier), std::move(method),
                                                     std::move(password), std::move(write_cipher),
                                                     std::move(initial_wire));
    return std::unique_ptr<io::StreamHandle>(
        std::make_unique<LegacyStreamHandle>(std::move(state)));
}

} // namespace clash_native::transport::shadowsocks
