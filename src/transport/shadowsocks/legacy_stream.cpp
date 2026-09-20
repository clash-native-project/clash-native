#include <clash_native/transport/shadowsocks/legacy_stream.hpp>

#include <clash_native/transport/shadowsocks/crypto.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <utility>

namespace clash_native::transport::shadowsocks {

namespace {

class LegacyStreamState final : public std::enable_shared_from_this<LegacyStreamState> {
  public:
    LegacyStreamState(std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::string method,
                      std::string password, LegacyStreamCipher write_cipher)
        : socket_(std::move(socket)), method_(std::move(method)), password_(std::move(password)),
          write_cipher_(std::move(write_cipher)) {}

    void read(boost::asio::mutable_buffer buffer, core::StreamHandle::ReadHandler handler) {
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
        if (!read_cipher_) {
            receive_iv();
            return;
        }
        receive_plaintext();
    }

    void write(boost::asio::const_buffer buffer, core::StreamHandle::WriteHandler handler) {
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
        boost::asio::async_write(
            *socket_, boost::asio::buffer(*wire),
            [self, wire, handler = std::move(handler), size = buffer.size()](
                const boost::system::error_code &error, std::size_t) mutable {
                self->write_in_progress_ = false;
                handler(error, error ? 0 : size);
            });
    }

    void close() noexcept {
        boost::system::error_code ignored;
        socket_->cancel(ignored);
        socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
        socket_->close(ignored);
        finish_read(boost::asio::error::operation_aborted, 0);
    }

    boost::asio::any_io_executor executor() noexcept { return socket_->get_executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept {
        return socket_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_send, error);
    }

  private:
    void receive_iv() {
        const auto spec = cipher_method(method_);
        if (!spec) {
            finish_read(boost::asio::error::operation_not_supported, 0);
            return;
        }
        receive_iv_buffer_.resize(spec.value().iv_size);
        auto self = shared_from_this();
        boost::asio::async_read(
            *socket_, boost::asio::buffer(receive_iv_buffer_),
            [self](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    self->finish_read(error, 0);
                    return;
                }
                auto key = derive_legacy_key(self->method_, self->password_,
                                             self->receive_iv_buffer_);
                if (!key) {
                    self->finish_read(boost::asio::error::operation_not_supported, 0);
                    return;
                }
                auto cipher = LegacyStreamCipher::create(
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
        socket_->async_read_some(
            read_buffer_,
            [self](const boost::system::error_code &error, std::size_t size) {
                if (error && error != boost::asio::error::eof) {
                    self->finish_read(error, size);
                    return;
                }
                if (const auto result = self->read_cipher_->update(
                        std::span<std::uint8_t>(static_cast<std::uint8_t *>(self->read_buffer_.data()),
                                                size));
                    !result) {
                    self->finish_read(boost::asio::error::operation_not_supported, 0);
                    return;
                }
                self->finish_read(error, size);
            });
    }

    void finish_read(const boost::system::error_code &error, std::size_t size) {
        read_in_progress_ = false;
        auto handler = std::move(read_handler_);
        if (handler) {
            handler(error, size);
        }
    }

    void post_read(core::StreamHandle::ReadHandler handler, boost::system::error_code error,
                   std::size_t size) {
        boost::asio::post(socket_->get_executor(),
                          [handler = std::move(handler), error, size]() mutable {
                              handler(error, size);
                          });
    }

    void post_write(core::StreamHandle::WriteHandler handler, boost::system::error_code error,
                    std::size_t size) {
        boost::asio::post(socket_->get_executor(),
                          [handler = std::move(handler), error, size]() mutable {
                              handler(error, size);
                          });
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::string method_;
    std::string password_;
    LegacyStreamCipher write_cipher_;
    std::optional<LegacyStreamCipher> read_cipher_;
    std::vector<std::uint8_t> receive_iv_buffer_;
    boost::asio::mutable_buffer read_buffer_;
    core::StreamHandle::ReadHandler read_handler_;
    bool read_in_progress_ = false;
    bool write_in_progress_ = false;
};

class LegacyStreamHandle final : public core::StreamHandle {
  public:
    explicit LegacyStreamHandle(std::shared_ptr<LegacyStreamState> state)
        : state_(std::move(state)) {}

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        state_->read(buffer, std::move(handler));
    }
    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        state_->write(buffer, std::move(handler));
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

core::Result<std::unique_ptr<core::StreamHandle>> make_legacy_stream_handle(
    std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::string method,
    std::string password, LegacyStreamCipher write_cipher) {
    auto state = std::make_shared<LegacyStreamState>(std::move(socket), std::move(method),
                                                     std::move(password), std::move(write_cipher));
    return std::unique_ptr<core::StreamHandle>(std::make_unique<LegacyStreamHandle>(
        std::move(state)));
}

} // namespace clash_native::transport::shadowsocks
