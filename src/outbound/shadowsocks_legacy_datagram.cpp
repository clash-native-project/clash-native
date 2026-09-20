#include "shadowsocks_legacy_datagram.hpp"

#include "outbound_utils.hpp"
#include "proxy_address.hpp"

#include <clash_native/transport/shadowsocks/crypto.hpp>
#include <clash_native/transport/shadowsocks/legacy_packet.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/errc.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace clash_native::outbound::detail {

namespace {

constexpr std::size_t kMaxUdpWireSize = 65507;
constexpr std::size_t kMaxEncryptedUdpDatagramSize = 1500;
constexpr std::size_t kMaxProxyAddressSize = 1 + 1 + 255 + 2;

boost::system::error_code protocol_error() {
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

class LegacyDatagramState final : public std::enable_shared_from_this<LegacyDatagramState> {
  public:
    LegacyDatagramState(std::shared_ptr<net::UdpStream> socket,
                        boost::asio::ip::udp::endpoint server, std::string method,
                        std::string password)
        : socket_(std::move(socket)), server_(std::move(server)), method_(std::move(method)),
          password_(std::move(password)) {}

    void send(boost::asio::const_buffer buffer, core::DatagramAddress destination,
              core::DatagramHandle::WriteHandler handler) {
        auto address = encode_proxy_address(destination.to_destination());
        if (!address) {
            boost::asio::post(socket_->executor(), [handler = std::move(handler)]() mutable {
                handler(protocol_error(), 0);
            });
            return;
        }
        std::vector<std::uint8_t> plaintext = std::move(address.value());
        const auto *payload = static_cast<const std::uint8_t *>(buffer.data());
        plaintext.insert(plaintext.end(), payload, payload + buffer.size());
        auto wire = transport::shadowsocks::encrypt_legacy_datagram(method_, password_, plaintext);
        if (!wire || wire.value().size() > kMaxEncryptedUdpDatagramSize) {
            boost::asio::post(socket_->executor(), [handler = std::move(handler)]() mutable {
                handler(wire_error(), 0);
            });
            return;
        }
        auto packet = std::make_shared<std::vector<std::uint8_t>>(std::move(wire.value()));
        auto self = shared_from_this();
        socket_->async_send_to(boost::asio::buffer(*packet),
                               core::DatagramAddress::from_endpoint(server_),
                               [self, packet, handler = std::move(handler), size = buffer.size()](
                                   const boost::system::error_code &error, std::size_t) mutable {
                                   handler(error, error ? 0 : size);
                               });
    }

    void receive(boost::asio::mutable_buffer buffer, core::DatagramHandle::ReadHandler handler) {
        if (receive_in_progress_) {
            boost::asio::post(socket_->executor(), [handler = std::move(handler)]() mutable {
                handler(boost::asio::error::already_started, 0, {});
            });
            return;
        }
        receive_in_progress_ = true;
        output_buffer_ = buffer;
        receive_handler_ = std::move(handler);
        receive_next();
    }

    void close() noexcept { socket_->close(); }

    boost::asio::any_io_executor executor() noexcept { return socket_->executor(); }

    std::size_t max_datagram_size() const noexcept {
        return std::min<std::size_t>(
            transport::shadowsocks::legacy_datagram_payload_limit(
                method_, kMaxEncryptedUdpDatagramSize, kMaxProxyAddressSize),
            kMaxUdpWireSize);
    }

  private:
    static boost::system::error_code wire_error() {
        return boost::system::errc::make_error_code(boost::system::errc::message_size);
    }

    void receive_next() {
        auto self = shared_from_this();
        socket_->async_receive_from(boost::asio::buffer(receive_buffer_),
                                    [self](const boost::system::error_code &error, std::size_t size,
                                           core::DatagramAddress sender) {
                                        if (error) {
                                            self->finish_receive(error, 0, {});
                                            return;
                                        }
                                        if (!sender.is_address() ||
                                            sender.address() != self->server_.address() ||
                                            sender.port() != self->server_.port()) {
                                            self->receive_next();
                                            return;
                                        }
                                        self->decode_response(size);
                                    });
    }

    void decode_response(std::size_t size) {
        auto plaintext = transport::shadowsocks::decrypt_legacy_datagram(
            method_, password_, std::span<const std::uint8_t>(receive_buffer_.data(), size));
        if (!plaintext) {
            finish_receive(protocol_error(), 0, {});
            return;
        }
        auto address = decode_proxy_address(plaintext.value());
        if (!address || address.value().size > plaintext.value().size()) {
            finish_receive(protocol_error(), 0, {});
            return;
        }
        const auto payload_offset = address.value().size;
        const auto payload_size = plaintext.value().size() - payload_offset;
        if (address.value().destination.is_address()) {
            complete_payload(plaintext.value(), payload_offset, payload_size,
                             core::DatagramAddress::address(address.value().destination.address(),
                                                            address.value().destination.port()));
            return;
        }
        complete_payload(plaintext.value(), payload_offset, payload_size,
                         core::DatagramAddress::domain(address.value().destination.domain(),
                                                       address.value().destination.port()));
    }

    void complete_payload(const std::vector<std::uint8_t> &plaintext, std::size_t offset,
                          std::size_t size, core::DatagramAddress sender) {
        if (size > output_buffer_.size()) {
            finish_receive(boost::asio::error::message_size, 0, {});
            return;
        }
        if (size != 0) {
            std::memcpy(output_buffer_.data(), plaintext.data() + offset, size);
        }
        finish_receive({}, size, std::move(sender));
    }

    void finish_receive(const boost::system::error_code &error, std::size_t size,
                        core::DatagramAddress sender) {
        receive_in_progress_ = false;
        auto handler = std::move(receive_handler_);
        if (handler) {
            handler(error, size, std::move(sender));
        }
    }

    std::shared_ptr<net::UdpStream> socket_;
    boost::asio::ip::udp::endpoint server_;
    std::string method_;
    std::string password_;
    std::array<std::uint8_t, kMaxUdpWireSize> receive_buffer_{};
    boost::asio::mutable_buffer output_buffer_;
    core::DatagramHandle::ReadHandler receive_handler_;
    bool receive_in_progress_ = false;
};

class LegacyDatagramHandle final : public core::DatagramHandle {
  public:
    explicit LegacyDatagramHandle(std::shared_ptr<LegacyDatagramState> state)
        : state_(std::move(state)) {}

    void async_send_to(boost::asio::const_buffer buffer, core::DatagramAddress destination,
                       WriteHandler handler) override {
        state_->send(buffer, std::move(destination), std::move(handler));
    }
    void async_receive_from(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        state_->receive(buffer, std::move(handler));
    }
    boost::asio::any_io_executor executor() noexcept override { return state_->executor(); }
    std::size_t max_datagram_size() const noexcept override { return state_->max_datagram_size(); }
    void cancel() noexcept override { state_->close(); }
    void close() noexcept override { state_->close(); }

  private:
    std::shared_ptr<LegacyDatagramState> state_;
};

} // namespace

core::Result<std::unique_ptr<core::DatagramHandle>>
make_legacy_shadowsocks_datagram_handle(std::shared_ptr<net::UdpStream> socket,
                                        boost::asio::ip::udp::endpoint server, std::string method,
                                        std::string password) {
    const auto spec = transport::shadowsocks::cipher_method(method);
    if (!spec) {
        return core::fail(spec.error());
    }
    if (spec.value().kind != transport::shadowsocks::CipherKind::stream) {
        return core::fail({core::ErrorCode::configuration,
                           "legacy Shadowsocks datagram handle requires a stream cipher"});
    }
    auto state = std::make_shared<LegacyDatagramState>(std::move(socket), std::move(server),
                                                       std::move(method), std::move(password));
    return std::unique_ptr<core::DatagramHandle>(
        std::make_unique<LegacyDatagramHandle>(std::move(state)));
}

} // namespace clash_native::outbound::detail
