#include "shadowsocks_legacy_datagram.hpp"

#include "outbound_utils.hpp"
#include "proxy_address.hpp"

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/transport/proxy/crypto.hpp>
#include <clash_native/transport/shadowsocks/legacy_packet.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <stdexec/execution.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace clash_native::outbound::detail {

namespace {

constexpr std::size_t kMaxUdpWireSize = 65507;
constexpr std::size_t kMaxEncryptedUdpDatagramSize = 1500;
constexpr std::size_t kMaxProxyAddressSize = 1 + 1 + 255 + 2;

using SendTerminal = std::function<void(const boost::system::error_code &, std::size_t)>;
using ReceiveTerminal =
    std::function<void(const boost::system::error_code &, std::size_t, io::DatagramAddress)>;

class LegacyDatagramState final : public std::enable_shared_from_this<LegacyDatagramState> {
  public:
    LegacyDatagramState(std::shared_ptr<net::UdpStream> socket,
                        boost::asio::ip::udp::endpoint server, std::string method,
                        std::string password)
        : socket_(std::move(socket)), server_(std::move(server)), method_(std::move(method)),
          password_(std::move(password)) {}

    io::AnySender<std::size_t> async_send(boost::asio::const_buffer buffer,
                                          io::DatagramAddress destination) {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        if (send_in_progress_) {
            return io::AnySender<std::size_t>{stdexec::just_error(std::make_exception_ptr(
                core::Error{core::ErrorCode::transport_io, "legacy datagram send in progress"}))};
        }
        auto address = encode_proxy_address(
            outbound::detail::to_core_destination(destination.to_destination()));
        if (!address) {
            return io::AnySender<std::size_t>{
                stdexec::just_error(std::make_exception_ptr(address.error()))};
        }
        std::vector<std::uint8_t> plaintext = std::move(address.value());
        const auto *payload = static_cast<const std::uint8_t *>(buffer.data());
        plaintext.insert(plaintext.end(), payload, payload + buffer.size());
        auto wire = transport::shadowsocks::encrypt_legacy_datagram(method_, password_, plaintext);
        if (!wire || wire.value().size() > kMaxEncryptedUdpDatagramSize) {
            const auto failure = wire ? core::Error{core::ErrorCode::transport_io,
                                                    "legacy datagram exceeds encrypted size limit"}
                                      : wire.error();
            return io::AnySender<std::size_t>{
                stdexec::just_error(std::make_exception_ptr(failure))};
        }
        auto self = shared_from_this();
        auto packet = std::make_shared<std::vector<std::uint8_t>>(std::move(wire.value()));
        const auto plaintext_size = buffer.size();
        send_in_progress_ = true;
        return io::AnySender<std::size_t>{async::callback_sender<Signatures>(
            [self, packet, plaintext_size](auto terminal) mutable -> async::CallbackAbortFn {
                // Single send chain as one task co_awaiting the socket sender;
                // teardown stays guard-driven, so no stop is ever requested.
                // The terminal drops late completions once stop/destroy claims
                // the callback_sender settlement.
                SendTerminal done{std::move(terminal)};
                self->scope_.spawn(
                    run_send(self, std::move(packet), plaintext_size, std::move(done)));
                return async::CallbackAbortFn{[self] { self->abort(); }};
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
                stdexec::set_error(std::move(receiver), std::make_exception_ptr(core::Error{
                                                            core::ErrorCode::transport_io,
                                                            "legacy datagram send failed", error}));
            })};
    }

    io::AnySender<io::DatagramPacket> async_receive(boost::asio::mutable_buffer buffer) {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(io::DatagramPacket),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        if (receive_in_progress_) {
            return io::AnySender<io::DatagramPacket>{
                stdexec::just_error(std::make_exception_ptr(core::Error{
                    core::ErrorCode::transport_io, "legacy datagram receive in progress"}))};
        }
        auto self = shared_from_this();
        receive_in_progress_ = true;
        return io::AnySender<io::DatagramPacket>{async::callback_sender<Signatures>(
            [self, buffer](auto terminal) mutable -> async::CallbackAbortFn {
                // Single-pull receive loop as one task: keep pulling from the
                // socket (dropping off-server packets) until a decodable
                // datagram lands in the caller's buffer.
                ReceiveTerminal done{std::move(terminal)};
                self->scope_.spawn(run_receive(self, buffer, std::move(done)));
                return async::CallbackAbortFn{[self] { self->abort(); }};
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size,
               io::DatagramAddress source) {
                if (!error) {
                    stdexec::set_value(std::move(receiver),
                                       io::DatagramPacket{size, std::move(source)});
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(
                    std::move(receiver),
                    std::make_exception_ptr(core::Error{core::ErrorCode::transport_io,
                                                        "legacy datagram receive failed", error}));
            })};
    }

    // Abort for sender-driven cancellation: dispatched to the socket executor
    // because the parked flags are strand-private. Retires the parked op
    // without closing the transport; the in-flight socket op (if any)
    // completes aborted and the task drops its terminal at the retired guard
    // or the claimed callback_sender settlement.
    void abort() noexcept {
        try {
            auto self = shared_from_this();
            auto executor = socket_->executor();
            boost::asio::dispatch(std::move(executor), [self] {
                self->send_in_progress_ = false;
                self->receive_in_progress_ = false;
                self->socket_->cancel();
            });
        } catch (...) {
            // Aborter contract: never throw; the late task completion retires
            // against the guards instead.
        }
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
    static exec::task<void> run_send(std::shared_ptr<LegacyDatagramState> self,
                                     std::shared_ptr<std::vector<std::uint8_t>> packet,
                                     std::size_t plaintext_size, SendTerminal done) {
        try {
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = self->socket_->async_send_to(
                boost::asio::buffer(*packet), io::DatagramAddress::from_endpoint(self->server_));
            co_await std::move(sender);
        } catch (...) {
            // Stopped (via abort's socket cancel) included: the guard is
            // already retired, the terminal drops at the settlement, and the
            // task still ends with a value for the scope.
            self->send_in_progress_ = false;
            done(net::unpack_error(std::current_exception()), 0);
            co_return;
        }
        self->send_in_progress_ = false;
        done({}, plaintext_size);
    }

    static exec::task<void> run_receive(std::shared_ptr<LegacyDatagramState> self,
                                        boost::asio::mutable_buffer output, ReceiveTerminal done) {
        for (;;) {
            std::size_t size = 0;
            io::DatagramAddress sender;
            try {
                // NOTE: name the sender first; argument order is unspecified.
                auto receiver =
                    self->socket_->async_receive_from(boost::asio::buffer(self->receive_buffer_));
                auto raw = co_await std::move(receiver);
                size = raw.size;
                sender = std::move(raw.address);
            } catch (...) {
                self->receive_in_progress_ = false;
                done(net::unpack_error(std::current_exception()), 0, {});
                co_return;
            }
            if (!sender.is_address() || sender.address() != self->server_.address() ||
                sender.port() != self->server_.port()) {
                continue;
            }
            try {
                auto packet = self->decode_response(size, output);
                self->receive_in_progress_ = false;
                done({}, packet.size, std::move(packet.address));
            } catch (...) {
                self->receive_in_progress_ = false;
                done(net::unpack_error(std::current_exception()), 0, {});
            }
            co_return;
        }
    }

    io::DatagramPacket decode_response(std::size_t size, boost::asio::mutable_buffer output) {
        auto plaintext = transport::shadowsocks::decrypt_legacy_datagram(
            method_, password_, std::span<const std::uint8_t>(receive_buffer_.data(), size));
        if (!plaintext) {
            throw plaintext.error();
        }
        auto address = decode_proxy_address(plaintext.value());
        if (!address || address.value().size > plaintext.value().size()) {
            throw core::Error{core::ErrorCode::transport_io, "legacy datagram framing failed"};
        }
        const auto payload_offset = address.value().size;
        const auto payload_size = plaintext.value().size() - payload_offset;
        if (payload_size > output.size()) {
            throw core::Error{
                core::ErrorCode::transport_io, "legacy datagram truncated",
                std::error_code(boost::asio::error::message_size, std::system_category())};
        }
        if (payload_size != 0) {
            std::memcpy(output.data(), plaintext.value().data() + payload_offset, payload_size);
        }
        if (address.value().destination.is_address()) {
            return io::DatagramPacket{
                payload_size, io::DatagramAddress::address(address.value().destination.address(),
                                                           address.value().destination.port())};
        }
        return io::DatagramPacket{payload_size,
                                  io::DatagramAddress::domain(address.value().destination.domain(),
                                                              address.value().destination.port())};
    }

    std::shared_ptr<net::UdpStream> socket_;
    boost::asio::ip::udp::endpoint server_;
    std::string method_;
    std::string password_;
    std::array<std::uint8_t, kMaxUdpWireSize> receive_buffer_{};
    // Owns the single send/receive chain tasks, which always end with a value.
    exec::async_scope scope_;
    // Single-outstanding guards so concurrent callers fail fast instead of
    // interleaving on the shared codec buffer.
    bool receive_in_progress_ = false;
    bool send_in_progress_ = false;
};

class LegacyDatagramHandle final : public io::DatagramHandle {
  public:
    explicit LegacyDatagramHandle(std::shared_ptr<LegacyDatagramState> state)
        : state_(std::move(state)) {}

    io::AnySender<std::size_t> async_send_to(boost::asio::const_buffer buffer,
                                             io::DatagramAddress destination) override {
        return state_->async_send(buffer, std::move(destination));
    }

    io::AnySender<io::DatagramPacket>
    async_receive_from(boost::asio::mutable_buffer buffer) override {
        return state_->async_receive(buffer);
    }

    boost::asio::any_io_executor executor() noexcept override { return state_->executor(); }
    std::size_t max_datagram_size() const noexcept override { return state_->max_datagram_size(); }
    void cancel() noexcept override { state_->close(); }
    void close() noexcept override { state_->close(); }

  private:
    std::shared_ptr<LegacyDatagramState> state_;
};

} // namespace

core::Result<std::unique_ptr<io::DatagramHandle>>
make_legacy_shadowsocks_datagram_handle(std::shared_ptr<net::UdpStream> socket,
                                        boost::asio::ip::udp::endpoint server, std::string method,
                                        std::string password) {
    const auto spec = transport::proxy::cipher_method(method);
    if (!spec) {
        return core::fail(spec.error());
    }
    if (spec.value().kind != transport::proxy::CipherKind::stream) {
        return core::fail({core::ErrorCode::configuration,
                           "legacy Shadowsocks datagram handle requires a stream cipher"});
    }
    auto state = std::make_shared<LegacyDatagramState>(std::move(socket), std::move(server),
                                                       std::move(method), std::move(password));
    return std::unique_ptr<io::DatagramHandle>(
        std::make_unique<LegacyDatagramHandle>(std::move(state)));
}

} // namespace clash_native::outbound::detail
