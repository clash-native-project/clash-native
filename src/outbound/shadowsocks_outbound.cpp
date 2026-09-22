#include <clash_native/outbound/shadowsocks_outbound.hpp>

#include <clash_native/async/bridge.hpp>
#include <clash_native/async/callback_sender.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/net/udp_stream.hpp>
#include <clash_native/transport/shadowsocks/aead_packet.hpp>
#include <clash_native/transport/shadowsocks/crypto.hpp>
#include <clash_native/transport/shadowsocks/jls_client.hpp>
#include <clash_native/transport/shadowsocks/legacy_stream.hpp>
#include <clash_native/transport/shadowsocks/restls_client.hpp>
#include <clash_native/transport/shadowsocks/shadow_tls.hpp>
#include <clash_native/transport/shadowsocks/simple_obfs.hpp>
#include <clash_native/transport/shadowsocks/ss2022_packet.hpp>
#include <clash_native/transport/shadowsocks/ss2022_stream.hpp>
#include <clash_native/transport/shadowsocks/stream_carrier.hpp>
#include <clash_native/transport/shadowsocks/udp_over_tcp.hpp>
#include <clash_native/transport/shadowsocks/websocket_plugin.hpp>

#include "outbound_utils.hpp"
#include "proxy_address.hpp"
#include "shadowsocks_legacy_datagram.hpp"

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/errc.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::outbound {

namespace ss = clash_native::transport::shadowsocks;

namespace {

constexpr std::size_t kAeadTagSize = 16;
constexpr std::size_t kMaxChunkPayload = 0x3fff;
constexpr std::size_t kMaxUdpWireSize = 65507;
// Counts the Shadowsocks UDP payload (salt + ciphertext), not the IP or UDP headers.
constexpr std::size_t kMaxEncryptedUdpDatagramSize = 1500;
constexpr std::size_t kMaxProxyAddressSize = 1 + 1 + 255 + 2;
constexpr auto kConnectTimeout = std::chrono::seconds(15);
constexpr std::string_view kUdpOverTcpMagicAddress = "sp.udp-over-tcp.arpa";
constexpr std::string_view kUdpOverTcpV2MagicAddress = "sp.v2.udp-over-tcp.arpa";

boost::system::error_code protocol_error() {
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

boost::system::error_code authentication_error() {
    return boost::system::errc::make_error_code(boost::system::errc::permission_denied);
}

std::vector<std::uint8_t> append_tcp_record(std::string_view method,
                                            std::span<const std::uint8_t> key,
                                            std::vector<std::uint8_t> &nonce,
                                            std::span<const std::uint8_t> payload) {
    const auto payload_size = static_cast<std::uint16_t>(payload.size());
    const std::array<std::uint8_t, 2> length{static_cast<std::uint8_t>(payload_size >> 8),
                                             static_cast<std::uint8_t>(payload_size & 0xff)};
    auto encrypted_length = ss::aead_encrypt(method, key, nonce, length);
    ss::increment_nonce(nonce);
    auto encrypted_payload = ss::aead_encrypt(method, key, nonce, payload);
    ss::increment_nonce(nonce);
    if (!encrypted_length || !encrypted_payload) {
        return {};
    }
    std::vector<std::uint8_t> result;
    result.reserve(encrypted_length.value().size() + encrypted_payload.value().size());
    result.insert(result.end(), encrypted_length.value().begin(), encrypted_length.value().end());
    result.insert(result.end(), encrypted_payload.value().begin(), encrypted_payload.value().end());
    return result;
}

class ShadowsocksStreamHandle final : public io::StreamHandle {
  private:
    using ReadSignatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;
    using WriteSignatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                           stdexec::set_error_t(std::exception_ptr),
                                                           stdexec::set_stopped_t()>;

    struct State : std::enable_shared_from_this<State> {
        State(std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::string method,
              std::string password, std::vector<std::uint8_t> key,
              std::vector<std::uint8_t> write_nonce, std::vector<std::uint8_t> initial_wire = {},
              ss::ObfsMode obfs_mode = ss::ObfsMode::none)
            : socket(std::move(socket)), carrier(std::make_shared<ss::StreamCarrier>(this->socket)),
              method(std::move(method)), password(std::move(password)), key(std::move(key)),
              write_nonce(std::move(write_nonce)), initial_wire(std::move(initial_wire)),
              obfs_mode(obfs_mode), obfs_response_ready(obfs_mode == ss::ObfsMode::none) {
            if (const auto spec = ss::cipher_method(this->method)) {
                read_nonce.assign(spec.value().nonce_size, 0);
                encrypted_length.resize(2 + spec.value().overhead);
            }
        }

        State(std::shared_ptr<ss::StreamCarrier> carrier, std::string method, std::string password,
              std::vector<std::uint8_t> key, std::vector<std::uint8_t> write_nonce,
              std::vector<std::uint8_t> initial_wire = {})
            : socket(carrier ? carrier->socket() : nullptr), carrier(std::move(carrier)),
              method(std::move(method)), password(std::move(password)), key(std::move(key)),
              write_nonce(std::move(write_nonce)), initial_wire(std::move(initial_wire)) {
            if (const auto spec = ss::cipher_method(this->method)) {
                read_nonce.assign(spec.value().nonce_size, 0);
                encrypted_length.resize(2 + spec.value().overhead);
            }
        }

        void write(boost::asio::const_buffer buffer, core::StreamHandle::WriteHandler handler) {
            if (write_in_progress) {
                boost::asio::post(carrier->executor(), [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::already_started, 0);
                });
                return;
            }
            if (buffer.size() == 0) {
                boost::asio::post(carrier->executor(),
                                  [handler = std::move(handler)]() mutable { handler({}, 0); });
                return;
            }

            const auto *data = static_cast<const std::uint8_t *>(buffer.data());
            std::vector<std::uint8_t> encoded;
            const auto size = buffer.size();
            for (std::size_t offset = 0; offset < size;) {
                const auto chunk_size = std::min(kMaxChunkPayload, size - offset);
                auto chunk =
                    append_tcp_record(method, key, write_nonce,
                                      std::span<const std::uint8_t>(data + offset, chunk_size));
                if (chunk.empty()) {
                    boost::asio::post(
                        carrier->executor(),
                        [handler = std::move(handler)]() mutable { handler(protocol_error(), 0); });
                    return;
                }
                encoded.insert(encoded.end(), chunk.begin(), chunk.end());
                offset += chunk_size;
            }

            write_in_progress = true;
            auto self = shared_from_this();
            auto wire = std::make_shared<std::vector<std::uint8_t>>(std::move(encoded));
            if (obfs_mode == ss::ObfsMode::tls) {
                ss::async_write_tls_obfs_records(
                    socket, std::move(*wire),
                    [self, handler = std::move(handler), size](core::Status result) mutable {
                        self->write_in_progress = false;
                        handler(result ? boost::system::error_code() : protocol_error(),
                                result ? size : 0);
                    });
                return;
            }
            carrier->async_write(boost::asio::buffer(*wire),
                                 [self, wire, handler = std::move(handler), size](
                                     const boost::system::error_code &error, std::size_t) mutable {
                                     self->write_in_progress = false;
                                     handler(error, error ? 0 : size);
                                 });
        }

        void read(boost::asio::mutable_buffer buffer, core::StreamHandle::ReadHandler handler) {
            if (read_in_progress) {
                boost::asio::post(carrier->executor(), [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::already_started, 0);
                });
                return;
            }
            if (buffer.size() == 0) {
                boost::asio::post(carrier->executor(),
                                  [handler = std::move(handler)]() mutable { handler({}, 0); });
                return;
            }
            if (pending_offset < pending_plaintext.size()) {
                copy_pending(buffer, std::move(handler));
                return;
            }

            read_in_progress = true;
            read_buffer = buffer;
            read_handler = std::move(handler);
            if (!obfs_response_ready) {
                receive_obfs_response();
            } else if (!read_key_ready) {
                receive_salt();
            } else {
                receive_length();
            }
        }

        void close() noexcept { carrier->close(); }

        void receive_salt() {
            const auto method_info = ss::cipher_method(method);
            if (!method_info) {
                finish_read(protocol_error(), 0);
                return;
            }
            auto self = shared_from_this();
            receive_salt_buffer.resize(method_info.value().key_size);
            read_exact(boost::asio::buffer(receive_salt_buffer),
                       [self](const boost::system::error_code &error) {
                           if (error) {
                               self->finish_read(error, 0);
                               return;
                           }
                           auto key_result = ss::derive_aead_subkey(self->method, self->password,
                                                                    self->receive_salt_buffer);
                           if (!key_result) {
                               self->finish_read(authentication_error(), 0);
                               return;
                           }
                           self->read_key = std::move(key_result.value());
                           self->read_key_ready = true;
                           self->receive_length();
                       });
        }

        void receive_obfs_response() {
            auto self = shared_from_this();
            auto handler = [self](core::Result<std::vector<std::uint8_t>> result) {
                if (!result) {
                    self->finish_read(protocol_error(), 0);
                    return;
                }
                self->initial_wire = std::move(result.value());
                self->initial_wire_offset = 0;
                self->obfs_response_ready = true;
                self->receive_salt();
            };
            if (obfs_mode == ss::ObfsMode::http) {
                ss::async_read_http_obfs_response(socket, std::move(handler));
            } else {
                ss::async_read_tls_obfs_response(socket, std::move(handler));
            }
        }

        void receive_length() {
            auto self = shared_from_this();
            read_exact(
                boost::asio::buffer(encrypted_length),
                [self](const boost::system::error_code &error) {
                    if (error) {
                        self->finish_read(error, 0);
                        return;
                    }
                    const auto length = ss::aead_decrypt(self->method, self->read_key,
                                                         self->read_nonce, self->encrypted_length);
                    if (!length || length.value().size() != 2) {
                        self->finish_read(authentication_error(), 0);
                        return;
                    }
                    ss::increment_nonce(self->read_nonce);
                    const auto payload_size =
                        (static_cast<std::size_t>(length.value()[0]) << 8) | length.value()[1];
                    if (payload_size == 0 || payload_size > kMaxChunkPayload) {
                        self->finish_read(protocol_error(), 0);
                        return;
                    }
                    self->receive_payload(payload_size);
                });
        }

        void receive_payload(std::size_t payload_size) {
            auto self = shared_from_this();
            const auto method_info = ss::cipher_method(method);
            if (!method_info) {
                finish_read(protocol_error(), 0);
                return;
            }
            encrypted_payload.resize(payload_size + method_info.value().overhead);
            read_exact(boost::asio::buffer(encrypted_payload),
                       [self](const boost::system::error_code &error) {
                           if (error) {
                               self->finish_read(error, 0);
                               return;
                           }
                           auto plaintext =
                               ss::aead_decrypt(self->method, self->read_key, self->read_nonce,
                                                self->encrypted_payload);
                           if (!plaintext || plaintext.value().empty()) {
                               self->finish_read(authentication_error(), 0);
                               return;
                           }
                           ss::increment_nonce(self->read_nonce);
                           self->pending_plaintext = std::move(plaintext.value());
                           self->pending_offset = 0;
                           self->copy_pending(self->read_buffer, std::move(self->read_handler));
                       });
        }

        using ExactReadHandler = std::function<void(const boost::system::error_code &)>;

        void read_exact(boost::asio::mutable_buffer buffer, ExactReadHandler handler) {
            if (obfs_mode == ss::ObfsMode::tls) {
                read_exact_tls(buffer, std::move(handler), 0);
                return;
            }
            std::size_t copied = 0;
            if (initial_wire_offset < initial_wire.size()) {
                copied = std::min(buffer.size(), initial_wire.size() - initial_wire_offset);
                std::memcpy(static_cast<std::uint8_t *>(buffer.data()),
                            initial_wire.data() + initial_wire_offset, copied);
                initial_wire_offset += copied;
                if (initial_wire_offset == initial_wire.size()) {
                    initial_wire.clear();
                    initial_wire_offset = 0;
                }
            }
            if (copied == buffer.size()) {
                boost::asio::post(carrier->executor(),
                                  [handler = std::move(handler)]() mutable { handler({}); });
                return;
            }
            auto remaining = boost::asio::mutable_buffer(
                static_cast<std::uint8_t *>(buffer.data()) + copied, buffer.size() - copied);
            read_exact_carrier(remaining, std::move(handler));
        }

        void read_exact_tls(boost::asio::mutable_buffer buffer, ExactReadHandler handler,
                            std::size_t copied) {
            if (initial_wire_offset < initial_wire.size()) {
                const auto count =
                    std::min(buffer.size() - copied, initial_wire.size() - initial_wire_offset);
                std::memcpy(static_cast<std::uint8_t *>(buffer.data()) + copied,
                            initial_wire.data() + initial_wire_offset, count);
                initial_wire_offset += count;
                copied += count;
                if (initial_wire_offset == initial_wire.size()) {
                    initial_wire.clear();
                    initial_wire_offset = 0;
                }
            }
            if (copied == buffer.size()) {
                boost::asio::post(carrier->executor(),
                                  [handler = std::move(handler)]() mutable { handler({}); });
                return;
            }
            auto self = shared_from_this();
            ss::async_read_tls_obfs_record(
                socket, [self, buffer, handler = std::move(handler),
                         copied](core::Result<std::vector<std::uint8_t>> result) mutable {
                    if (!result) {
                        handler(protocol_error());
                        return;
                    }
                    self->initial_wire = std::move(result.value());
                    self->initial_wire_offset = 0;
                    self->read_exact_tls(buffer, std::move(handler), copied);
                });
        }

        void copy_pending(boost::asio::mutable_buffer buffer,
                          core::StreamHandle::ReadHandler handler) {
            const auto remaining = pending_plaintext.size() - pending_offset;
            const auto copied = std::min(buffer.size(), remaining);
            std::memcpy(buffer.data(), pending_plaintext.data() + pending_offset, copied);
            pending_offset += copied;
            if (pending_offset == pending_plaintext.size()) {
                pending_plaintext.clear();
                pending_offset = 0;
            }
            read_in_progress = false;
            handler({}, copied);
        }

        void read_exact_carrier(boost::asio::mutable_buffer buffer, ExactReadHandler handler) {
            auto callback = std::make_shared<ExactReadHandler>(std::move(handler));
            read_exact_carrier(buffer, std::move(callback));
        }

        void read_exact_carrier(boost::asio::mutable_buffer buffer,
                                std::shared_ptr<ExactReadHandler> callback) {
            auto self = shared_from_this();
            carrier->async_read_some(
                buffer, [self, buffer, callback = std::move(callback)](
                            const boost::system::error_code &error, std::size_t size) mutable {
                    auto &handler = *callback;
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
                    self->read_exact_carrier(remaining, callback);
                });
        }

        void finish_read(const boost::system::error_code &error, std::size_t size) {
            read_in_progress = false;
            auto handler = std::move(read_handler);
            if (handler) {
                handler(error, size);
            }
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> socket;
        std::shared_ptr<ss::StreamCarrier> carrier;
        std::string method;
        std::string password;
        std::vector<std::uint8_t> key;
        std::vector<std::uint8_t> write_nonce;
        std::vector<std::uint8_t> read_nonce;
        std::vector<std::uint8_t> receive_salt_buffer;
        std::vector<std::uint8_t> read_key;
        std::vector<std::uint8_t> encrypted_length = std::vector<std::uint8_t>(2 + kAeadTagSize);
        std::vector<std::uint8_t> encrypted_payload;
        std::vector<std::uint8_t> initial_wire;
        std::size_t initial_wire_offset = 0;
        std::vector<std::uint8_t> pending_plaintext;
        std::size_t pending_offset = 0;
        boost::asio::mutable_buffer read_buffer;
        core::StreamHandle::ReadHandler read_handler;
        bool read_key_ready = false;
        ss::ObfsMode obfs_mode = ss::ObfsMode::none;
        bool obfs_response_ready = true;
        bool read_in_progress = false;
        bool write_in_progress = false;
    };

  public:
    ~ShadowsocksStreamHandle() override = default;

    ShadowsocksStreamHandle(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                            std::string method, std::string password, std::vector<std::uint8_t> key,
                            std::vector<std::uint8_t> write_nonce,
                            std::vector<std::uint8_t> initial_wire = {},
                            ss::ObfsMode obfs_mode = ss::ObfsMode::none)
        : state_(std::make_shared<State>(std::move(socket), std::move(method), std::move(password),
                                         std::move(key), std::move(write_nonce),
                                         std::move(initial_wire), obfs_mode)) {}

    ShadowsocksStreamHandle(std::shared_ptr<ss::StreamCarrier> carrier, std::string method,
                            std::string password, std::vector<std::uint8_t> key,
                            std::vector<std::uint8_t> write_nonce,
                            std::vector<std::uint8_t> initial_wire = {})
        : state_(std::make_shared<State>(std::move(carrier), std::move(method), std::move(password),
                                         std::move(key), std::move(write_nonce),
                                         std::move(initial_wire))) {}

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
                if (!error) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>(count));
                } else if (error == boost::asio::error::eof) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>());
                } else {
                    stdexec::set_error(
                        std::move(receiver),
                        std::make_exception_ptr(
                            core::Error{core::ErrorCode::transport_io, "shadowsocks read",
                                        std::error_code(error.value(), std::system_category())}));
                }
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
                if (!error) {
                    stdexec::set_value(std::move(receiver), count);
                } else {
                    stdexec::set_error(
                        std::move(receiver),
                        std::make_exception_ptr(
                            core::Error{core::ErrorCode::transport_io, "shadowsocks write",
                                        std::error_code(error.value(), std::system_category())}));
                }
            })};
    }

    boost::asio::any_io_executor executor() noexcept override {
        return state_->carrier->executor();
    }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        return state_->carrier->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        state_->carrier->shutdown_send(error);
    }

    void close() noexcept override { state_->close(); }

  private:
    std::shared_ptr<State> state_;
};

class ShadowsocksConnectOperation final
    : public std::enable_shared_from_this<ShadowsocksConnectOperation> {
  public:
    ShadowsocksConnectOperation(runtime::AsioRuntime &runtime,
                                std::shared_ptr<dns::ResolverService> resolver,
                                std::shared_ptr<ss::KcptunClientPool> kcptun_pool,
                                std::shared_ptr<ss::WebSocketPluginMuxPool> websocket_mux_pool,
                                ShadowsocksOutboundConfig config, core::StreamRequest request,
                                core::StreamOpenHandler handler)
        : runtime_(runtime), resolver_(std::move(resolver)), config_(std::move(config)),
          kcptun_pool_(std::move(kcptun_pool)), websocket_mux_pool_(std::move(websocket_mux_pool)),
          request_(std::move(request)),
          socket_(std::make_shared<boost::asio::ip::tcp::socket>(runtime.serialized_executor())),
          timer_(runtime.serialized_executor()), handler_(std::move(handler)) {}

    void start() {
        const auto validation = validate_config();
        if (!validation) {
            finish(core::StreamOpenResult::failed(validation.error()));
            return;
        }
        timer_.expires_after(kConnectTimeout);
        timer_.async_wait([self = shared_from_this()](const boost::system::error_code &error) {
            if (!error) {
                if (self->resolver_ && self->resolver_request_id_) {
                    self->resolver_->cancel(*self->resolver_request_id_);
                    self->resolver_request_id_.reset();
                }
                boost::system::error_code ignored;
                if (self->carrier_) {
                    self->carrier_->close();
                } else {
                    self->socket_->cancel(ignored);
                }
                self->finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::timeout, "timed out opening Shadowsocks TCP stream"}));
            }
        });
        detail::resolve_host(runtime_, resolver_, config_.server_host,
                             [self = shared_from_this()](core::Result<detail::AddressList> result) {
                                 self->resolved(std::move(result));
                             });
    }

  private:
    core::Status validate_config() const {
        if (config_.id.empty() || config_.server_host.empty() || config_.server_port == 0 ||
            config_.password.empty()) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks outbound ID, server, port, and password are required"});
        }
        const auto method = ss::cipher_method(config_.method);
        if (!method) {
            return core::fail(method.error());
        }
        if (!config_.plugin.empty() && config_.plugin != "obfs" &&
            config_.plugin != "v2ray-plugin" && config_.plugin != "gost-plugin" &&
            config_.plugin != "kcptun" && config_.plugin != "shadow-tls" &&
            config_.plugin != "restls" && config_.plugin != "jls") {
            return core::fail({core::ErrorCode::unsupported, "unsupported Shadowsocks plugin", {}});
        }
        if (config_.plugin == "obfs" && config_.plugin_mode != "http" &&
            config_.plugin_mode != "tls") {
            return core::fail({core::ErrorCode::unsupported,
                               "only Shadowsocks simple-obfs http and tls modes are supported",
                               {}});
        }
        if ((config_.plugin == "v2ray-plugin" || config_.plugin == "gost-plugin") &&
            config_.plugin_mode != "websocket") {
            return core::fail({core::ErrorCode::unsupported,
                               "Shadowsocks WebSocket plugins require websocket mode",
                               {}});
        }
        if (config_.plugin == "kcptun" &&
            (config_.plugin_mode != "" || config_.plugin_tls || config_.plugin_skip_cert_verify)) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks kcptun does not use WebSocket plugin options",
                               {}});
        }
        if (config_.plugin == "shadow-tls") {
            if (!config_.plugin_mode.empty() || !config_.plugin_path.empty() ||
                config_.plugin_tls) {
                return core::fail({core::ErrorCode::configuration,
                                   "Shadowsocks Shadow-TLS does not use WebSocket plugin options",
                                   {}});
            }
            if (config_.plugin_version < 1 || config_.plugin_version > 3) {
                return core::fail({core::ErrorCode::configuration,
                                   "Shadowsocks Shadow-TLS version must be 1, 2, or 3",
                                   {}});
            }
            if (config_.plugin_version >= 2 && config_.plugin_password.empty()) {
                return core::fail({core::ErrorCode::configuration,
                                   "Shadowsocks Shadow-TLS v2 and v3 require a plugin password",
                                   {}});
            }
            if (config_.plugin_host.empty()) {
                return core::fail({core::ErrorCode::configuration,
                                   "Shadowsocks Shadow-TLS host is required",
                                   {}});
            }
        }
        if (config_.plugin == "restls") {
            if (!config_.plugin_mode.empty() || !config_.plugin_path.empty() ||
                config_.plugin_tls || config_.plugin_version_hint.empty()) {
                return core::fail({core::ErrorCode::configuration,
                                   "Shadowsocks ResTLS does not use WebSocket plugin options",
                                   {}});
            }
            if (config_.plugin_version_hint != "tls12" && config_.plugin_version_hint != "tls13") {
                return core::fail({core::ErrorCode::configuration,
                                   "Shadowsocks ResTLS version hint must be tls12 or tls13",
                                   {}});
            }
            if (config_.plugin_password.empty() || config_.plugin_host.empty()) {
                return core::fail({core::ErrorCode::configuration,
                                   "Shadowsocks ResTLS host and password are required",
                                   {}});
            }
        }
        if (config_.plugin_mux && !websocket_plugin()) {
            return core::fail({core::ErrorCode::unsupported,
                               "Shadowsocks plugin mux requires v2ray-plugin or gost-plugin",
                               {}});
        }
        if (config_.plugin_mux && config_.plugin_smux_version != 1 &&
            config_.plugin_smux_version != 2) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks WebSocket smux version must be 1 or 2",
                               {}});
        }
        if (config_.plugin == "v2ray-plugin" && config_.plugin_mux &&
            config_.plugin_smux_version != 1) {
            return core::fail({core::ErrorCode::unsupported,
                               "v2ray-plugin does not use smux version selection",
                               {}});
        }
        if (config_.plugin == "jls") {
            if (!config_.plugin_mode.empty() || !config_.plugin_path.empty() ||
                config_.plugin_tls) {
                return core::fail(
                    {core::ErrorCode::configuration,
                     "Shadowsocks JLS requires the TLS 1.3 carrier without WebSocket options",
                     {}});
            }
            if (config_.plugin_username.empty() || config_.plugin_password.empty() ||
                config_.plugin_host.empty()) {
                return core::fail({core::ErrorCode::configuration,
                                   "Shadowsocks JLS host, username, and password are required",
                                   {}});
            }
        }
        if (config_.udp_over_tcp_version != 1 && config_.udp_over_tcp_version != 2) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks UDP-over-TCP version must be 1 or 2",
                               {}});
        }
        if (!config_.plugin_path.empty() && config_.plugin_path.front() != '/') {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks WebSocket plugin path must start with '/'",
                               {}});
        }
        if (config_.plugin_host.find_first_of("\r\n") != std::string::npos) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks plugin host contains invalid characters",
                               {}});
        }
        return {};
    }

    std::optional<ss::ObfsClientOptions> obfs_options() const {
        if (config_.plugin != "obfs") {
            return std::nullopt;
        }
        return ss::ObfsClientOptions{
            config_.plugin_mode == "tls" ? ss::ObfsMode::tls : ss::ObfsMode::http,
            config_.plugin_host.empty() ? "bing.com" : config_.plugin_host, config_.server_port};
    }

    bool websocket_plugin() const noexcept {
        return config_.plugin == "v2ray-plugin" || config_.plugin == "gost-plugin";
    }

    bool kcptun_plugin() const noexcept { return config_.plugin == "kcptun"; }

    bool shadow_tls_plugin() const noexcept { return config_.plugin == "shadow-tls"; }

    bool restls_plugin() const noexcept { return config_.plugin == "restls"; }

    bool jls_plugin() const noexcept { return config_.plugin == "jls"; }

    ss::WebSocketPluginOptions websocket_options() const {
        ss::WebSocketPluginOptions options;
        options.host = config_.plugin_host.empty() ? "bing.com" : config_.plugin_host;
        options.path = config_.plugin_path.empty() ? "/" : config_.plugin_path;
        options.tls = config_.plugin_tls;
        options.skip_cert_verify = config_.plugin_skip_cert_verify;
        options.mux = config_.plugin_mux;
        options.mux_protocol = config_.plugin == "gost-plugin" ? ss::WebSocketMuxProtocol::smux
                                                               : ss::WebSocketMuxProtocol::v2ray;
        options.smux_version = config_.plugin_smux_version;
        return options;
    }

    void resolved(core::Result<detail::AddressList> result) {
        if (completed_) {
            return;
        }
        if (!result) {
            finish(core::StreamOpenResult::failed(result.error()));
            return;
        }
        if (kcptun_plugin()) {
            if (result.value().empty()) {
                finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::resolution,
                     "Shadowsocks kcptun server hostname resolved to no addresses",
                     {}}));
                return;
            }
            const auto endpoint =
                boost::asio::ip::udp::endpoint(result.value().front(), config_.server_port);
            if (!kcptun_pool_) {
                auto options = config_.kcptun.value_or(ss::KcptunClientOptions{});
                auto stream = ss::make_kcptun_client_stream(runtime_, endpoint, std::move(options));
                if (!stream) {
                    finish(core::StreamOpenResult::failed(stream.error()));
                    return;
                }
                carrier_ = std::make_shared<ss::StreamCarrier>(std::move(stream.value()));
                send_initial_request();
                return;
            }
            auto self = shared_from_this();
            kcptun_pool_->async_open_stream(
                endpoint, [self](core::StreamOpenResult stream) mutable {
                    if (!stream.succeeded()) {
                        self->finish(std::move(stream));
                        return;
                    }
                    self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(stream.handle));
                    self->send_initial_request();
                });
            return;
        }
        auto endpoints = std::make_shared<std::vector<boost::asio::ip::tcp::endpoint>>();
        endpoints->reserve(result.value().size());
        for (const auto &address : result.value()) {
            endpoints->emplace_back(address, config_.server_port);
        }
        auto self = shared_from_this();
        if (websocket_plugin() && config_.plugin_mux) {
            if (!websocket_mux_pool_) {
                finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::configuration,
                     "Shadowsocks WebSocket mux pool is not initialized",
                     {}}));
                return;
            }
            websocket_mux_pool_->async_open_stream(
                std::move(*endpoints), websocket_options(),
                [self](core::Result<std::unique_ptr<core::StreamHandle>> stream) mutable {
                    if (!stream) {
                        self->finish(core::StreamOpenResult::failed(stream.error()));
                        return;
                    }
                    self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(stream.value()));
                    self->send_initial_request();
                });
            return;
        }
        boost::asio::async_connect(
            *socket_, *endpoints,
            [self, endpoints](const boost::system::error_code &error,
                              const boost::asio::ip::tcp::endpoint &) {
                if (error) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::endpoint_connection,
                         "failed to connect to Shadowsocks server", detail::to_std_error(error)}));
                    return;
                }
                if (self->shadow_tls_plugin()) {
                    self->open_shadow_tls();
                    return;
                }
                if (self->restls_plugin()) {
                    self->open_restls();
                    return;
                }
                if (self->jls_plugin()) {
                    self->open_jls();
                    return;
                }
                self->send_initial_request();
            });
    }

    void open_shadow_tls() {
        auto self = shared_from_this();
        auto stream = std::make_unique<net::TcpStream>(std::move(*socket_));
        ss::ShadowTlsClientOptions options;
        options.version = config_.plugin_version;
        options.password = config_.plugin_password;
        options.host = config_.plugin_host;
        options.skip_cert_verify = config_.plugin_skip_cert_verify;
        if (!config_.plugin_alpn.empty()) {
            options.alpn_protocols = config_.plugin_alpn;
        }
        ss::async_open_shadow_tls(
            std::move(stream), std::move(options),
            [self](core::Result<std::unique_ptr<io::StreamHandle>> result) mutable {
                if (!result) {
                    self->finish(core::StreamOpenResult::failed(result.error()));
                    return;
                }
                self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(result.value()));
                self->send_initial_request();
            });
    }

    void open_restls() {
        auto self = shared_from_this();
        auto stream = std::make_unique<net::TcpStream>(std::move(*socket_));
        ss::RestlsClientOptions options;
        options.server_name = config_.plugin_host;
        options.password = config_.plugin_password;
        options.version_hint = config_.plugin_version_hint;
        options.restls_script = config_.plugin_restls_script;
        options.skip_cert_verify = config_.plugin_skip_cert_verify;
        ss::async_open_restls(
            std::move(stream), std::move(options),
            [self](core::Result<std::unique_ptr<io::StreamHandle>> result) mutable {
                if (!result) {
                    self->finish(core::StreamOpenResult::failed(result.error()));
                    return;
                }
                self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(result.value()));
                self->send_initial_request();
            });
    }

    void open_jls() {
        auto self = shared_from_this();
        auto stream = std::make_unique<net::TcpStream>(std::move(*socket_));
        ss::JlsClientOptions options;
        options.server_name = config_.plugin_host;
        options.username = config_.plugin_username;
        options.password = config_.plugin_password;
        options.alpn = config_.plugin_alpn;
        options.skip_cert_verify = config_.plugin_skip_cert_verify;
        ss::async_open_jls(std::move(stream), std::move(options),
                           [self](core::Result<std::unique_ptr<io::StreamHandle>> result) mutable {
                               if (!result) {
                                   self->finish(core::StreamOpenResult::failed(result.error()));
                                   return;
                               }
                               self->carrier_ =
                                   std::make_shared<ss::StreamCarrier>(std::move(result.value()));
                               self->send_initial_request();
                           });
    }

    void send_initial_request() {
        const auto method = ss::cipher_method(config_.method);
        if (method.value().shadowsocks_2022) {
            auto address = detail::encode_proxy_address(request_.destination);
            if (!address) {
                finish(core::StreamOpenResult::failed(address.error()));
                return;
            }
            if (websocket_plugin() && !config_.plugin_mux) {
                open_websocket_2022(std::move(address.value()));
                return;
            }
            auto self = shared_from_this();
            if (self->carrier_) {
                ss::async_open_shadowsocks_2022_stream(
                    runtime_, self->carrier_, self->config_.method, self->config_.password,
                    std::move(address.value()),
                    [self](core::StreamOpenResult result) { self->finish(std::move(result)); });
            } else {
                ss::async_open_shadowsocks_2022_stream(
                    runtime_, self->socket_, self->config_.method, self->config_.password,
                    std::move(address.value()), self->obfs_options(),
                    [self](core::StreamOpenResult result) { self->finish(std::move(result)); });
            }
            return;
        }
        if (method.value().kind == ss::CipherKind::stream) {
            send_legacy_initial_request(method.value());
            return;
        }
        std::vector<std::uint8_t> salt(method.value().key_size);
        if (!ss::random_bytes(salt)) {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::authentication, "failed to generate Shadowsocks salt"}));
            return;
        }
        auto key = ss::derive_aead_subkey(config_.method, config_.password, salt);
        auto address = detail::encode_proxy_address(request_.destination);
        if (!key || !address) {
            finish(core::StreamOpenResult::failed(!key ? key.error() : address.error()));
            return;
        }
        write_nonce_.assign(method.value().nonce_size, 0);
        auto record = append_tcp_record(config_.method, key.value(), write_nonce_, address.value());
        if (record.empty()) {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::authentication, "failed to encrypt Shadowsocks destination"}));
            return;
        }
        salt.insert(salt.end(), record.begin(), record.end());
        auto wire = std::make_shared<std::vector<std::uint8_t>>(std::move(salt));
        auto self = shared_from_this();
        if (websocket_plugin() && !config_.plugin_mux) {
            open_websocket_classic(std::move(*wire), std::move(key.value()));
            return;
        }
        if (const auto obfs = obfs_options(); obfs) {
            auto handler = [self, key = std::move(key.value()),
                            mode = obfs->mode](core::Status result) mutable {
                if (!result) {
                    self->finish(core::StreamOpenResult::failed(result.error()));
                    return;
                }
                auto handler = std::move(self->handler_);
                self->cancel_timer();
                self->completed_ = true;
                handler(core::StreamOpenResult::opened(std::make_unique<ShadowsocksStreamHandle>(
                    self->socket_, self->config_.method, self->config_.password, std::move(key),
                    self->write_nonce_, std::vector<std::uint8_t>{}, mode)));
            };
            if (obfs->mode == ss::ObfsMode::http) {
                ss::async_write_http_obfs_request(socket_, std::move(*wire),
                                                  {obfs->host, obfs->port}, std::move(handler));
            } else {
                ss::async_write_tls_obfs_request(socket_, std::move(*wire), obfs->host,
                                                 std::move(handler));
            }
            return;
        }
        auto write_handler = [self, wire, key = std::move(key.value())](
                                 const boost::system::error_code &error, std::size_t) mutable {
            if (error) {
                self->finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "failed to write Shadowsocks TCP request",
                     detail::to_std_error(error)}));
                return;
            }
            auto handler = std::move(self->handler_);
            self->cancel_timer();
            self->completed_ = true;
            if (self->carrier_) {
                handler(core::StreamOpenResult::opened(std::make_unique<ShadowsocksStreamHandle>(
                    self->carrier_, self->config_.method, self->config_.password, std::move(key),
                    self->write_nonce_)));
            } else {
                handler(core::StreamOpenResult::opened(std::make_unique<ShadowsocksStreamHandle>(
                    self->socket_, self->config_.method, self->config_.password, std::move(key),
                    self->write_nonce_)));
            }
        };
        if (carrier_) {
            carrier_->async_write(boost::asio::buffer(*wire), std::move(write_handler));
        } else {
            boost::asio::async_write(*socket_, boost::asio::buffer(*wire),
                                     std::move(write_handler));
        }
    }

    void open_websocket_classic(std::vector<std::uint8_t> wire, std::vector<std::uint8_t> key) {
        auto self = shared_from_this();
        auto stream = std::make_unique<net::TcpStream>(std::move(*socket_));
        ss::async_open_websocket_plugin(
            std::move(stream), websocket_options(),
            [self, wire = std::make_shared<std::vector<std::uint8_t>>(std::move(wire)),
             key = std::move(key)](core::Result<std::unique_ptr<io::StreamHandle>> result) mutable {
                if (!result) {
                    self->finish(core::StreamOpenResult::failed(result.error()));
                    return;
                }
                self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(result.value()));
                self->carrier_->async_write(
                    boost::asio::buffer(*wire),
                    [self, wire, key = std::move(key)](const boost::system::error_code &error,
                                                       std::size_t) mutable {
                        if (error) {
                            self->finish(core::StreamOpenResult::failed(
                                {core::ErrorCode::transport_io,
                                 "failed to write Shadowsocks WebSocket request",
                                 detail::to_std_error(error)}));
                            return;
                        }
                        auto handler = std::move(self->handler_);
                        self->cancel_timer();
                        self->completed_ = true;
                        handler(core::StreamOpenResult::opened(
                            std::make_unique<ShadowsocksStreamHandle>(
                                self->carrier_, self->config_.method, self->config_.password,
                                std::move(key), self->write_nonce_)));
                    });
            });
    }

    void open_websocket_2022(std::vector<std::uint8_t> destination) {
        auto self = shared_from_this();
        auto stream = std::make_unique<net::TcpStream>(std::move(*socket_));
        ss::async_open_websocket_plugin(
            std::move(stream), websocket_options(),
            [self, destination = std::move(destination)](
                core::Result<std::unique_ptr<io::StreamHandle>> result) mutable {
                if (!result) {
                    self->finish(core::StreamOpenResult::failed(result.error()));
                    return;
                }
                self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(result.value()));
                ss::async_open_shadowsocks_2022_stream(
                    self->runtime_, self->carrier_, self->config_.method, self->config_.password,
                    std::move(destination),
                    [self](core::StreamOpenResult opened) { self->finish(std::move(opened)); });
            });
    }

    void send_legacy_initial_request(const ss::CipherMethod &method) {
        std::vector<std::uint8_t> iv(method.iv_size);
        if (!ss::random_bytes(iv)) {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::authentication, "failed to generate Shadowsocks legacy IV"}));
            return;
        }
        auto key = ss::derive_legacy_key(config_.method, config_.password, iv);
        auto address = detail::encode_proxy_address(request_.destination);
        if (!key || !address) {
            finish(core::StreamOpenResult::failed(!key ? key.error() : address.error()));
            return;
        }
        auto cipher = ss::LegacyStreamCipher::create(config_.method, key.value(), iv, true);
        if (!cipher) {
            finish(core::StreamOpenResult::failed(cipher.error()));
            return;
        }
        auto encrypted_address = std::move(address.value());
        if (const auto result = cipher.value().update(encrypted_address); !result) {
            finish(core::StreamOpenResult::failed(result.error()));
            return;
        }
        iv.insert(iv.end(), encrypted_address.begin(), encrypted_address.end());
        auto wire = std::make_shared<std::vector<std::uint8_t>>(std::move(iv));
        auto self = shared_from_this();
        if (websocket_plugin() && !config_.plugin_mux) {
            open_websocket_legacy(std::move(*wire), std::move(cipher.value()));
            return;
        }
        if (const auto obfs = obfs_options(); obfs) {
            auto write_cipher = std::make_shared<ss::LegacyStreamCipher>(std::move(cipher.value()));
            auto handler = [self, write_cipher, mode = obfs->mode](core::Status result) mutable {
                if (!result) {
                    self->finish(core::StreamOpenResult::failed(result.error()));
                    return;
                }
                auto handler = std::move(self->handler_);
                self->cancel_timer();
                self->completed_ = true;
                auto stream = ss::make_legacy_stream_handle(self->socket_, self->config_.method,
                                                            self->config_.password,
                                                            std::move(*write_cipher), {}, mode);
                if (!stream) {
                    handler(core::StreamOpenResult::failed(stream.error()));
                    return;
                }
                handler(core::StreamOpenResult::opened(std::move(stream.value())));
            };
            if (obfs->mode == ss::ObfsMode::http) {
                ss::async_write_http_obfs_request(socket_, std::move(*wire),
                                                  {obfs->host, obfs->port}, std::move(handler));
            } else {
                ss::async_write_tls_obfs_request(socket_, std::move(*wire), obfs->host,
                                                 std::move(handler));
            }
            return;
        }
        auto write_cipher = std::make_shared<ss::LegacyStreamCipher>(std::move(cipher.value()));
        auto write_handler = [self, wire, write_cipher](const boost::system::error_code &error,
                                                        std::size_t) mutable {
            if (error) {
                self->finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "failed to write Shadowsocks legacy request",
                     detail::to_std_error(error)}));
                return;
            }
            auto handler = std::move(self->handler_);
            self->cancel_timer();
            self->completed_ = true;
            auto stream = self->carrier_
                              ? ss::make_legacy_stream_handle(self->carrier_, self->config_.method,
                                                              self->config_.password,
                                                              std::move(*write_cipher))
                              : ss::make_legacy_stream_handle(self->socket_, self->config_.method,
                                                              self->config_.password,
                                                              std::move(*write_cipher));
            if (!stream) {
                handler(core::StreamOpenResult::failed(stream.error()));
                return;
            }
            handler(core::StreamOpenResult::opened(std::move(stream.value())));
        };
        if (carrier_) {
            carrier_->async_write(boost::asio::buffer(*wire), std::move(write_handler));
        } else {
            boost::asio::async_write(*socket_, boost::asio::buffer(*wire),
                                     std::move(write_handler));
        }
    }

    void open_websocket_legacy(std::vector<std::uint8_t> wire,
                               ss::LegacyStreamCipher write_cipher) {
        auto self = shared_from_this();
        auto cipher = std::make_shared<ss::LegacyStreamCipher>(std::move(write_cipher));
        auto stream = std::make_unique<net::TcpStream>(std::move(*socket_));
        ss::async_open_websocket_plugin(
            std::move(stream), websocket_options(),
            [self, wire = std::make_shared<std::vector<std::uint8_t>>(std::move(wire)),
             cipher = std::move(cipher)](
                core::Result<std::unique_ptr<io::StreamHandle>> result) mutable {
                if (!result) {
                    self->finish(core::StreamOpenResult::failed(result.error()));
                    return;
                }
                self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(result.value()));
                self->carrier_->async_write(
                    boost::asio::buffer(*wire),
                    [self, wire, cipher](const boost::system::error_code &error,
                                         std::size_t) mutable {
                        if (error) {
                            self->finish(core::StreamOpenResult::failed(
                                {core::ErrorCode::transport_io,
                                 "failed to write Shadowsocks WebSocket request",
                                 detail::to_std_error(error)}));
                            return;
                        }
                        auto handler = std::move(self->handler_);
                        self->cancel_timer();
                        self->completed_ = true;
                        auto stream = ss::make_legacy_stream_handle(
                            self->carrier_, self->config_.method, self->config_.password,
                            std::move(*cipher));
                        if (!stream) {
                            handler(core::StreamOpenResult::failed(stream.error()));
                            return;
                        }
                        handler(core::StreamOpenResult::opened(std::move(stream.value())));
                    });
            });
    }

    void cancel_timer() noexcept { timer_.cancel(); }

  public:
    // Abort for sender-driven cancellation: posted to the strand so it stays
    // ordered with finish(). The bridge drops the late terminal.
    void abort() noexcept {
        auto self = shared_from_this();
        try {
            boost::asio::post(socket_->get_executor(), [self]() {
                if (self->completed_) {
                    return;
                }
                boost::system::error_code ignored;
                self->cancel_timer();
                if (self->resolver_ && self->resolver_request_id_) {
                    self->resolver_->cancel(*self->resolver_request_id_);
                    self->resolver_request_id_.reset();
                }
                self->socket_->close(ignored);
                if (self->carrier_) {
                    self->carrier_->close();
                }
            });
        } catch (...) {
        }
    }

  private:
    void finish(core::StreamOpenResult result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        cancel_timer();
        if (resolver_ && resolver_request_id_) {
            resolver_->cancel(*resolver_request_id_);
            resolver_request_id_.reset();
        }
        if (!result.succeeded()) {
            boost::system::error_code ignored;
            socket_->close(ignored);
            if (carrier_) {
                carrier_->close();
            }
        }
        auto handler = std::move(handler_);
        handler(std::move(result));
    }

    runtime::AsioRuntime &runtime_;
    std::shared_ptr<dns::ResolverService> resolver_;
    std::shared_ptr<ss::KcptunClientPool> kcptun_pool_;
    std::shared_ptr<ss::WebSocketPluginMuxPool> websocket_mux_pool_;
    ShadowsocksOutboundConfig config_;
    core::StreamRequest request_;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::shared_ptr<ss::StreamCarrier> carrier_;
    boost::asio::steady_timer timer_;
    core::StreamOpenHandler handler_;
    std::vector<std::uint8_t> write_nonce_;
    std::optional<dns::ResolverService::RequestId> resolver_request_id_;
    bool completed_ = false;
};

class ShadowsocksDatagramHandle final : public core::DatagramHandle {
  public:
    struct State : std::enable_shared_from_this<State> {
        State(std::shared_ptr<net::UdpStream> socket, boost::asio::ip::udp::endpoint server,
              std::string method, std::string password)
            : socket(std::move(socket)), server(std::move(server)), method(std::move(method)),
              password(std::move(password)) {
            const auto method_info = ss::cipher_method(this->method);
            if (method_info && method_info.value().shadowsocks_2022) {
                ss2022_codec = std::make_unique<ss::Shadowsocks2022DatagramCodec>(this->method,
                                                                                  this->password);
            }
        }

        void send(boost::asio::const_buffer buffer, core::DatagramAddress destination,
                  WriteHandler handler) {
            const auto target = destination.to_destination();
            auto address = detail::encode_proxy_address(target);
            const auto method_info = ss::cipher_method(method);
            if (!address || !method_info) {
                boost::asio::post(socket->executor(), [handler = std::move(handler)]() mutable {
                    handler(protocol_error(), 0);
                });
                return;
            }
            const auto payload_size = buffer.size();
            const auto *payload = static_cast<const std::uint8_t *>(buffer.data());
            if (ss2022_codec) {
                auto wire = ss2022_codec->encrypt(
                    address.value(), std::span<const std::uint8_t>(payload, payload_size));
                if (!wire || wire.value().size() > kMaxEncryptedUdpDatagramSize) {
                    boost::asio::post(socket->executor(), [handler = std::move(handler)]() mutable {
                        handler(boost::asio::error::message_size, 0);
                    });
                    return;
                }
                auto packet = std::make_shared<std::vector<std::uint8_t>>(std::move(wire.value()));
                auto self = shared_from_this();
                socket->async_send_to(
                    boost::asio::buffer(*packet), core::DatagramAddress::from_endpoint(server),
                    [self, packet, handler = std::move(handler),
                     payload_size](const boost::system::error_code &error, std::size_t) mutable {
                        handler(error, error ? 0 : payload_size);
                    });
                return;
            }
            std::vector<std::uint8_t> plaintext = std::move(address.value());
            plaintext.insert(plaintext.end(), payload, payload + payload_size);
            auto encoded = ss::encrypt_aead_datagram(method, password, plaintext);
            if (!encoded || encoded.value().size() > kMaxEncryptedUdpDatagramSize) {
                boost::asio::post(socket->executor(), [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::message_size, 0);
                });
                return;
            }
            auto wire = std::make_shared<std::vector<std::uint8_t>>(std::move(encoded.value()));
            auto self = shared_from_this();
            socket->async_send_to(boost::asio::buffer(*wire),
                                  core::DatagramAddress::from_endpoint(server),
                                  [self, wire, handler = std::move(handler), payload_size](
                                      const boost::system::error_code &error, std::size_t) mutable {
                                      handler(error, error ? 0 : payload_size);
                                  });
        }

        void receive(boost::asio::mutable_buffer buffer, ReadHandler handler) {
            if (receive_in_progress) {
                boost::asio::post(socket->executor(), [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::already_started, 0, {});
                });
                return;
            }
            receive_in_progress = true;
            output_buffer = buffer;
            receive_handler = std::move(handler);
            auto self = shared_from_this();
            socket->async_receive_from(boost::asio::buffer(receive_buffer),
                                       [self](const boost::system::error_code &error,
                                              std::size_t size, core::DatagramAddress sender) {
                                           if (error) {
                                               self->finish_receive(error, 0, {});
                                               return;
                                           }
                                           if (!sender.is_address() ||
                                               sender.address() != self->server.address() ||
                                               sender.port() != self->server.port()) {
                                               self->receive_next();
                                               return;
                                           }
                                           self->decode_response(size);
                                       });
        }

        void receive_next() {
            auto self = shared_from_this();
            socket->async_receive_from(boost::asio::buffer(receive_buffer),
                                       [self](const boost::system::error_code &error,
                                              std::size_t size, core::DatagramAddress sender) {
                                           if (error) {
                                               self->finish_receive(error, 0, {});
                                               return;
                                           }
                                           if (!sender.is_address() ||
                                               sender.address() != self->server.address() ||
                                               sender.port() != self->server.port()) {
                                               self->receive_next();
                                               return;
                                           }
                                           self->decode_response(size);
                                       });
        }

        void decode_response(std::size_t size) {
            if (ss2022_codec) {
                auto plaintext = ss2022_codec->decrypt(
                    std::span<const std::uint8_t>(receive_buffer.data(), size));
                if (!plaintext) {
                    finish_receive(authentication_error(), 0, {});
                    return;
                }
                decode_plaintext(std::move(plaintext.value()));
                return;
            }
            auto plaintext = ss::decrypt_aead_datagram(
                method, password, std::span<const std::uint8_t>(receive_buffer.data(), size));
            if (!plaintext) {
                finish_receive(authentication_error(), 0, {});
                return;
            }
            decode_plaintext(std::move(plaintext.value()));
        }

        void decode_plaintext(std::vector<std::uint8_t> plaintext) {
            auto address = detail::decode_proxy_address(plaintext);
            if (!address) {
                finish_receive(protocol_error(), 0, {});
                return;
            }
            const auto payload_offset = address.value().size;
            const auto payload_size = plaintext.size() - payload_offset;
            if (address.value().destination.is_address()) {
                complete_payload(
                    plaintext, payload_offset, payload_size,
                    core::DatagramAddress::address(address.value().destination.address(),
                                                   address.value().destination.port()));
                return;
            }
            complete_payload(plaintext, payload_offset, payload_size,
                             core::DatagramAddress::domain(address.value().destination.domain(),
                                                           address.value().destination.port()));
        }

        void complete_payload(const std::vector<std::uint8_t> &plaintext, std::size_t offset,
                              std::size_t size, core::DatagramAddress sender) {
            if (size > output_buffer.size()) {
                finish_receive(boost::asio::error::message_size, 0, {});
                return;
            }
            if (size != 0) {
                std::memcpy(output_buffer.data(), plaintext.data() + offset, size);
            }
            finish_receive({}, size, std::move(sender));
        }

        void finish_receive(const boost::system::error_code &error, std::size_t size,
                            core::DatagramAddress sender) {
            receive_in_progress = false;
            auto handler = std::move(receive_handler);
            if (handler) {
                handler(error, size, std::move(sender));
            }
        }

        void close() noexcept { socket->close(); }

        std::size_t max_datagram_size() const noexcept {
            if (ss2022_codec) {
                return std::min<std::size_t>(
                    ss2022_codec->max_datagram_size(kMaxEncryptedUdpDatagramSize,
                                                    kMaxProxyAddressSize),
                    kMaxUdpWireSize);
            }
            const auto spec = ss::cipher_method(method);
            if (!spec) {
                return 0;
            }
            return std::min<std::size_t>(
                ss::aead_datagram_payload_limit(method, kMaxEncryptedUdpDatagramSize,
                                                kMaxProxyAddressSize),
                kMaxUdpWireSize);
        }

        std::shared_ptr<net::UdpStream> socket;
        boost::asio::ip::udp::endpoint server;
        std::string method;
        std::string password;
        std::unique_ptr<ss::Shadowsocks2022DatagramCodec> ss2022_codec;
        std::array<std::uint8_t, kMaxUdpWireSize> receive_buffer{};
        boost::asio::mutable_buffer output_buffer;
        ReadHandler receive_handler;
        bool receive_in_progress = false;
    };

  public:
    explicit ShadowsocksDatagramHandle(std::shared_ptr<State> state) : state_(std::move(state)) {}

    void async_send_to(boost::asio::const_buffer buffer, core::DatagramAddress destination,
                       WriteHandler handler) override {
        state_->send(buffer, std::move(destination), std::move(handler));
    }

    void async_receive_from(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        state_->receive(buffer, std::move(handler));
    }

    boost::asio::any_io_executor executor() noexcept override { return state_->socket->executor(); }

    std::size_t max_datagram_size() const noexcept override { return state_->max_datagram_size(); }

    void cancel() noexcept override { state_->close(); }

    void close() noexcept override { state_->close(); }

  private:
    std::shared_ptr<State> state_;
};

} // namespace

ShadowsocksOutbound::ShadowsocksOutbound(runtime::AsioRuntime &runtime,
                                         ShadowsocksOutboundConfig config,
                                         std::shared_ptr<dns::ResolverService> resolver)
    : runtime_(runtime), config_(std::move(config)), resolver_(std::move(resolver)),
      descriptor_{config_.id, "shadowsocks"} {
    if (config_.plugin == "kcptun") {
        kcptun_pool_ = std::make_shared<transport::shadowsocks::KcptunClientPool>(
            runtime_, config_.kcptun.value_or(transport::shadowsocks::KcptunClientOptions{}));
    }
    if (config_.plugin_mux &&
        (config_.plugin == "v2ray-plugin" || config_.plugin == "gost-plugin")) {
        websocket_mux_pool_ = std::make_shared<transport::shadowsocks::WebSocketPluginMuxPool>(
            runtime_.serialized_executor());
    }
}

core::Status ShadowsocksOutbound::validate() const {
    if (config_.id.empty() || config_.server_host.empty() || config_.server_port == 0 ||
        config_.password.empty()) {
        return core::fail({core::ErrorCode::configuration,
                           "Shadowsocks outbound ID, server, port, and password are required"});
    }
    const auto method = ss::cipher_method(config_.method);
    if (!method) {
        return core::Status(core::fail(method.error()));
    }
    if (!config_.plugin.empty() && config_.plugin != "obfs" && config_.plugin != "v2ray-plugin" &&
        config_.plugin != "gost-plugin" && config_.plugin != "kcptun" &&
        config_.plugin != "shadow-tls" && config_.plugin != "restls" && config_.plugin != "jls") {
        return core::fail({core::ErrorCode::unsupported, "unsupported Shadowsocks plugin", {}});
    }
    if (config_.plugin == "obfs" && config_.plugin_mode != "http" && config_.plugin_mode != "tls") {
        return core::fail({core::ErrorCode::unsupported,
                           "only Shadowsocks simple-obfs http and tls modes are supported",
                           {}});
    }
    if ((config_.plugin == "v2ray-plugin" || config_.plugin == "gost-plugin") &&
        config_.plugin_mode != "websocket") {
        return core::fail({core::ErrorCode::unsupported,
                           "Shadowsocks WebSocket plugins require websocket mode",
                           {}});
    }
    if (config_.plugin == "kcptun" &&
        (config_.plugin_mode != "" || config_.plugin_tls || config_.plugin_skip_cert_verify)) {
        return core::fail({core::ErrorCode::configuration,
                           "Shadowsocks kcptun does not use WebSocket plugin options",
                           {}});
    }
    if (config_.plugin == "shadow-tls") {
        if (!config_.plugin_mode.empty() || !config_.plugin_path.empty() || config_.plugin_tls) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks Shadow-TLS does not use WebSocket plugin options",
                               {}});
        }
        if (config_.plugin_version < 1 || config_.plugin_version > 3) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks Shadow-TLS version must be 1, 2, or 3",
                               {}});
        }
        if (config_.plugin_version >= 2 && config_.plugin_password.empty()) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks Shadow-TLS v2 and v3 require a plugin password",
                               {}});
        }
        if (config_.plugin_host.empty()) {
            return core::fail(
                {core::ErrorCode::configuration, "Shadowsocks Shadow-TLS host is required", {}});
        }
    }
    if (config_.plugin == "restls") {
        if (!config_.plugin_mode.empty() || !config_.plugin_path.empty() || config_.plugin_tls ||
            config_.plugin_version_hint.empty()) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks ResTLS does not use WebSocket plugin options",
                               {}});
        }
        if (config_.plugin_version_hint != "tls12" && config_.plugin_version_hint != "tls13") {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks ResTLS version hint must be tls12 or tls13",
                               {}});
        }
        if (config_.plugin_password.empty() || config_.plugin_host.empty()) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks ResTLS host and password are required",
                               {}});
        }
    }
    if (config_.plugin_mux && config_.plugin != "v2ray-plugin" && config_.plugin != "gost-plugin") {
        return core::fail({core::ErrorCode::unsupported,
                           "Shadowsocks plugin mux requires v2ray-plugin or gost-plugin",
                           {}});
    }
    if (config_.plugin_mux && config_.plugin_smux_version != 1 &&
        config_.plugin_smux_version != 2) {
        return core::fail({core::ErrorCode::configuration,
                           "Shadowsocks WebSocket smux version must be 1 or 2",
                           {}});
    }
    if (config_.plugin == "v2ray-plugin" && config_.plugin_mux &&
        config_.plugin_smux_version != 1) {
        return core::fail(
            {core::ErrorCode::unsupported, "v2ray-plugin does not use smux version selection", {}});
    }
    if (config_.plugin == "jls") {
        if (!config_.plugin_mode.empty() || !config_.plugin_path.empty() || config_.plugin_tls) {
            return core::fail(
                {core::ErrorCode::configuration,
                 "Shadowsocks JLS requires the TLS 1.3 carrier without WebSocket options",
                 {}});
        }
        if (config_.plugin_username.empty() || config_.plugin_password.empty() ||
            config_.plugin_host.empty()) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks JLS host, username, and password are required",
                               {}});
        }
    }
    if (config_.plugin == "kcptun") {
        if (const auto validation = transport::shadowsocks::validate_kcptun_client_options(
                config_.kcptun.value_or(transport::shadowsocks::KcptunClientOptions{}));
            !validation) {
            return validation;
        }
    }
    if (config_.udp_over_tcp_version != 1 && config_.udp_over_tcp_version != 2) {
        return core::fail({core::ErrorCode::configuration,
                           "Shadowsocks UDP-over-TCP version must be 1 or 2",
                           {}});
    }
    if (!config_.plugin_path.empty() && config_.plugin_path.front() != '/') {
        return core::fail({core::ErrorCode::configuration,
                           "Shadowsocks WebSocket plugin path must start with '/'",
                           {}});
    }
    if (config_.plugin_host.find_first_of("\r\n") != std::string::npos) {
        return core::fail({core::ErrorCode::configuration,
                           "Shadowsocks plugin host contains invalid characters",
                           {}});
    }
    return {};
}

const core::OutboundDescriptor &ShadowsocksOutbound::descriptor() const noexcept {
    return descriptor_;
}

core::OutboundCapabilities ShadowsocksOutbound::capabilities() const noexcept {
    return capabilities_;
}

io::AnySender<core::StreamOpenResult>
ShadowsocksOutbound::connect_stream(core::StreamRequest request) {
    auto &runtime = runtime_;
    auto resolver = resolver_;
    auto kcptun_pool = kcptun_pool_;
    auto websocket_mux_pool = websocket_mux_pool_;
    auto config = config_;
    return async::bridge_sender<core::StreamOpenResult>(
        [&runtime, resolver = std::move(resolver), kcptun_pool = std::move(kcptun_pool),
         websocket_mux_pool = std::move(websocket_mux_pool), config = std::move(config),
         request = std::move(request)](
            async::BridgeSender<core::StreamOpenResult>::Handler terminal) mutable {
            auto operation = std::make_shared<ShadowsocksConnectOperation>(
                runtime, std::move(resolver), std::move(kcptun_pool), std::move(websocket_mux_pool),
                std::move(config), std::move(request), std::move(terminal));
            operation->start();
            return [operation] { operation->abort(); };
        });
}

void ShadowsocksOutbound::open_datagram(core::DatagramRequest request,
                                        core::DatagramOpenHandler handler) {
    if (const auto validation = validate(); !validation) {
        runtime_.scheduler().post(
            [handler = std::move(handler), error = validation.error()]() mutable {
                handler(core::DatagramOpenResult::failed(std::move(error)));
            });
        return;
    }

    if (config_.udp_over_tcp || config_.plugin == "kcptun") {
        const auto version = config_.udp_over_tcp_version;
        const auto magic = version == 2 ? kUdpOverTcpV2MagicAddress : kUdpOverTcpMagicAddress;
        core::StreamRequest stream_request{core::Destination::domain(std::string(magic), 0),
                                           std::nullopt, request.dial_trace};
        auto operation = std::make_shared<ShadowsocksConnectOperation>(
            runtime_, resolver_, kcptun_pool_, websocket_mux_pool_, config_,
            std::move(stream_request),
            [handler = std::move(handler), initial_destination = request.initial_destination,
             version,
             executor = runtime_.serialized_executor()](core::StreamOpenResult result) mutable {
                boost::asio::post(executor, [handler = std::move(handler), initial_destination,
                                             version, result = std::move(result)]() mutable {
                    if (!result.succeeded()) {
                        handler(core::DatagramOpenResult::failed(result.error.value_or(
                            core::Error{core::ErrorCode::transport_io,
                                        "failed to open Shadowsocks UoT stream"})));
                        return;
                    }
                    const auto request_destination =
                        version == 2 ? initial_destination : std::nullopt;
                    // Datagram-plane debt: UDP-over-TCP still speaks core::.
                    auto datagram = ss::make_udp_over_tcp_datagram_handle(
                        net::adapt_io_to_core(std::move(result.handle)),
                        {version == 2 ? ss::UdpOverTcpVersion::version2
                                      : ss::UdpOverTcpVersion::legacy,
                         request_destination});
                    if (!datagram) {
                        handler(core::DatagramOpenResult::failed(datagram.error()));
                        return;
                    }
                    handler(core::DatagramOpenResult::opened(
                        std::move(datagram.value()), core::DatagramSemantics::multi_destination));
                });
            });
        operation->start();
        return;
    }

    detail::resolve_host(
        runtime_, resolver_, config_.server_host,
        [runtime = &runtime_, config = config_, resolver = resolver_,
         handler = std::move(handler)](core::Result<detail::AddressList> result) mutable {
            if (!result || result.value().empty()) {
                handler(core::DatagramOpenResult::failed(
                    result ? core::Error{core::ErrorCode::resolution,
                                         "Shadowsocks server hostname resolved to no addresses"}
                           : result.error()));
                return;
            }
            const auto server =
                boost::asio::ip::udp::endpoint(result.value().front(), config.server_port);
            auto socket = std::make_shared<net::UdpStream>(runtime->serialized_executor());
            boost::system::error_code error;
            socket->open(server.protocol(), error);
            if (!error) {
                socket->bind({server.address().is_v4()
                                  ? boost::asio::ip::address(boost::asio::ip::address_v4::any())
                                  : boost::asio::ip::address(boost::asio::ip::address_v6::any()),
                              0},
                             error);
            }
            if (error) {
                handler(core::DatagramOpenResult::failed({core::ErrorCode::transport_io,
                                                          "failed to open Shadowsocks UDP socket",
                                                          detail::to_std_error(error)}));
                return;
            }
            const auto method = ss::cipher_method(config.method);
            if (!method) {
                handler(core::DatagramOpenResult::failed(method.error()));
                return;
            }
            if (method.value().kind == ss::CipherKind::stream) {
                auto handle = detail::make_legacy_shadowsocks_datagram_handle(
                    std::move(socket), server, config.method, config.password);
                if (!handle) {
                    handler(core::DatagramOpenResult::failed(handle.error()));
                    return;
                }
                handler(core::DatagramOpenResult::opened(
                    std::move(handle.value()), core::DatagramSemantics::multi_destination));
                return;
            }
            auto state = std::make_shared<ShadowsocksDatagramHandle::State>(
                std::move(socket), server, config.method, config.password);
            handler(core::DatagramOpenResult::opened(
                std::make_unique<ShadowsocksDatagramHandle>(std::move(state)),
                core::DatagramSemantics::multi_destination));
        });
}

} // namespace clash_native::outbound
