#include <clash_native/outbound/shadowsocks_outbound.hpp>

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/detached.hpp>
#include <clash_native/async/timer.hpp>
#include <clash_native/core/base64.hpp>
#include <clash_native/dns/ech_resolver.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/net/udp_stream.hpp>
#include <clash_native/transport/endpoint_dialer.hpp>
#include <clash_native/transport/proxy/crypto.hpp>
#include <clash_native/transport/proxy/jls_client.hpp>
#include <clash_native/transport/proxy/restls_client.hpp>
#include <clash_native/transport/proxy/shadow_tls.hpp>
#include <clash_native/transport/shadowsocks/aead_packet.hpp>
#include <clash_native/transport/shadowsocks/legacy_stream.hpp>
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
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>

#include <boost/asio/write.hpp>
#include <boost/system/errc.hpp>
#include <exec/asio/use_sender.hpp>
#include <exec/async_scope.hpp>
#include <stdexec/execution.hpp>

#include <algorithm>
#include <atomic>
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

using StreamReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
using StreamWriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

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
    auto encrypted_length = transport::proxy::aead_encrypt(method, key, nonce, length);
    transport::proxy::increment_nonce(nonce);
    auto encrypted_payload = transport::proxy::aead_encrypt(method, key, nonce, payload);
    transport::proxy::increment_nonce(nonce);
    if (!encrypted_length || !encrypted_payload) {
        return {};
    }
    std::vector<std::uint8_t> result;
    result.reserve(encrypted_length.value().size() + encrypted_payload.value().size());
    result.insert(result.end(), encrypted_length.value().begin(), encrypted_length.value().end());
    result.insert(result.end(), encrypted_payload.value().begin(), encrypted_payload.value().end());
    return result;
}

// Resolves ECH configs for the WebSocket plugin TLS layer (Mihomo
// ech-opts): a static base64 ECHConfigList, or an HTTPS-record lookup
// with an optional query-server-name override. DNS failure fails closed.
// NOTE: named function per the coroutine creation rules; never an
// immediately-invoked capturing lambda.
stdexec::task<core::Result<std::vector<std::uint8_t>>>
fetch_ss_plugin_ech_config(std::shared_ptr<dns::ResolverService> resolver,
                           const ShadowsocksOutboundConfig &config,
                           const std::string &server_name) {
    if (!config.plugin_ech_config.empty()) {
        const auto decoded = core::base64_decode(config.plugin_ech_config);
        if (!decoded || decoded->empty()) {
            co_return core::fail(core::Error{core::ErrorCode::configuration,
                                             "Shadowsocks plugin ECH config is not valid base64"});
        }
        co_return core::Result<std::vector<std::uint8_t>>{
            std::vector<std::uint8_t>(decoded->begin(), decoded->end())};
    }
    if (!resolver) {
        co_return core::fail(core::Error{core::ErrorCode::configuration,
                                         "Shadowsocks plugin ECH lookup requires a DNS resolver"});
    }
    std::optional<std::string> query_name;
    if (!config.plugin_ech_query_server_name.empty()) {
        query_name = config.plugin_ech_query_server_name;
    }
    core::Result<std::vector<std::uint8_t>> ech;
    try {
        ech = co_await dns::async_query_ech_config(resolver->query_service(), server_name,
                                                   std::move(query_name));
    } catch (const core::Error &failure) {
        co_return core::fail(failure);
    } catch (...) {
        co_return core::fail(core::Error{core::ErrorCode::endpoint_connection,
                                         "failed to resolve Shadowsocks plugin ECH config"});
    }
    if (!ech) {
        co_return core::fail(ech.error());
    }
    co_return core::Result<std::vector<std::uint8_t>>{std::move(ech.value())};
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
            if (const auto spec = transport::proxy::cipher_method(this->method)) {
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
            if (const auto spec = transport::proxy::cipher_method(this->method)) {
                read_nonce.assign(spec.value().nonce_size, 0);
                encrypted_length.resize(2 + spec.value().overhead);
            }
        }

        using WriteTerminal = StreamWriteHandler;

        // Single carrier write as one task: co_await the carrier sender
        // directly instead of bridging it back into a handler.
        // NOTE: named function per the coroutine creation rules; never an
        // immediately-invoked capturing lambda.
        static stdexec::task<void>
        run_carrier_write(std::shared_ptr<State> self,
                          std::shared_ptr<std::vector<std::uint8_t>> wire, std::size_t size,
                          WriteTerminal done) {
            try {
                // NOTE: name the sender first; argument order is unspecified.
                auto sender = self->carrier->async_write(boost::asio::buffer(*wire));
                co_await std::move(sender);
            } catch (...) {
                self->write_in_progress = false;
                done(net::unpack_error(std::current_exception()), 0);
                co_return;
            }
            self->write_in_progress = false;
            done({}, size);
        }

        void write(boost::asio::const_buffer buffer, StreamWriteHandler handler) {
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
            write_handler = std::move(handler);
            auto wire = std::make_shared<std::vector<std::uint8_t>>(std::move(encoded));
            auto self = shared_from_this();
            // Single carrier write as one task co_awaiting the carrier
            // sender directly; runs detached (immortal heap scope) so the
            // last State reference cannot free a member scope_ (#194).
            // Teardown stays guard-driven via abort().
            WriteTerminal done{std::move(write_handler)};
            async::spawn_detached(run_carrier_write(self, wire, size, std::move(done)));
        }

        void read(boost::asio::mutable_buffer buffer, StreamReadHandler handler) {
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
                read_in_progress = true;
                read_buffer = buffer;
                read_handler = std::move(handler);
                copy_pending(buffer);
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

        // Retires a parked read without closing the transport. The framed
        // lower reads in flight complete against a cleared handler and drop;
        // buffered plaintext stays for the next read.
        void cancel_read() noexcept {
            try {
                auto self = shared_from_this();
                boost::asio::dispatch(carrier->executor(), [self] {
                    auto handler = std::move(self->read_handler);
                    if (!handler) {
                        return;
                    }
                    self->read_buffer = {};
                    self->read_in_progress = false;
                    boost::asio::post(self->carrier->executor(),
                                      [handler = std::move(handler)]() mutable {
                                          handler(boost::asio::error::operation_aborted, 0);
                                      });
                });
            } catch (...) {
                // Aborter contract: never throw; the late framed completion or
                // close() retires the parked handler instead.
            }
        }

        // Retires a parked write without closing the transport. The staged
        // wire write in flight (referencing the shared wire buffer) drains;
        // its late completion finds a cleared write state and drops.
        void cancel_write() noexcept {
            try {
                auto self = shared_from_this();
                boost::asio::dispatch(carrier->executor(), [self] {
                    auto handler = std::move(self->write_handler);
                    if (!handler) {
                        return;
                    }
                    self->write_in_progress = false;
                    boost::asio::post(self->carrier->executor(),
                                      [handler = std::move(handler)]() mutable {
                                          handler(boost::asio::error::operation_aborted, 0);
                                      });
                });
            } catch (...) {
                // Aborter contract: never throw; see cancel_read.
            }
        }

        void close() noexcept {
            carrier->close();
            finish_read(boost::asio::error::operation_aborted, 0);
        }

        void receive_salt() {
            const auto method_info = transport::proxy::cipher_method(method);
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
                           auto key_result = transport::proxy::derive_aead_subkey(
                               self->method, self->password, self->receive_salt_buffer);
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
                    const auto length = transport::proxy::aead_decrypt(
                        self->method, self->read_key, self->read_nonce, self->encrypted_length);
                    if (!length || length.value().size() != 2) {
                        self->finish_read(authentication_error(), 0);
                        return;
                    }
                    transport::proxy::increment_nonce(self->read_nonce);
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
            const auto method_info = transport::proxy::cipher_method(method);
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
                           auto plaintext = transport::proxy::aead_decrypt(
                               self->method, self->read_key, self->read_nonce,
                               self->encrypted_payload);
                           if (!plaintext || plaintext.value().empty()) {
                               self->finish_read(authentication_error(), 0);
                               return;
                           }
                           transport::proxy::increment_nonce(self->read_nonce);
                           self->pending_plaintext = std::move(plaintext.value());
                           self->pending_offset = 0;
                           self->copy_pending(self->read_buffer);
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

        void copy_pending(boost::asio::mutable_buffer buffer) {
            if (!read_in_progress) {
                // Parked read was aborted; keep plaintext buffered for the next read.
                return;
            }
            const auto remaining = pending_plaintext.size() - pending_offset;
            const auto copied = std::min(buffer.size(), remaining);
            std::memcpy(buffer.data(), pending_plaintext.data() + pending_offset, copied);
            pending_offset += copied;
            if (pending_offset == pending_plaintext.size()) {
                pending_plaintext.clear();
                pending_offset = 0;
            }
            finish_read({}, copied);
        }

        // Exact carrier pull as one task: loop co_awaiting carrier senders
        // directly instead of re-arming through a bridge receiver.
        // NOTE: named function per the coroutine creation rules; never an
        // immediately-invoked capturing lambda.
        static stdexec::task<void> run_read_exact_carrier(std::shared_ptr<State> self,
                                                          boost::asio::mutable_buffer buffer,
                                                          ExactReadHandler handler) {
            std::size_t done = 0;
            while (done < buffer.size()) {
                auto rest = boost::asio::mutable_buffer(
                    static_cast<std::uint8_t *>(buffer.data()) + done, buffer.size() - done);
                std::optional<std::size_t> pulled;
                try {
                    // NOTE: name the sender first; argument order is unspecified.
                    auto sender = self->carrier->async_read_some(rest);
                    pulled = co_await std::move(sender);
                } catch (...) {
                    handler(net::unpack_error(std::current_exception()));
                    co_return;
                }
                if (!pulled) {
                    handler(boost::asio::error::eof);
                    co_return;
                }
                if (*pulled == 0) {
                    handler(boost::asio::error::eof);
                    co_return;
                }
                done += *pulled;
            }
            handler({});
        }

        void read_exact_carrier(boost::asio::mutable_buffer buffer, ExactReadHandler handler) {
            // Detached (immortal heap scope): the last State reference cannot
            // free a member scope_ (#194). Teardown stays guard-driven.
            async::spawn_detached(
                run_read_exact_carrier(shared_from_this(), buffer, std::move(handler)));
        }

        void finish_write(const boost::system::error_code &error, std::size_t size) {
            write_in_progress = false;
            auto handler = std::move(write_handler);
            if (!handler) {
                // Late lower completion after cancel_write retired the op.
                return;
            }
            handler(error, size);
        }

        void finish_read(const boost::system::error_code &error, std::size_t size) {
            read_in_progress = false;
            auto handler = std::move(read_handler);
            read_buffer = {};
            if (!handler) {
                // Late lower completion after cancel_read retired the op.
                return;
            }
            handler(error, size);
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
        StreamReadHandler read_handler;
        StreamWriteHandler write_handler;
        bool read_key_ready = false;
        ss::ObfsMode obfs_mode = ss::ObfsMode::none;
        bool obfs_response_ready = true;
        bool read_in_progress = false;
        bool write_in_progress = false;
        // No member scope: carrier read/write chain tasks run detached
        // (immortal heap scope) so the last State reference cannot free its
        // scope (#194). Teardown stays guard-driven via cancel_read/write.
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
                return async::CallbackAbortFn{[state] { state->cancel_read(); }};
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>(count));
                } else if (error == boost::asio::error::eof) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>());
                } else if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
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
                return async::CallbackAbortFn{[state] { state->cancel_write(); }};
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), count);
                } else if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
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
                                OutboundRegistry::Snapshot chain_registry,
                                std::shared_ptr<ss::KcptunClientPool> kcptun_pool,
                                std::shared_ptr<ss::WebSocketPluginMuxPool> websocket_mux_pool,
                                ShadowsocksOutboundConfig config, core::StreamRequest request,
                                core::StreamOpenHandler handler)
        : runtime_(runtime), resolver_(std::move(resolver)),
          chain_registry_(std::move(chain_registry)), config_(std::move(config)),
          kcptun_pool_(std::move(kcptun_pool)), websocket_mux_pool_(std::move(websocket_mux_pool)),
          request_(std::move(request)),
          socket_(std::make_shared<boost::asio::ip::tcp::socket>(runtime.serialized_executor())),
          handler_(std::move(handler)) {}

    void start() {
        const auto validation = validate_config();
        if (!validation) {
            finish(core::StreamOpenResult::failed(validation.error()));
            return;
        }
        // Guarded connect runs detached (immortal heap scope): the finished
        // task holds the last operation reference at completion, which would
        // free a member scope_ before __complete touches scope->__active_
        // (ASan #194). Teardown stays guard-driven via abort(); no stop is
        // ever requested.
        async::spawn_detached(run_guarded(shared_from_this()));
    }

    // Timeout race driver: the connect chain races a sleep via
    // with_timeout so a stalled peer cannot park the open. Timeout
    // surfaces as an in-band Result; machinery set_error crosses as an
    // exception mapped to a transport_io failure; outer stop cancels both
    // branches. The former timer task's timeout-side teardown (carrier
    // close / socket cancel) is subsumed by finish()'s !succeeded close
    // path. A named function (not an immediately-invoked capturing
    // lambda) builds the task; see docs/async-pitfalls.md.
    static stdexec::task<void> run_guarded(std::shared_ptr<ShadowsocksConnectOperation> self) {
        core::StreamOpenResult result = core::StreamOpenResult::failed(
            {core::ErrorCode::cancelled, "Shadowsocks connect stopped"});
        try {
            result = co_await async::with_timeout<core::StreamOpenResult>(
                self->runtime_.serialized_executor(), kConnectTimeout, run_work(self), [] {
                    return core::StreamOpenResult::failed(
                        {core::ErrorCode::timeout, "timed out opening Shadowsocks TCP stream"});
                });
        } catch (...) {
            result = core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "Shadowsocks connect chain failed"});
        }
        self->finish(std::move(result));
    }

    // Straight-line connect chain: resolve, transport survivor
    // (kcptun / mux pool / TCP plus plugin), cipher handshake. Every
    // terminal returns a Result; run_guarded funnels it through finish(),
    // so the spawned task always ends with a value unless an outer stop
    // ends it early.
    static stdexec::task<core::StreamOpenResult>
    run_work(std::shared_ptr<ShadowsocksConnectOperation> self) {
        // Chained dials skip local resolution: the chain resolves the server.
        if (!self->config_.dialer_proxy.empty()) {
            try {
                co_await dial_chained_transport(self);
            } catch (const core::Error &failure) {
                co_return core::StreamOpenResult::failed(failure);
            } catch (...) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "Shadowsocks chained dial failed"});
            }
            if (self->completed_ || !self->chained_transport_) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
            }
            try {
                co_await resolve_plugin_ech(self);
            } catch (const core::Error &failure) {
                co_return core::StreamOpenResult::failed(failure);
            } catch (...) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "Shadowsocks plugin ECH lookup failed"});
            }
            if (self->completed_) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
            }
            // StreamHandle-native plugin carriers consume the chained
            // transport directly; cipher opens use it via the carrier.
            const bool stream_plugin = self->shadow_tls_plugin() || self->restls_plugin() ||
                                       self->jls_plugin() ||
                                       (self->websocket_plugin() && !self->config_.plugin_mux);
            if (!stream_plugin) {
                self->carrier_ =
                    std::make_shared<ss::StreamCarrier>(std::move(self->chained_transport_));
            }
            co_return co_await dispatch_connected(self);
        }
        core::Result<detail::AddressList> resolved;
        try {
            resolved = co_await detail::resolve_host_sender(self->runtime_, self->resolver_,
                                                            self->config_.server_host);
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::resolution, "failed to resolve Shadowsocks server"});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        if (!resolved) {
            co_return core::StreamOpenResult::failed(resolved.error());
        }
        try {
            co_await resolve_plugin_ech(self);
        } catch (const core::Error &failure) {
            co_return core::StreamOpenResult::failed(failure);
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "Shadowsocks plugin ECH lookup failed"});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        if (self->kcptun_plugin()) {
            if (resolved.value().empty()) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::resolution,
                     "Shadowsocks kcptun server hostname resolved to no addresses",
                     {}});
            }
            const auto endpoint =
                boost::asio::ip::udp::endpoint(resolved.value().front(), self->config_.server_port);
            if (!self->kcptun_pool_) {
                auto options = self->config_.kcptun.value_or(ss::KcptunClientOptions{});
                auto stream =
                    ss::make_kcptun_client_stream(self->runtime_, endpoint, std::move(options));
                if (!stream) {
                    co_return core::StreamOpenResult::failed(stream.error());
                }
                self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(stream.value()));
                co_return co_await send_initial_request(self);
            }
            try {
                auto stream = co_await self->kcptun_pool_->open_stream(endpoint);
                if (self->completed_) {
                    co_return core::StreamOpenResult::failed(
                        {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
                }
                self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(stream));
            } catch (const core::Error &failure) {
                co_return core::StreamOpenResult::failed(failure);
            } catch (...) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "kcptun pool open failed", {}});
            }
            co_return co_await send_initial_request(self);
        }
        auto endpoints = std::make_shared<std::vector<boost::asio::ip::tcp::endpoint>>();
        endpoints->reserve(resolved.value().size());
        for (const auto &address : resolved.value()) {
            endpoints->emplace_back(address, self->config_.server_port);
        }
        if (self->websocket_plugin() && self->config_.plugin_mux) {
            if (!self->websocket_mux_pool_) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::configuration,
                     "Shadowsocks WebSocket mux pool is not initialized",
                     {}});
            }
            core::Result<std::unique_ptr<io::StreamHandle>> mux_stream;
            try {
                using Sigs =
                    async::BridgeSignatures<core::Result<std::unique_ptr<io::StreamHandle>>>;
                // NOTE: name the sender first; argument order is unspecified.
                auto sender = async::callback_sender<Sigs>(
                    [self, endpoints](auto terminal) mutable -> async::CallbackAbortFn {
                        self->websocket_mux_pool_->async_open_stream(
                            std::move(*endpoints), self->websocket_options(), std::move(terminal));
                        return async::CallbackAbortFn{[self] { self->abort(); }};
                    },
                    [](auto receiver, core::Result<std::unique_ptr<io::StreamHandle>> stream) {
                        stdexec::set_value(std::move(receiver), std::move(stream));
                    });
                mux_stream = co_await std::move(sender);
            } catch (...) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "WebSocket mux pool open failed", {}});
            }
            if (self->completed_) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
            }
            if (!mux_stream) {
                co_return core::StreamOpenResult::failed(mux_stream.error());
            }
            self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(mux_stream.value()));
            co_return co_await send_initial_request(self);
        }
        co_return co_await self->connect_tcp(self, std::move(endpoints));
    }

    // TCP connect plus plugin/cipher tail, shared by run_work().
    // Plugin dispatch shared by the direct and chained transports.
    static stdexec::task<core::StreamOpenResult>
    dispatch_connected(std::shared_ptr<ShadowsocksConnectOperation> self) {
        if (self->shadow_tls_plugin()) {
            co_return co_await open_shadow_tls(self);
        }
        if (self->restls_plugin()) {
            co_return co_await open_restls(self);
        }
        if (self->jls_plugin()) {
            co_return co_await open_jls(self);
        }
        co_return co_await send_initial_request(self);
    }

    // ECH config fetch shared by the direct and chained transports. Throws
    // core::Error on failure; callers map it to a failure Result.
    static stdexec::task<void>
    resolve_plugin_ech(std::shared_ptr<ShadowsocksConnectOperation> self) {
        if (self->websocket_plugin() && self->config_.plugin_tls &&
            self->config_.plugin_ech_enabled) {
            auto ech = co_await fetch_ss_plugin_ech_config(
                self->resolver_, self->config_,
                self->config_.plugin_host.empty() ? "bing.com" : self->config_.plugin_host);
            if (self->completed_) {
                co_return;
            }
            if (!ech) {
                throw ech.error();
            }
            self->plugin_ech_config_ = std::move(ech.value());
        }
        co_return;
    }

    // Dials the server through the dialer_proxy chain, delivering a ready
    // StreamHandle. The trace carries our own ID so chain cycles fail fast.
    // Throws core::Error on failure; callers map it to a failure Result.
    // NOTE: named function per the coroutine creation rules; never an
    // immediately-invoked capturing lambda.
    static stdexec::task<void>
    dial_chained_transport(std::shared_ptr<ShadowsocksConnectOperation> self) {
        if (!self->chain_registry_) {
            throw core::Error{core::ErrorCode::configuration,
                              "Shadowsocks dialer-proxy requires a chain registry",
                              {}};
        }
        const auto trace =
            transport::extend_endpoint_trace(self->request_.dial_trace, self->config_.id);
        if (!trace) {
            throw trace.error();
        }
        const transport::EndpointDialRequirements requirements{true, false};
        const auto plan = transport::EndpointDialPlan::from_registry(
            self->chain_registry_, self->config_.dialer_proxy, requirements);
        if (!plan) {
            throw plan.error();
        }
        boost::system::error_code ignored;
        const auto numeric = boost::asio::ip::make_address(self->config_.server_host, ignored);
        core::Destination destination =
            ignored
                ? core::Destination::domain(self->config_.server_host, self->config_.server_port)
                : core::Destination::address(numeric, self->config_.server_port);
        core::StreamRequest chained_request{std::move(destination), std::nullopt, trace.value()};
        core::Result<std::unique_ptr<io::StreamHandle>> opened;
        try {
            // Co_await the chained sender directly: StreamOpenResult
            // unwraps into the transported handle; stop aborts via the
            // operation abort (socket/carrier close through finish path).
            auto sender = transport::EndpointDialer(self->runtime_.serialized_executor(),
                                                    std::move(plan.value()))
                              .connect_stream(std::move(chained_request));
            auto stream_result = co_await std::move(sender);
            if (stream_result.status == core::OpenStatus::opened && stream_result.handle) {
                opened = core::Result<std::unique_ptr<io::StreamHandle>>{
                    std::move(stream_result.handle)};
            } else if (stream_result.error) {
                opened = core::fail(*stream_result.error);
            } else {
                opened = core::fail(
                    {core::ErrorCode::endpoint_connection, "Shadowsocks chained dial failed", {}});
            }
        } catch (const core::Error &failure) {
            throw failure;
        } catch (...) {
            throw core::Error{core::ErrorCode::transport_io, "Shadowsocks chained dial failed", {}};
        }
        if (self->completed_) {
            co_return;
        }
        if (!opened) {
            throw opened.error();
        }
        self->chained_transport_ = std::move(opened.value());
    }

    static stdexec::task<core::StreamOpenResult>
    connect_tcp(std::shared_ptr<ShadowsocksConnectOperation> self,
                std::shared_ptr<std::vector<boost::asio::ip::tcp::endpoint>> endpoints) {
        try {
            try {
                co_await (
                    boost::asio::async_connect(*self->socket_, *endpoints, exec::asio::use_sender) |
                    stdexec::then([](const boost::asio::ip::tcp::endpoint &) {}) |
                    stdexec::let_error([self](std::exception_ptr error) {
                        try {
                            std::rethrow_exception(std::move(error));
                        } catch (const boost::system::system_error &failure) {
                            return stdexec::just_error(std::make_exception_ptr(
                                core::Error{core::ErrorCode::endpoint_connection,
                                            "failed to connect to Shadowsocks server",
                                            detail::to_std_error(failure.code())}));
                        }
                        std::rethrow_exception(std::current_exception());
                    }));
            } catch (const core::Error &failure) {
                co_return core::StreamOpenResult::failed(failure);
            } catch (...) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::endpoint_connection,
                     "failed to connect to Shadowsocks server"});
            }
            if (self->completed_) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
            }
            co_return co_await dispatch_connected(self);
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "Shadowsocks connect chain failed"});
        }
    }

  private:
    core::Status validate_config() const {
        if (config_.id.empty() || config_.server_host.empty() || config_.server_port == 0 ||
            config_.password.empty()) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks outbound ID, server, port, and password are required"});
        }
        const auto method = transport::proxy::cipher_method(config_.method);
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
        if ((config_.plugin == "v2ray-plugin" || config_.plugin == "gost-plugin") &&
            config_.plugin_certificate.empty() != config_.plugin_private_key.empty()) {
            return core::fail(
                {core::ErrorCode::configuration,
                 "Shadowsocks WebSocket plugin mTLS requires both certificate and private-key",
                 {}});
        }
        const bool websocket_tls_plugin =
            config_.plugin == "v2ray-plugin" || config_.plugin == "gost-plugin";
        if (!websocket_tls_plugin &&
            (!config_.plugin_headers.empty() || !config_.plugin_name_cert_verify.empty() ||
             !config_.plugin_certificate.empty() || !config_.plugin_private_key.empty() ||
             config_.plugin_ech_enabled)) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks WebSocket TLS options require v2ray-plugin or "
                               "gost-plugin",
                               {}});
        }
        if (config_.plugin == "kcptun" &&
            (config_.plugin_mode != "" || config_.plugin_tls || config_.plugin_skip_cert_verify)) {
            return core::fail({core::ErrorCode::configuration,
                               "Shadowsocks kcptun does not use WebSocket plugin options",
                               {}});
        }
        if (!config_.dialer_proxy.empty()) {
            if (config_.plugin == "kcptun") {
                return core::fail({core::ErrorCode::unsupported,
                                   "Shadowsocks dialer-proxy cannot chain kcptun carriers",
                                   {}});
            }
            if (config_.plugin_mux) {
                return core::fail({core::ErrorCode::unsupported,
                                   "Shadowsocks dialer-proxy cannot chain multiplexed plugin "
                                   "carriers",
                                   {}});
            }
            if (config_.plugin == "obfs") {
                return core::fail({core::ErrorCode::unsupported,
                                   "Shadowsocks dialer-proxy cannot chain simple-obfs carriers",
                                   {}});
            }
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

    // Returns the connected transport: the chained StreamHandle when
    // dialer_proxy is set, otherwise the directly connected socket wrapped
    // for the plugin carriers.
    std::unique_ptr<io::StreamHandle> take_connected_stream() {
        if (chained_transport_) {
            return std::move(chained_transport_);
        }
        return std::make_unique<net::TcpStream>(std::move(*socket_));
    }

    ss::WebSocketPluginOptions websocket_options() const {
        ss::WebSocketPluginOptions options;
        options.host = config_.plugin_host.empty() ? "bing.com" : config_.plugin_host;
        options.path = config_.plugin_path.empty() ? "/" : config_.plugin_path;
        options.tls = config_.plugin_tls;
        options.skip_cert_verify = config_.plugin_skip_cert_verify;
        options.headers = config_.plugin_headers;
        options.certificate_pin = config_.plugin_fingerprint;
        options.name_cert_verify = config_.plugin_name_cert_verify;
        options.client_certificate_pem = config_.plugin_certificate;
        options.client_private_key_pem = config_.plugin_private_key;
        if (plugin_ech_config_) {
            options.ech_config_list = *plugin_ech_config_;
        }
        options.mux = config_.plugin_mux;
        options.mux_protocol = config_.plugin == "gost-plugin" ? ss::WebSocketMuxProtocol::smux
                                                               : ss::WebSocketMuxProtocol::v2ray;
        options.smux_version = config_.plugin_smux_version;
        return options;
    }

    static stdexec::task<core::StreamOpenResult>
    open_shadow_tls(std::shared_ptr<ShadowsocksConnectOperation> self) {
        auto stream =
            std::make_shared<std::unique_ptr<io::StreamHandle>>(self->take_connected_stream());
        transport::proxy::ShadowTlsClientOptions options;
        options.version = self->config_.plugin_version;
        options.password = self->config_.plugin_password;
        options.host = self->config_.plugin_host;
        options.skip_cert_verify = self->config_.plugin_skip_cert_verify;
        options.fingerprint = self->config_.plugin_client_fingerprint;
        options.certificate_pin = self->config_.plugin_fingerprint;
        if (!self->config_.plugin_alpn.empty()) {
            options.alpn_protocols = self->config_.plugin_alpn;
        }
        core::Result<std::unique_ptr<io::StreamHandle>> result;
        try {
            using Sigs = async::BridgeSignatures<core::Result<std::unique_ptr<io::StreamHandle>>>;
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = async::callback_sender<Sigs>(
                [self, stream,
                 options = std::move(options)](auto terminal) mutable -> async::CallbackAbortFn {
                    auto handle = transport::proxy::async_open_shadow_tls_abortable(
                        std::move(*stream), std::move(options), std::move(terminal));
                    return async::CallbackAbortFn{[self, handle] {
                        self->abort();
                        if (handle) {
                            handle->abort();
                        }
                    }};
                },
                [](auto receiver, core::Result<std::unique_ptr<io::StreamHandle>> opened) {
                    stdexec::set_value(std::move(receiver), std::move(opened));
                });
            result = co_await std::move(sender);
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "Shadow-TLS open failed", {}});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        if (!result) {
            co_return core::StreamOpenResult::failed(result.error());
        }
        self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(result.value()));
        co_return co_await send_initial_request(self);
    }

    static stdexec::task<core::StreamOpenResult>
    open_restls(std::shared_ptr<ShadowsocksConnectOperation> self) {
        auto stream =
            std::make_shared<std::unique_ptr<io::StreamHandle>>(self->take_connected_stream());
        transport::proxy::RestlsClientOptions options;
        options.server_name = self->config_.plugin_host;
        options.password = self->config_.plugin_password;
        options.version_hint = self->config_.plugin_version_hint;
        options.restls_script = self->config_.plugin_restls_script;
        options.skip_cert_verify = self->config_.plugin_skip_cert_verify;
        options.certificate_pin = self->config_.plugin_fingerprint;
        core::Result<std::unique_ptr<io::StreamHandle>> result;
        try {
            using Sigs = async::BridgeSignatures<core::Result<std::unique_ptr<io::StreamHandle>>>;
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = async::callback_sender<Sigs>(
                [self, stream,
                 options = std::move(options)](auto terminal) mutable -> async::CallbackAbortFn {
                    auto handle = transport::proxy::async_open_restls_abortable(
                        std::move(*stream), std::move(options), std::move(terminal));
                    return async::CallbackAbortFn{[self, handle] {
                        self->abort();
                        if (handle) {
                            handle->abort();
                        }
                    }};
                },
                [](auto receiver, core::Result<std::unique_ptr<io::StreamHandle>> opened) {
                    stdexec::set_value(std::move(receiver), std::move(opened));
                });
            result = co_await std::move(sender);
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "ResTLS open failed", {}});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        if (!result) {
            co_return core::StreamOpenResult::failed(result.error());
        }
        self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(result.value()));
        co_return co_await send_initial_request(self);
    }

    static stdexec::task<core::StreamOpenResult>
    open_jls(std::shared_ptr<ShadowsocksConnectOperation> self) {
        auto stream =
            std::make_shared<std::unique_ptr<io::StreamHandle>>(self->take_connected_stream());
        transport::proxy::JlsClientOptions options;
        options.server_name = self->config_.plugin_host;
        options.username = self->config_.plugin_username;
        options.password = self->config_.plugin_password;
        options.alpn = self->config_.plugin_alpn;
        options.skip_cert_verify = self->config_.plugin_skip_cert_verify;
        core::Result<std::unique_ptr<io::StreamHandle>> result;
        try {
            using Sigs = async::BridgeSignatures<core::Result<std::unique_ptr<io::StreamHandle>>>;
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = async::callback_sender<Sigs>(
                [self, stream,
                 options = std::move(options)](auto terminal) mutable -> async::CallbackAbortFn {
                    auto handle = transport::proxy::async_open_jls_abortable(
                        std::move(*stream), std::move(options), std::move(terminal));
                    return async::CallbackAbortFn{[self, handle] {
                        self->abort();
                        if (handle) {
                            handle->abort();
                        }
                    }};
                },
                [](auto receiver, core::Result<std::unique_ptr<io::StreamHandle>> opened) {
                    stdexec::set_value(std::move(receiver), std::move(opened));
                });
            result = co_await std::move(sender);
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "JLS open failed", {}});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        if (!result) {
            co_return core::StreamOpenResult::failed(result.error());
        }
        self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(result.value()));
        co_return co_await send_initial_request(self);
    }

    static stdexec::task<core::StreamOpenResult>
    send_initial_request(std::shared_ptr<ShadowsocksConnectOperation> self) {
        const auto method = transport::proxy::cipher_method(self->config_.method);
        if (method.value().shadowsocks_2022) {
            auto address = detail::encode_proxy_address(self->request_.destination);
            if (!address) {
                co_return core::StreamOpenResult::failed(address.error());
            }
            if (self->websocket_plugin() && !self->config_.plugin_mux) {
                co_return co_await open_websocket_2022(self, std::move(address.value()));
            }
            std::optional<core::StreamOpenResult> opened;
            try {
                if (self->carrier_) {
                    using Sigs = async::BridgeSignatures<core::StreamOpenResult>;
                    // NOTE: name the sender first; argument order is unspecified.
                    auto sender = async::callback_sender<Sigs>(
                        [self, dest = std::move(address.value())](
                            auto terminal) mutable -> async::CallbackAbortFn {
                            ss::async_open_shadowsocks_2022_stream(
                                self->runtime_, self->carrier_, self->config_.method,
                                self->config_.password, std::move(dest), std::move(terminal));
                            return async::CallbackAbortFn{[self] { self->abort(); }};
                        },
                        [](auto receiver, core::StreamOpenResult result) {
                            stdexec::set_value(std::move(receiver), std::move(result));
                        });
                    opened = co_await std::move(sender);
                } else {
                    using Sigs = async::BridgeSignatures<core::StreamOpenResult>;
                    auto obfs = self->obfs_options();
                    // NOTE: name the sender first; argument order is unspecified.
                    auto sender = async::callback_sender<Sigs>(
                        [self, dest = std::move(address.value()),
                         obfs = std::move(obfs)](auto terminal) mutable -> async::CallbackAbortFn {
                            ss::async_open_shadowsocks_2022_stream(
                                self->runtime_, self->socket_, self->config_.method,
                                self->config_.password, std::move(dest), std::move(obfs),
                                std::move(terminal));
                            return async::CallbackAbortFn{[self] { self->abort(); }};
                        },
                        [](auto receiver, core::StreamOpenResult result) {
                            stdexec::set_value(std::move(receiver), std::move(result));
                        });
                    opened = co_await std::move(sender);
                }
            } catch (...) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "Shadowsocks 2022 open failed", {}});
            }
            co_return std::move(*opened);
        }
        if (method.value().kind == transport::proxy::CipherKind::stream) {
            co_return co_await send_legacy_initial_request(self, method.value());
        }
        std::vector<std::uint8_t> salt(method.value().key_size);
        if (!transport::proxy::random_bytes(salt)) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::authentication, "failed to generate Shadowsocks salt"});
        }
        auto key = transport::proxy::derive_aead_subkey(self->config_.method,
                                                        self->config_.password, salt);
        auto address = detail::encode_proxy_address(self->request_.destination);
        if (!key || !address) {
            co_return core::StreamOpenResult::failed(!key ? key.error() : address.error());
        }
        self->write_nonce_.assign(method.value().nonce_size, 0);
        auto record = append_tcp_record(self->config_.method, key.value(), self->write_nonce_,
                                        address.value());
        if (record.empty()) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::authentication, "failed to encrypt Shadowsocks destination"});
        }
        salt.insert(salt.end(), record.begin(), record.end());
        auto wire = std::make_shared<std::vector<std::uint8_t>>(std::move(salt));
        if (self->websocket_plugin() && !self->config_.plugin_mux) {
            co_return co_await open_websocket_classic(self, std::move(*wire),
                                                      std::move(key.value()));
        }
        if (const auto obfs = self->obfs_options(); obfs) {
            core::Status obfs_result;
            try {
                if (obfs->mode == ss::ObfsMode::http) {
                    using Sigs = async::BridgeSignatures<core::Status>;
                    // NOTE: name the sender first; argument order is unspecified.
                    auto sender = async::callback_sender<Sigs>(
                        [self, wire](auto terminal) mutable -> async::CallbackAbortFn {
                            const auto options = self->obfs_options();
                            auto handle = ss::async_write_http_obfs_request_abortable(
                                self->socket_, std::move(*wire), {options->host, options->port},
                                std::move(terminal));
                            return async::CallbackAbortFn{[self, handle] {
                                self->abort();
                                if (handle) {
                                    handle->abort();
                                }
                            }};
                        },
                        [](auto receiver, core::Status result) {
                            stdexec::set_value(std::move(receiver), std::move(result));
                        });
                    obfs_result = co_await std::move(sender);
                } else {
                    using Sigs = async::BridgeSignatures<core::Status>;
                    // NOTE: name the sender first; argument order is unspecified.
                    auto sender = async::callback_sender<Sigs>(
                        [self, wire](auto terminal) mutable -> async::CallbackAbortFn {
                            const auto options = self->obfs_options();
                            auto handle = ss::async_write_tls_obfs_request_abortable(
                                self->socket_, std::move(*wire), options->host,
                                std::move(terminal));
                            return async::CallbackAbortFn{[self, handle] {
                                self->abort();
                                if (handle) {
                                    handle->abort();
                                }
                            }};
                        },
                        [](auto receiver, core::Status result) {
                            stdexec::set_value(std::move(receiver), std::move(result));
                        });
                    obfs_result = co_await std::move(sender);
                }
            } catch (...) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "Shadowsocks obfs request failed", {}});
            }
            if (self->completed_) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
            }
            if (!obfs_result) {
                co_return core::StreamOpenResult::failed(obfs_result.error());
            }
            co_return core::StreamOpenResult::opened(std::make_unique<ShadowsocksStreamHandle>(
                self->socket_, self->config_.method, self->config_.password, std::move(key.value()),
                self->write_nonce_, std::vector<std::uint8_t>{}, obfs->mode));
        }
        try {
            if (self->carrier_) {
                co_await self->carrier_->async_write(boost::asio::buffer(*wire));
            } else {
                co_await (boost::asio::async_write(*self->socket_, boost::asio::buffer(*wire),
                                                   exec::asio::use_sender) |
                          stdexec::then([](std::size_t) {}) |
                          stdexec::let_error([](std::exception_ptr error) {
                              try {
                                  std::rethrow_exception(std::move(error));
                              } catch (const boost::system::system_error &failure) {
                                  return stdexec::just_error(std::make_exception_ptr(
                                      core::Error{core::ErrorCode::transport_io,
                                                  "failed to write Shadowsocks TCP request",
                                                  detail::to_std_error(failure.code())}));
                              }
                              std::rethrow_exception(std::current_exception());
                          }));
            }
        } catch (const core::Error &failure) {
            co_return core::StreamOpenResult::failed(
                {failure.code, "failed to write Shadowsocks TCP request", failure.cause});
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "failed to write Shadowsocks TCP request", {}});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        if (self->carrier_) {
            co_return core::StreamOpenResult::opened(std::make_unique<ShadowsocksStreamHandle>(
                self->carrier_, self->config_.method, self->config_.password,
                std::move(key.value()), self->write_nonce_));
        }
        co_return core::StreamOpenResult::opened(std::make_unique<ShadowsocksStreamHandle>(
            self->socket_, self->config_.method, self->config_.password, std::move(key.value()),
            self->write_nonce_));
    }

    static stdexec::task<core::StreamOpenResult>
    open_websocket_classic(std::shared_ptr<ShadowsocksConnectOperation> self,
                           std::vector<std::uint8_t> wire, std::vector<std::uint8_t> key) {
        auto stream =
            std::make_shared<std::unique_ptr<io::StreamHandle>>(self->take_connected_stream());
        core::Result<std::unique_ptr<io::StreamHandle>> plugin;
        try {
            using Sigs = async::BridgeSignatures<core::Result<std::unique_ptr<io::StreamHandle>>>;
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = async::callback_sender<Sigs>(
                [self, stream](auto terminal) mutable -> async::CallbackAbortFn {
                    auto handle = ss::async_open_websocket_plugin(
                        std::move(*stream), self->websocket_options(), std::move(terminal));
                    return async::CallbackAbortFn{[self, handle] {
                        self->abort();
                        if (handle) {
                            handle->cancel();
                        }
                    }};
                },
                [](auto receiver, core::Result<std::unique_ptr<io::StreamHandle>> opened) {
                    stdexec::set_value(std::move(receiver), std::move(opened));
                });
            plugin = co_await std::move(sender);
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "WebSocket plugin open failed", {}});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        if (!plugin) {
            co_return core::StreamOpenResult::failed(plugin.error());
        }
        self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(plugin.value()));
        auto shared_wire = std::make_shared<std::vector<std::uint8_t>>(std::move(wire));
        try {
            co_await self->carrier_->async_write(boost::asio::buffer(*shared_wire));
        } catch (const core::Error &failure) {
            co_return core::StreamOpenResult::failed(
                {failure.code, "failed to write Shadowsocks WebSocket request", failure.cause});
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io,
                 "failed to write Shadowsocks WebSocket request",
                 {}});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        co_return core::StreamOpenResult::opened(std::make_unique<ShadowsocksStreamHandle>(
            self->carrier_, self->config_.method, self->config_.password, std::move(key),
            self->write_nonce_));
    }

    static stdexec::task<core::StreamOpenResult>
    open_websocket_2022(std::shared_ptr<ShadowsocksConnectOperation> self,
                        std::vector<std::uint8_t> destination) {
        auto stream =
            std::make_shared<std::unique_ptr<io::StreamHandle>>(self->take_connected_stream());
        core::Result<std::unique_ptr<io::StreamHandle>> plugin;
        try {
            using Sigs = async::BridgeSignatures<core::Result<std::unique_ptr<io::StreamHandle>>>;
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = async::callback_sender<Sigs>(
                [self, stream](auto terminal) mutable -> async::CallbackAbortFn {
                    auto handle = ss::async_open_websocket_plugin(
                        std::move(*stream), self->websocket_options(), std::move(terminal));
                    return async::CallbackAbortFn{[self, handle] {
                        self->abort();
                        if (handle) {
                            handle->cancel();
                        }
                    }};
                },
                [](auto receiver, core::Result<std::unique_ptr<io::StreamHandle>> opened) {
                    stdexec::set_value(std::move(receiver), std::move(opened));
                });
            plugin = co_await std::move(sender);
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "WebSocket plugin open failed", {}});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        if (!plugin) {
            co_return core::StreamOpenResult::failed(plugin.error());
        }
        self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(plugin.value()));
        core::StreamOpenResult opened;
        try {
            using Sigs = async::BridgeSignatures<core::StreamOpenResult>;
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = async::callback_sender<Sigs>(
                [self, destination = std::move(destination)](
                    auto terminal) mutable -> async::CallbackAbortFn {
                    ss::async_open_shadowsocks_2022_stream(
                        self->runtime_, self->carrier_, self->config_.method,
                        self->config_.password, std::move(destination), std::move(terminal));
                    return async::CallbackAbortFn{[self] { self->abort(); }};
                },
                [](auto receiver, core::StreamOpenResult result) {
                    stdexec::set_value(std::move(receiver), std::move(result));
                });
            opened = co_await std::move(sender);
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "Shadowsocks 2022 open failed", {}});
        }
        co_return std::move(opened);
    }

    static stdexec::task<core::StreamOpenResult>
    send_legacy_initial_request(std::shared_ptr<ShadowsocksConnectOperation> self,
                                const transport::proxy::CipherMethod &method) {
        std::vector<std::uint8_t> iv(method.iv_size);
        if (!transport::proxy::random_bytes(iv)) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::authentication, "failed to generate Shadowsocks legacy IV"});
        }
        auto key =
            transport::proxy::derive_legacy_key(self->config_.method, self->config_.password, iv);
        auto address = detail::encode_proxy_address(self->request_.destination);
        if (!key || !address) {
            co_return core::StreamOpenResult::failed(!key ? key.error() : address.error());
        }
        auto cipher = transport::proxy::LegacyStreamCipher::create(self->config_.method,
                                                                   key.value(), iv, true);
        if (!cipher) {
            co_return core::StreamOpenResult::failed(cipher.error());
        }
        auto encrypted_address = std::move(address.value());
        if (const auto result = cipher.value().update(encrypted_address); !result) {
            co_return core::StreamOpenResult::failed(result.error());
        }
        iv.insert(iv.end(), encrypted_address.begin(), encrypted_address.end());
        auto wire = std::make_shared<std::vector<std::uint8_t>>(std::move(iv));
        if (self->websocket_plugin() && !self->config_.plugin_mux) {
            co_return co_await open_websocket_legacy(self, std::move(*wire),
                                                     std::move(cipher.value()));
        }
        if (const auto obfs = self->obfs_options(); obfs) {
            auto write_cipher =
                std::make_shared<transport::proxy::LegacyStreamCipher>(std::move(cipher.value()));
            core::Status obfs_result;
            try {
                if (obfs->mode == ss::ObfsMode::http) {
                    using Sigs = async::BridgeSignatures<core::Status>;
                    // NOTE: name the sender first; argument order is unspecified.
                    auto sender = async::callback_sender<Sigs>(
                        [self, wire](auto terminal) mutable -> async::CallbackAbortFn {
                            const auto options = self->obfs_options();
                            auto handle = ss::async_write_http_obfs_request_abortable(
                                self->socket_, std::move(*wire), {options->host, options->port},
                                std::move(terminal));
                            return async::CallbackAbortFn{[self, handle] {
                                self->abort();
                                if (handle) {
                                    handle->abort();
                                }
                            }};
                        },
                        [](auto receiver, core::Status result) {
                            stdexec::set_value(std::move(receiver), std::move(result));
                        });
                    obfs_result = co_await std::move(sender);
                } else {
                    using Sigs = async::BridgeSignatures<core::Status>;
                    // NOTE: name the sender first; argument order is unspecified.
                    auto sender = async::callback_sender<Sigs>(
                        [self, wire](auto terminal) mutable -> async::CallbackAbortFn {
                            const auto options = self->obfs_options();
                            auto handle = ss::async_write_tls_obfs_request_abortable(
                                self->socket_, std::move(*wire), options->host,
                                std::move(terminal));
                            return async::CallbackAbortFn{[self, handle] {
                                self->abort();
                                if (handle) {
                                    handle->abort();
                                }
                            }};
                        },
                        [](auto receiver, core::Status result) {
                            stdexec::set_value(std::move(receiver), std::move(result));
                        });
                    obfs_result = co_await std::move(sender);
                }
            } catch (...) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::transport_io, "Shadowsocks obfs request failed", {}});
            }
            if (self->completed_) {
                co_return core::StreamOpenResult::failed(
                    {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
            }
            if (!obfs_result) {
                co_return core::StreamOpenResult::failed(obfs_result.error());
            }
            auto stream = ss::make_legacy_stream_handle(self->socket_, self->config_.method,
                                                        self->config_.password,
                                                        std::move(*write_cipher), {}, obfs->mode);
            if (!stream) {
                co_return core::StreamOpenResult::failed(stream.error());
            }
            co_return core::StreamOpenResult::opened(std::move(stream.value()));
        }
        auto write_cipher =
            std::make_shared<transport::proxy::LegacyStreamCipher>(std::move(cipher.value()));
        try {
            if (self->carrier_) {
                co_await self->carrier_->async_write(boost::asio::buffer(*wire));
            } else {
                co_await (boost::asio::async_write(*self->socket_, boost::asio::buffer(*wire),
                                                   exec::asio::use_sender) |
                          stdexec::then([](std::size_t) {}) |
                          stdexec::let_error([](std::exception_ptr error) {
                              try {
                                  std::rethrow_exception(std::move(error));
                              } catch (const boost::system::system_error &failure) {
                                  return stdexec::just_error(std::make_exception_ptr(
                                      core::Error{core::ErrorCode::transport_io,
                                                  "failed to write Shadowsocks legacy request",
                                                  detail::to_std_error(failure.code())}));
                              }
                              std::rethrow_exception(std::current_exception());
                          }));
            }
        } catch (const core::Error &failure) {
            co_return core::StreamOpenResult::failed(
                {failure.code, "failed to write Shadowsocks legacy request", failure.cause});
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "failed to write Shadowsocks legacy request", {}});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        auto stream =
            self->carrier_
                ? ss::make_legacy_stream_handle(self->carrier_, self->config_.method,
                                                self->config_.password, std::move(*write_cipher))
                : ss::make_legacy_stream_handle(self->socket_, self->config_.method,
                                                self->config_.password, std::move(*write_cipher));
        if (!stream) {
            co_return core::StreamOpenResult::failed(stream.error());
        }
        co_return core::StreamOpenResult::opened(std::move(stream.value()));
    }

    static stdexec::task<core::StreamOpenResult>
    open_websocket_legacy(std::shared_ptr<ShadowsocksConnectOperation> self,
                          std::vector<std::uint8_t> wire,
                          transport::proxy::LegacyStreamCipher write_cipher) {
        auto cipher =
            std::make_shared<transport::proxy::LegacyStreamCipher>(std::move(write_cipher));
        auto stream =
            std::make_shared<std::unique_ptr<io::StreamHandle>>(self->take_connected_stream());
        core::Result<std::unique_ptr<io::StreamHandle>> plugin;
        try {
            using Sigs = async::BridgeSignatures<core::Result<std::unique_ptr<io::StreamHandle>>>;
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = async::callback_sender<Sigs>(
                [self, stream](auto terminal) mutable -> async::CallbackAbortFn {
                    auto handle = ss::async_open_websocket_plugin(
                        std::move(*stream), self->websocket_options(), std::move(terminal));
                    return async::CallbackAbortFn{[self, handle] {
                        self->abort();
                        if (handle) {
                            handle->cancel();
                        }
                    }};
                },
                [](auto receiver, core::Result<std::unique_ptr<io::StreamHandle>> opened) {
                    stdexec::set_value(std::move(receiver), std::move(opened));
                });
            plugin = co_await std::move(sender);
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "WebSocket plugin open failed", {}});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        if (!plugin) {
            co_return core::StreamOpenResult::failed(plugin.error());
        }
        self->carrier_ = std::make_shared<ss::StreamCarrier>(std::move(plugin.value()));
        auto shared_wire = std::make_shared<std::vector<std::uint8_t>>(std::move(wire));
        try {
            co_await self->carrier_->async_write(boost::asio::buffer(*shared_wire));
        } catch (const core::Error &failure) {
            co_return core::StreamOpenResult::failed(
                {failure.code, "failed to write Shadowsocks WebSocket request", failure.cause});
        } catch (...) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io,
                 "failed to write Shadowsocks WebSocket request",
                 {}});
        }
        if (self->completed_) {
            co_return core::StreamOpenResult::failed(
                {core::ErrorCode::cancelled, "Shadowsocks connect cancelled"});
        }
        auto stream_handle = ss::make_legacy_stream_handle(
            self->carrier_, self->config_.method, self->config_.password, std::move(*cipher));
        if (!stream_handle) {
            co_return core::StreamOpenResult::failed(stream_handle.error());
        }
        co_return core::StreamOpenResult::opened(std::move(stream_handle.value()));
    }

  public:
    // Abort for sender-driven cancellation: posted to the strand so it stays
    // ordered with finish(). The bridge drops the late terminal. The
    // timed-out race loser is retired by finish()'s completed_ guard;
    // with_timeout owns its sleep timer and cancels both branches on
    // outer stop.
    void abort() noexcept {
        auto self = shared_from_this();
        try {
            boost::asio::post(socket_->get_executor(), [self]() {
                if (self->completed_) {
                    return;
                }
                boost::system::error_code ignored;
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
    OutboundRegistry::Snapshot chain_registry_;
    std::shared_ptr<ss::KcptunClientPool> kcptun_pool_;
    std::shared_ptr<ss::WebSocketPluginMuxPool> websocket_mux_pool_;
    ShadowsocksOutboundConfig config_;
    core::StreamRequest request_;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::shared_ptr<ss::StreamCarrier> carrier_;
    // Chained transport when dialer_proxy is set: the chain delivers a
    // ready StreamHandle instead of a raw socket.
    std::unique_ptr<io::StreamHandle> chained_transport_;
    // ECH config bytes resolved once per connect for the WebSocket plugin
    // TLS layer; injected into every plugin open via websocket_options().
    std::optional<std::vector<std::uint8_t>> plugin_ech_config_;
    core::StreamOpenHandler handler_;
    std::vector<std::uint8_t> write_nonce_;
    bool completed_ = false;
    // No member scope: guarded connect task runs detached (immortal heap
    // scope) so the last operation reference cannot free its scope (#194).
};

class ShadowsocksDatagramHandle final : public io::DatagramHandle {
  public:
    struct State : std::enable_shared_from_this<State> {
        using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t,
                                               io::DatagramAddress)>;
        using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
        using ReadTerminal = ReadHandler;
        using WriteTerminal = WriteHandler;

        // Single datagram send as one task co_awaiting the transport
        // sender directly; teardown stays guard-driven via abort.
        // NOTE: named function per the coroutine creation rules; never an
        // immediately-invoked capturing lambda.
        static stdexec::task<void> run_send(std::shared_ptr<State> self,
                                            std::shared_ptr<std::vector<std::uint8_t>> packet,
                                            std::size_t plaintext_size, WriteTerminal done) {
            try {
                // NOTE: name the sender first; argument order is unspecified.
                auto sender = self->transport_->async_send_to(
                    boost::asio::buffer(*packet), io::DatagramAddress::from_endpoint(self->server));
                co_await std::move(sender);
            } catch (...) {
                self->send_in_progress = false;
                done(net::unpack_error(std::current_exception()), 0);
                co_return;
            }
            self->send_in_progress = false;
            done({}, plaintext_size);
        }

        State(std::shared_ptr<io::DatagramHandle> link, boost::asio::ip::udp::endpoint server,
              std::string method, std::string password)
            : transport_(std::move(link)), server(std::move(server)), method(std::move(method)),
              password(std::move(password)) {
            const auto method_info = transport::proxy::cipher_method(this->method);
            if (method_info && method_info.value().shadowsocks_2022) {
                ss2022_codec = std::make_unique<ss::Shadowsocks2022DatagramCodec>(this->method,
                                                                                  this->password);
            }
        }

        void send(boost::asio::const_buffer buffer, io::DatagramAddress destination,
                  WriteHandler handler) {
            if (send_in_progress) {
                boost::asio::post(transport_->executor(), [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::already_started, 0);
                });
                return;
            }
            const auto target = destination.to_destination();
            auto address = detail::encode_proxy_address(detail::to_core_destination(target));
            const auto method_info = transport::proxy::cipher_method(method);
            if (!address || !method_info) {
                boost::asio::post(transport_->executor(), [handler = std::move(handler)]() mutable {
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
                    boost::asio::post(transport_->executor(),
                                      [handler = std::move(handler)]() mutable {
                                          handler(boost::asio::error::message_size, 0);
                                      });
                    return;
                }
                auto packet = std::make_shared<std::vector<std::uint8_t>>(std::move(wire.value()));
                auto self = shared_from_this();
                self->send_in_progress = true;
                self->send_handler = std::move(handler);
                WriteTerminal done{std::move(self->send_handler)};
                // Detached (immortal heap scope): the last State reference
                // cannot free a member scope_ (#194).
                async::spawn_detached(run_send(self, packet, payload_size, std::move(done)));
                return;
            }
            std::vector<std::uint8_t> plaintext = std::move(address.value());
            plaintext.insert(plaintext.end(), payload, payload + payload_size);
            auto encoded = ss::encrypt_aead_datagram(method, password, plaintext);
            if (!encoded || encoded.value().size() > kMaxEncryptedUdpDatagramSize) {
                boost::asio::post(transport_->executor(), [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::message_size, 0);
                });
                return;
            }
            auto wire = std::make_shared<std::vector<std::uint8_t>>(std::move(encoded.value()));
            auto self = shared_from_this();
            self->send_in_progress = true;
            self->send_handler = std::move(handler);
            WriteTerminal done{std::move(self->send_handler)};
            // Detached (immortal heap scope): the last State reference
            // cannot free a member scope_ (#194).
            async::spawn_detached(run_send(self, wire, payload_size, std::move(done)));
        }

        void receive(boost::asio::mutable_buffer buffer, ReadHandler handler) {
            if (receive_in_progress) {
                boost::asio::post(transport_->executor(), [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::already_started, 0, {});
                });
                return;
            }
            receive_in_progress = true;
            output_buffer = buffer;
            receive_handler = std::move(handler);
            receive_next();
        }

        // Single-pull receive loop as one task: keep pulling from the
        // transport (dropping off-server packets) until a decodable
        // datagram lands in the caller's buffer. Co_awaits the transport
        // sender directly instead of bridging back into a handler.
        // NOTE: named function per the coroutine creation rules; never an
        // immediately-invoked capturing lambda.
        static stdexec::task<void> run_receive(std::shared_ptr<State> self, ReadTerminal done) {
            for (;;) {
                io::DatagramPacket raw;
                try {
                    // NOTE: name the sender first; argument order is unspecified.
                    auto receiver = self->transport_->async_receive_from(
                        boost::asio::buffer(self->receive_buffer));
                    raw = co_await std::move(receiver);
                } catch (...) {
                    self->receive_in_progress = false;
                    done(net::unpack_error(std::current_exception()), 0, {});
                    co_return;
                }
                // Chained relays report the ultimate sender rather than the
                // Shadowsocks server; the chain is point-to-point and the
                // AEAD layers still authenticate every packet.
                if (self->filter_server_endpoint &&
                    (!raw.address.is_address() || raw.address.address() != self->server.address() ||
                     raw.address.port() != self->server.port())) {
                    continue;
                }
                self->decode_response(raw.size);
                co_return;
            }
        }

        void receive_next() {
            ReadTerminal done{std::move(receive_handler)};
            // Detached (immortal heap scope): the last State reference
            // cannot free a member scope_ (#194).
            async::spawn_detached(run_receive(shared_from_this(), std::move(done)));
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
                complete_payload(plaintext, payload_offset, payload_size,
                                 io::DatagramAddress::address(address.value().destination.address(),
                                                              address.value().destination.port()));
                return;
            }
            complete_payload(plaintext, payload_offset, payload_size,
                             io::DatagramAddress::domain(address.value().destination.domain(),
                                                         address.value().destination.port()));
        }

        void complete_payload(const std::vector<std::uint8_t> &plaintext, std::size_t offset,
                              std::size_t size, io::DatagramAddress sender) {
            if (size > output_buffer.size()) {
                finish_receive(boost::asio::error::message_size, 0, {});
                return;
            }
            if (size != 0) {
                std::memcpy(output_buffer.data(), plaintext.data() + offset, size);
            }
            finish_receive({}, size, std::move(sender));
        }

        void finish_send(const boost::system::error_code &error, std::size_t size) {
            send_in_progress = false;
            auto handler = std::move(send_handler);
            if (!handler) {
                // Late lower completion after cancel_send retired the op.
                return;
            }
            handler(error, size);
        }

        void finish_receive(const boost::system::error_code &error, std::size_t size,
                            io::DatagramAddress sender) {
            receive_in_progress = false;
            auto handler = std::move(receive_handler);
            output_buffer = {};
            if (!handler) {
                // Late lower completion after cancel_receive retired the op.
                return;
            }
            handler(error, size, std::move(sender));
        }

        // Retires a parked receive without closing the transport. Dispatched
        // to the transport executor because the parked state is
        // strand-private. The lower receive (if any) stays in flight; its
        // late completion finds no parked handler and is dropped.
        void cancel_receive() noexcept {
            try {
                auto self = shared_from_this();
                boost::asio::dispatch(transport_->executor(), [self] {
                    auto handler = std::move(self->receive_handler);
                    if (!handler) {
                        return;
                    }
                    self->output_buffer = {};
                    self->receive_in_progress = false;
                    boost::asio::post(self->transport_->executor(),
                                      [handler = std::move(handler)]() mutable {
                                          handler(boost::asio::error::operation_aborted, 0, {});
                                      });
                });
            } catch (...) {
                // Aborter contract: never throw; the late lower completion or
                // close() retires the parked handler instead.
            }
        }

        // Retires a parked send without closing the transport. Dispatched
        // to the transport executor because the parked state is
        // strand-private. The lower send (if any) stays in flight; its
        // late completion finds no parked handler and is dropped.
        void cancel_send() noexcept {
            try {
                auto self = shared_from_this();
                boost::asio::dispatch(transport_->executor(), [self] {
                    auto handler = std::move(self->send_handler);
                    if (!handler) {
                        return;
                    }
                    self->send_in_progress = false;
                    boost::asio::post(self->transport_->executor(),
                                      [handler = std::move(handler)]() mutable {
                                          handler(boost::asio::error::operation_aborted, 0);
                                      });
                });
            } catch (...) {
                // Aborter contract: never throw; the late lower completion or
                // close() retires the parked handler instead.
            }
        }

        void close() noexcept { transport_->close(); }

        std::size_t max_datagram_size() const noexcept {
            if (ss2022_codec) {
                return std::min<std::size_t>(
                    ss2022_codec->max_datagram_size(kMaxEncryptedUdpDatagramSize,
                                                    kMaxProxyAddressSize),
                    kMaxUdpWireSize);
            }
            const auto spec = transport::proxy::cipher_method(method);
            if (!spec) {
                return 0;
            }
            return std::min<std::size_t>(
                ss::aead_datagram_payload_limit(method, kMaxEncryptedUdpDatagramSize,
                                                kMaxProxyAddressSize),
                kMaxUdpWireSize);
        }

        std::shared_ptr<io::DatagramHandle> transport_;
        boost::asio::ip::udp::endpoint server;
        // Drop packets whose source is not the server. Disabled for chained
        // transports, which report the ultimate sender instead.
        bool filter_server_endpoint = true;
        std::string method;
        std::string password;
        std::unique_ptr<ss::Shadowsocks2022DatagramCodec> ss2022_codec;
        std::array<std::uint8_t, kMaxUdpWireSize> receive_buffer{};
        boost::asio::mutable_buffer output_buffer;
        ReadHandler receive_handler;
        WriteHandler send_handler;
        bool receive_in_progress = false;
        bool send_in_progress = false;
        // No member scope: send/receive chain tasks run detached (immortal
        // heap scope) so the last State reference cannot free its scope
        // (#194). Teardown stays guard-driven via cancel_send/receive.
    };

  public:
    explicit ShadowsocksDatagramHandle(std::shared_ptr<State> state) : state_(std::move(state)) {}
    io::AnySender<std::size_t> async_send_to(boost::asio::const_buffer buffer,
                                             io::DatagramAddress destination) override {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        return io::AnySender<std::size_t>{async::callback_sender<Signatures>(
            [state = state_, buffer, destination](auto terminal) mutable {
                state->send(buffer, std::move(destination), std::move(terminal));
                return async::CallbackAbortFn{[state] { state->cancel_send(); }};
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
                    std::make_exception_ptr(core::Error{
                        core::ErrorCode::transport_io, "shadowsocks datagram send failed", error}));
            })};
    }

    io::AnySender<io::DatagramPacket>
    async_receive_from(boost::asio::mutable_buffer buffer) override {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(io::DatagramPacket),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        return io::AnySender<io::DatagramPacket>{async::callback_sender<Signatures>(
            [state = state_, buffer](auto terminal) mutable {
                state->receive(buffer, [terminal = std::move(terminal)](
                                           const boost::system::error_code &error, std::size_t size,
                                           io::DatagramAddress source) mutable {
                    terminal(error, size, std::move(source));
                });
                return async::CallbackAbortFn{[state] { state->cancel_receive(); }};
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
                stdexec::set_error(std::move(receiver),
                                   std::make_exception_ptr(
                                       core::Error{core::ErrorCode::transport_io,
                                                   "shadowsocks datagram receive failed", error}));
            })};
    }

    boost::asio::any_io_executor executor() noexcept override {
        return state_->transport_->executor();
    }

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
    if (!config_.udp_enabled) {
        capabilities_.datagram = core::DatagramSemantics::unsupported;
    }
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
    const auto method = transport::proxy::cipher_method(config_.method);
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
    auto chain_registry = chain_registry_;
    auto kcptun_pool = kcptun_pool_;
    auto websocket_mux_pool = websocket_mux_pool_;
    auto config = config_;
    return async::callback_sender<async::BridgeSignatures<core::StreamOpenResult>>(
        [&runtime, resolver = std::move(resolver), chain_registry = std::move(chain_registry),
         kcptun_pool = std::move(kcptun_pool), websocket_mux_pool = std::move(websocket_mux_pool),
         config = std::move(config), request = std::move(request)](
            async::BridgeHandler<core::StreamOpenResult> terminal) mutable {
            auto operation = std::make_shared<ShadowsocksConnectOperation>(
                runtime, std::move(resolver), std::move(chain_registry), std::move(kcptun_pool),
                std::move(websocket_mux_pool), std::move(config), std::move(request),
                std::move(terminal));
            operation->start();
            return async::CallbackAbortFn{[operation] { operation->abort(); }};
        },
        async::BridgeTranslate<core::StreamOpenResult>{});
}

// Chained native-UDP open as one task: co_await the chained datagram
// sender directly and layer the cipher session on the chain's handle.
// Stream-kind (legacy) ciphers stay socket-bound and cannot chain.
// NOTE: named function per the coroutine creation rules; never an
// immediately-invoked capturing lambda.
stdexec::task<core::DatagramOpenResult>
open_chained_datagram_task(runtime::AsioRuntime &runtime, transport::EndpointDialPlan plan,
                           ShadowsocksOutboundConfig config,
                           std::shared_ptr<const core::EndpointDialTrace> trace,
                           boost::asio::ip::udp::endpoint server) {
    boost::system::error_code ignored;
    const auto numeric = boost::asio::ip::make_address(config.server_host, ignored);
    core::Destination destination =
        ignored ? core::Destination::domain(config.server_host, config.server_port)
                : core::Destination::address(numeric, config.server_port);
    core::DatagramRequest chained_request{std::move(destination), std::move(trace)};
    core::DatagramOpenResult result;
    try {
        transport::EndpointDialer dialer(runtime.serialized_executor(), std::move(plan));
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = dialer.open_datagram(std::move(chained_request));
        result = co_await std::move(sender);
    } catch (const core::Error &failure) {
        co_return core::DatagramOpenResult::failed(failure);
    } catch (...) {
        co_return core::DatagramOpenResult::failed(
            {core::ErrorCode::endpoint_connection, "chained datagram open failed", {}});
    }
    if (result.status != core::OpenStatus::opened || !result.handle) {
        if (result.error) {
            co_return core::DatagramOpenResult::failed(result.error.value());
        }
        co_return core::DatagramOpenResult::failed(
            {core::ErrorCode::endpoint_connection, "chained datagram open failed", {}});
    }
    std::shared_ptr<io::DatagramHandle> link{std::move(result.handle)};
    auto state = std::make_shared<ShadowsocksDatagramHandle::State>(std::move(link), server,
                                                                    config.method, config.password);
    state->filter_server_endpoint = false;
    co_return core::DatagramOpenResult::opened(
        std::make_unique<ShadowsocksDatagramHandle>(std::move(state)),
        core::DatagramSemantics::multi_destination);
}

// Opens native UDP through the dialer_proxy chain: the chain delivers a
// DatagramHandle relaying the server, wrapped in the usual cipher session.
// Stream-kind (legacy) ciphers stay socket-bound and cannot chain.
stdexec::task<core::DatagramOpenResult>
open_chained_datagram(runtime::AsioRuntime &runtime, std::shared_ptr<dns::ResolverService> resolver,
                      OutboundRegistry::Snapshot registry, ShadowsocksOutboundConfig config,
                      core::DatagramRequest request) {
    if (!registry) {
        co_return core::DatagramOpenResult::failed(
            {core::ErrorCode::configuration,
             "Shadowsocks dialer-proxy requires a chain registry",
             {}});
    }
    const auto trace = transport::extend_endpoint_trace(request.dial_trace, config.id);
    if (!trace) {
        co_return core::DatagramOpenResult::failed(trace.error());
    }
    const transport::EndpointDialRequirements requirements{false, true};
    const auto plan =
        transport::EndpointDialPlan::from_registry(registry, config.dialer_proxy, requirements);
    if (!plan) {
        co_return core::DatagramOpenResult::failed(plan.error());
    }
    const auto method = transport::proxy::cipher_method(config.method);
    if (!method) {
        co_return core::DatagramOpenResult::failed(method.error());
    }
    if (method.value().kind == transport::proxy::CipherKind::stream) {
        co_return core::DatagramOpenResult::failed(
            {core::ErrorCode::unsupported,
             "Shadowsocks dialer-proxy cannot chain legacy stream-cipher UDP",
             {}});
    }
    // The server endpoint feeds the sender filter; routing itself stays
    // with the chain. Numeric literals skip the resolver outright.
    boost::system::error_code numeric_error;
    const auto numeric_host = boost::asio::ip::make_address(config.server_host, numeric_error);
    if (!numeric_error) {
        co_return co_await open_chained_datagram_task(
            runtime, std::move(plan.value()), std::move(config), trace.value(),
            boost::asio::ip::udp::endpoint(numeric_host, config.server_port));
    }
    core::Result<detail::AddressList> resolved;
    try {
        resolved =
            co_await detail::resolve_host_sender(runtime, std::move(resolver), config.server_host);
    } catch (...) {
        co_return core::DatagramOpenResult::failed(
            {core::ErrorCode::resolution, "failed to resolve Shadowsocks server", {}});
    }
    if (!resolved || resolved.value().empty()) {
        co_return core::DatagramOpenResult::failed(
            resolved ? core::Error{core::ErrorCode::resolution,
                                   "Shadowsocks server hostname resolved to no addresses"}
                     : resolved.error());
    }
    co_return co_await open_chained_datagram_task(
        runtime, std::move(plan.value()), std::move(config), std::move(trace.value()),
        boost::asio::ip::udp::endpoint(resolved.value().front(), config.server_port));
}

// Drives one datagram open task to a bridge terminal: every terminal
// funnels through done, so the spawned task always ends with a value.
// NOTE: named function per the coroutine creation rules; never an
// immediately-invoked capturing lambda.
stdexec::task<void> run_datagram_task(stdexec::task<core::DatagramOpenResult> task,
                                      async::BridgeHandler<core::DatagramOpenResult> done) {
    try {
        done(co_await std::move(task));
    } catch (const core::Error &failure) {
        done(core::DatagramOpenResult::failed(failure));
    } catch (...) {
        done(core::DatagramOpenResult::failed(
            {core::ErrorCode::transport_io, "Shadowsocks datagram open failed", {}}));
    }
}

// UDP-over-TCP (or kcptun) datagram open as one task: co_await the
// connect-operation bridge for the TCP carrier, then wrap it in the UoT
// datagram handle. Stop aborts via the operation abort.
// NOTE: named function per the coroutine creation rules; never an
// immediately-invoked capturing lambda.
stdexec::task<core::DatagramOpenResult> open_uot_datagram_task(
    runtime::AsioRuntime &runtime, std::shared_ptr<dns::ResolverService> resolver,
    OutboundRegistry::Snapshot chain_registry, std::shared_ptr<ss::KcptunClientPool> kcptun_pool,
    std::shared_ptr<ss::WebSocketPluginMuxPool> websocket_mux_pool,
    ShadowsocksOutboundConfig config, core::DatagramRequest request) {
    const auto version = config.udp_over_tcp_version;
    const auto magic = version == 2 ? kUdpOverTcpV2MagicAddress : kUdpOverTcpMagicAddress;
    core::StreamRequest stream_request{core::Destination::domain(std::string(magic), 0),
                                       std::nullopt, request.dial_trace};
    core::StreamOpenResult stream_result;
    try {
        using Sigs = async::BridgeSignatures<core::StreamOpenResult>;
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = async::callback_sender<Sigs>(
            [&runtime, resolver, chain_registry, kcptun_pool, websocket_mux_pool, config,
             stream_request =
                 std::move(stream_request)](auto terminal) mutable -> async::CallbackAbortFn {
                auto operation = std::make_shared<ShadowsocksConnectOperation>(
                    runtime, std::move(resolver), std::move(chain_registry), std::move(kcptun_pool),
                    std::move(websocket_mux_pool), std::move(config), std::move(stream_request),
                    std::move(terminal));
                operation->start();
                return async::CallbackAbortFn{[operation] { operation->abort(); }};
            },
            [](auto receiver, core::StreamOpenResult result) {
                stdexec::set_value(std::move(receiver), std::move(result));
            });
        stream_result = co_await std::move(sender);
    } catch (...) {
        co_return core::DatagramOpenResult::failed(
            {core::ErrorCode::transport_io, "failed to open Shadowsocks UoT stream", {}});
    }
    if (!stream_result.succeeded()) {
        co_return core::DatagramOpenResult::failed(stream_result.error.value_or(
            core::Error{core::ErrorCode::transport_io, "failed to open Shadowsocks UoT stream"}));
    }
    const auto request_destination = version == 2 ? request.initial_destination : std::nullopt;
    auto datagram = ss::make_udp_over_tcp_datagram_handle(
        std::move(stream_result.handle),
        {version == 2 ? ss::UdpOverTcpVersion::version2 : ss::UdpOverTcpVersion::legacy,
         request_destination});
    if (!datagram) {
        co_return core::DatagramOpenResult::failed(datagram.error());
    }
    co_return core::DatagramOpenResult::opened(std::move(datagram.value()),
                                               core::DatagramSemantics::multi_destination);
}

// Native UDP datagram open as one task: co_await the resolve sender,
// then build the cipher session synchronously on a bound socket.
// NOTE: named function per the coroutine creation rules; never an
// immediately-invoked capturing lambda.
stdexec::task<core::DatagramOpenResult>
open_native_datagram_task(runtime::AsioRuntime &runtime,
                          std::shared_ptr<dns::ResolverService> resolver,
                          ShadowsocksOutboundConfig config) {
    core::Result<detail::AddressList> resolved;
    try {
        resolved =
            co_await detail::resolve_host_sender(runtime, std::move(resolver), config.server_host);
    } catch (...) {
        co_return core::DatagramOpenResult::failed(
            {core::ErrorCode::resolution, "failed to resolve Shadowsocks server", {}});
    }
    if (!resolved || resolved.value().empty()) {
        co_return core::DatagramOpenResult::failed(
            resolved ? core::Error{core::ErrorCode::resolution,
                                   "Shadowsocks server hostname resolved to no addresses"}
                     : resolved.error());
    }
    const auto server =
        boost::asio::ip::udp::endpoint(resolved.value().front(), config.server_port);
    auto socket = std::make_shared<net::UdpStream>(runtime.serialized_executor());
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
        co_return core::DatagramOpenResult::failed({core::ErrorCode::transport_io,
                                                    "failed to open Shadowsocks UDP socket",
                                                    detail::to_std_error(error)});
    }
    const auto method = transport::proxy::cipher_method(config.method);
    if (!method) {
        co_return core::DatagramOpenResult::failed(method.error());
    }
    if (method.value().kind == transport::proxy::CipherKind::stream) {
        auto handle = detail::make_legacy_shadowsocks_datagram_handle(
            std::move(socket), server, config.method, config.password);
        if (!handle) {
            co_return core::DatagramOpenResult::failed(handle.error());
        }
        co_return core::DatagramOpenResult::opened(std::move(handle.value()),
                                                   core::DatagramSemantics::multi_destination);
    }
    auto state = std::make_shared<ShadowsocksDatagramHandle::State>(std::move(socket), server,
                                                                    config.method, config.password);
    co_return core::DatagramOpenResult::opened(
        std::make_unique<ShadowsocksDatagramHandle>(std::move(state)),
        core::DatagramSemantics::multi_destination);
}

io::AnySender<core::DatagramOpenResult>
ShadowsocksOutbound::open_datagram(core::DatagramRequest request) {
    using ResultSender = io::AnySender<core::DatagramOpenResult>;
    if (!config_.udp_enabled) {
        return ResultSender{stdexec::just(core::DatagramOpenResult::failed(
            {core::ErrorCode::configuration, "Shadowsocks outbound UDP is disabled"}))};
    }
    if (const auto validation = validate(); !validation) {
        return ResultSender{stdexec::just(core::DatagramOpenResult::failed(validation.error()))};
    }
    // Each datagram branch runs as one task (chained / UoT / native);
    // the bridge only adapts the task result into a sender with a real
    // aborter. Only values are captured: the outbound itself may die
    // before the open completes.
    // Native UDP through the dialer_proxy chain (UDP-over-TCP rides the
    // chained TCP carrier via the branch below).
    if (!config_.dialer_proxy.empty() && !config_.udp_over_tcp && config_.plugin != "kcptun") {
        auto &runtime = runtime_;
        auto resolver = resolver_;
        auto chain_registry = chain_registry_;
        auto config = config_;
        auto chained_request = request;
        // Heap scope owned by the starter (not the outbound): run_datagram_task
        // funnels every terminal through done, so the task always ends with a
        // value. The aborter stops the scope so the open awaits settle
        // promptly; the late terminal then drops at the first-wins guard.
        struct Shared {
            exec::async_scope scope;
        };
        auto shared = std::make_shared<Shared>();
        return async::callback_sender<async::BridgeSignatures<core::DatagramOpenResult>>(
            [&runtime, shared, resolver = std::move(resolver),
             chain_registry = std::move(chain_registry), config = std::move(config),
             request = std::move(chained_request)](
                async::BridgeHandler<core::DatagramOpenResult> terminal) mutable {
                shared->scope.spawn(run_datagram_task(
                    open_chained_datagram(runtime, std::move(resolver), std::move(chain_registry),
                                          std::move(config), std::move(request)),
                    std::move(terminal)));
                return async::CallbackAbortFn{[shared] { shared->scope.request_stop(); }};
            },
            async::BridgeTranslate<core::DatagramOpenResult>{});
    }
    auto &runtime = runtime_;
    auto resolver = resolver_;
    auto chain_registry = chain_registry_;
    auto kcptun_pool = kcptun_pool_;
    auto websocket_mux_pool = websocket_mux_pool_;
    auto config = config_;
    // Heap scope owned by the starter (not the outbound): the open task
    // funnels every terminal through done, so the task always ends with a
    // value. The aborter stops the scope so the open awaits settle promptly;
    // the late terminal then drops at the first-wins guard.
    struct Shared {
        exec::async_scope scope;
    };
    auto shared = std::make_shared<Shared>();
    return async::callback_sender<async::BridgeSignatures<core::DatagramOpenResult>>(
        [&runtime, shared, resolver = std::move(resolver),
         chain_registry = std::move(chain_registry), kcptun_pool = std::move(kcptun_pool),
         websocket_mux_pool = std::move(websocket_mux_pool), config = std::move(config),
         request =
             std::move(request)](async::BridgeHandler<core::DatagramOpenResult> terminal) mutable {
            stdexec::task<core::DatagramOpenResult> task =
                (config.udp_over_tcp || config.plugin == "kcptun")
                    ? open_uot_datagram_task(runtime, std::move(resolver),
                                             std::move(chain_registry), std::move(kcptun_pool),
                                             std::move(websocket_mux_pool), std::move(config),
                                             std::move(request))
                    : open_native_datagram_task(runtime, std::move(resolver), std::move(config));
            shared->scope.spawn(run_datagram_task(std::move(task), std::move(terminal)));
            return async::CallbackAbortFn{[shared] { shared->scope.request_stop(); }};
        },
        async::BridgeTranslate<core::DatagramOpenResult>{});
}

} // namespace clash_native::outbound
