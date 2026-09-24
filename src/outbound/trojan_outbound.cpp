#include <clash_native/async/bridge.hpp>
#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>

#include <clash_native/core/base64.hpp>
#include <clash_native/dns/ech_resolver.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/outbound/trojan_outbound.hpp>
#include <clash_native/transport/http_sessions.hpp>
#include <clash_native/transport/proxy/crypto.hpp>
#include <clash_native/transport/tls_client.hpp>
#include <clash_native/transport/trojan/packet_conn.hpp>
#include <clash_native/transport/trojan/ss_stream.hpp>
#include <exec/asio/use_sender.hpp>

#include "outbound_utils.hpp"
#include "proxy_address.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::outbound {

namespace {

constexpr auto kConnectTimeout = std::chrono::seconds(15);

// Resolves ECH configs for the TLS handshake (Mihomo ech-opts): a static
// base64 ECHConfigList, or an HTTPS-record lookup with an optional
// query-server-name override. DNS failure fails closed: silently dropping
// ECH would leak the SNI the user asked to encrypt.
// NOTE: named function per the coroutine creation rules; never an
// immediately-invoked capturing lambda.
exec::task<core::Result<std::vector<std::uint8_t>>>
fetch_trojan_ech_config(std::shared_ptr<dns::ResolverService> resolver,
                        const TrojanOutboundConfig &config, const std::string &server_name) {
    if (!config.ech_config.empty()) {
        const auto decoded = core::base64_decode(config.ech_config);
        if (!decoded || decoded->empty()) {
            co_return core::fail(core::Error{core::ErrorCode::configuration,
                                             "Trojan ECH config is not valid base64"});
        }
        co_return core::Result<std::vector<std::uint8_t>>{
            std::vector<std::uint8_t>(decoded->begin(), decoded->end())};
    }
    std::optional<std::string> query_name;
    if (!config.ech_query_server_name.empty()) {
        query_name = config.ech_query_server_name;
    }
    core::Result<std::vector<std::uint8_t>> ech;
    try {
        ech = co_await dns::async_query_ech_config(resolver->query_service(), server_name,
                                                   std::move(query_name));
    } catch (const core::Error &failure) {
        co_return core::fail(failure);
    } catch (...) {
        co_return core::fail(core::Error{core::ErrorCode::endpoint_connection,
                                         "failed to resolve Trojan ECH config"});
    }
    if (!ech) {
        co_return core::fail(ech.error());
    }
    co_return core::Result<std::vector<std::uint8_t>>{std::move(ech.value())};
}

core::Result<std::string> trojan_password_key(std::string_view password) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    if (EVP_Digest(password.data(), password.size(), digest.data(), &digest_size, EVP_sha224(),
                   nullptr) != 1 ||
        digest_size != 28) {
        return core::fail({core::ErrorCode::authentication, "failed to hash Trojan password"});
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string key;
    key.reserve(digest_size * 2);
    for (unsigned int index = 0; index < digest_size; ++index) {
        key.push_back(digits[digest[index] >> 4]);
        key.push_back(digits[digest[index] & 0x0f]);
    }
    return key;
}

std::error_code to_std_error(const boost::system::error_code &error) {
    return {error.value(), std::system_category()};
}

core::Result<std::vector<std::uint8_t>> build_request_header(const TrojanOutboundConfig &config,
                                                             const core::Destination &destination,
                                                             std::uint8_t command) {
    const auto password_key = trojan_password_key(config.password);
    const auto address = detail::encode_proxy_address(destination);
    if (!password_key || !address) {
        return core::fail(!password_key ? password_key.error() : address.error());
    }
    std::vector<std::uint8_t> wire;
    wire.reserve(password_key.value().size() + address.value().size() + 5);
    wire.insert(wire.end(), password_key.value().begin(), password_key.value().end());
    wire.push_back('\r');
    wire.push_back('\n');
    wire.push_back(command);
    wire.insert(wire.end(), address.value().begin(), address.value().end());
    wire.push_back('\r');
    wire.push_back('\n');
    return wire;
}

// gRPC Transport session: resolve, TCP connect, TLS with enforced h2 ALPN,
// then an HTTP/2 exchange session. Named-function task spawned directly
// into a scope (the run() shape); every terminal funnels through done.
struct GrpcSessionOpen {
    using SessionResult = core::Result<std::shared_ptr<io::ExchangeSession>>;
    using SessionHandler = async::BridgeSender<SessionResult>::Handler;
    static exec::task<void> run(runtime::AsioRuntime *runtime,
                                std::shared_ptr<dns::ResolverService> resolver,
                                TrojanOutboundConfig config, SessionHandler done) {
        const auto deadline = std::chrono::steady_clock::now() + kConnectTimeout;
        auto socket =
            std::make_shared<boost::asio::ip::tcp::socket>(runtime->serialized_executor());
        auto finish = [done = std::move(done), socket](SessionResult result) mutable {
            if (!result && socket) {
                boost::system::error_code ignored;
                socket->cancel(ignored);
                socket->close(ignored);
            }
            done(std::move(result));
        };
        auto addresses = co_await async::bridge_sender<core::Result<detail::AddressList>>(
            [runtime, resolver = std::move(resolver), host = config.server_host](
                async::BridgeSender<core::Result<detail::AddressList>>::Handler open) mutable {
                // The bridge starter must be copyable: resolve_host takes
                // its handler by value, so the lambda already copies.
                detail::resolve_host(*runtime, std::move(resolver), std::move(host),
                                     [open](core::Result<detail::AddressList> result) mutable {
                                         open(std::move(result));
                                     });
                using AbortFn = async::BridgeSender<core::Result<detail::AddressList>>::AbortFn;
                return AbortFn{[] {}};
            });
        if (!addresses || addresses.value().empty()) {
            finish(!addresses ? core::fail(addresses.error())
                              : core::fail(core::Error{core::ErrorCode::resolution,
                                                       "Trojan gRPC server hostname resolved to "
                                                       "no addresses"}));
            co_return;
        }
        auto endpoints = std::make_shared<std::vector<boost::asio::ip::tcp::endpoint>>();
        for (const auto &address : addresses.value()) {
            endpoints->emplace_back(address, config.server_port);
        }
        try {
            co_await (boost::asio::async_connect(*socket, *endpoints, exec::asio::use_sender) |
                      stdexec::then([](const boost::asio::ip::tcp::endpoint &) {}) |
                      stdexec::let_error([](std::exception_ptr error) {
                          try {
                              std::rethrow_exception(std::move(error));
                          } catch (const boost::system::system_error &failure) {
                              return stdexec::just_error(std::make_exception_ptr(
                                  core::Error{core::ErrorCode::endpoint_connection,
                                              "failed to connect to Trojan gRPC server",
                                              to_std_error(failure.code())}));
                          }
                          std::rethrow_exception(std::current_exception());
                      }));
        } catch (const core::Error &failure) {
            finish(core::fail(failure));
            co_return;
        } catch (...) {
            finish(core::fail(
                {core::ErrorCode::endpoint_connection, "failed to connect to Trojan gRPC server"}));
            co_return;
        }
        transport::TlsClientOptions tls_options;
        tls_options.server_name =
            config.server_name.empty() ? config.server_host : config.server_name;
        tls_options.verify_peer = config.verify_peer;
        tls_options.trusted_ca_pem = config.trusted_ca_pem;
        tls_options.verify_hostname = config.name_cert_verify;
        tls_options.client_certificate_pem = config.certificate;
        tls_options.client_private_key_pem = config.private_key;
        tls_options.alpn_protocols = {"h2"};
        tls_options.fingerprint = config.fingerprint;
        if (!config.reality_public_key.empty()) {
            tls_options.reality =
                transport::TlsRealityOptions{config.reality_public_key, config.reality_short_id};
        }
        if (config.ech_enabled) {
            auto ech = co_await fetch_trojan_ech_config(resolver, config, tls_options.server_name);
            if (!ech) {
                finish(core::fail(ech.error()));
                co_return;
            }
            tls_options.ech_config_list = std::move(ech.value());
        }
        tls_options.deadline = deadline;
        auto plain = std::make_unique<net::TcpStream>(std::move(*socket));
        transport::TlsClientConnection tls;
        try {
            tls = co_await transport::async_tls_client_handshake(std::move(plain),
                                                                 std::move(tls_options));
        } catch (const core::Error &failure) {
            finish(core::fail(failure));
            co_return;
        } catch (...) {
            finish(core::fail({core::ErrorCode::endpoint_connection, "Trojan gRPC TLS failed"}));
            co_return;
        }
        if (tls.negotiated_alpn != "h2") {
            tls.stream->close();
            finish(core::fail(
                {core::ErrorCode::carrier_handshake, "Trojan gRPC server did not negotiate h2"}));
            co_return;
        }
        transport::Http2SessionOptions http2_options;
        http2_options.ping_interval =
            std::chrono::duration_cast<std::chrono::milliseconds>(config.grpc_ping_interval);
        finish(SessionResult{transport::make_http2_exchange_session(std::move(tls.stream),
                                                                    std::move(http2_options))});
    }
};

io::AnySender<std::shared_ptr<io::ExchangeSession>>
open_grpc_session(runtime::AsioRuntime &runtime, std::shared_ptr<dns::ResolverService> resolver,
                  TrojanOutboundConfig config) {
    using SessionResult = GrpcSessionOpen::SessionResult;
    using SessionHandler = GrpcSessionOpen::SessionHandler;
    struct Shared {
        exec::async_scope scope;
    };
    auto shared = std::make_shared<Shared>();
    auto bridged = async::bridge_sender<SessionResult>(
        [shared, &runtime, resolver = std::move(resolver),
         config = std::move(config)](SessionHandler done) mutable {
            shared->scope.spawn(GrpcSessionOpen::run(&runtime, std::move(resolver),
                                                     std::move(config), std::move(done)));
            using AbortFn = async::BridgeSender<SessionResult>::AbortFn;
            return AbortFn{[] {}};
        });
    auto sender = std::move(bridged) | stdexec::then([](SessionResult result) {
                      if (!result) {
                          throw result.error();
                      }
                      return std::move(result.value());
                  });
    return io::AnySender<std::shared_ptr<io::ExchangeSession>>{std::move(sender)};
}

class TrojanConnectOperation final : public std::enable_shared_from_this<TrojanConnectOperation> {
  public:
    TrojanConnectOperation(runtime::AsioRuntime &runtime,
                           std::shared_ptr<dns::ResolverService> resolver,
                           TrojanOutboundConfig config, core::StreamRequest request,
                           core::StreamOpenHandler handler, std::uint8_t command = 0x01,
                           std::shared_ptr<transport::proxy::gun::GunClient> gun_pool = nullptr)
        : runtime_(runtime), resolver_(std::move(resolver)), config_(std::move(config)),
          request_(std::move(request)), command_(command), gun_pool_(std::move(gun_pool)),
          socket_(std::make_shared<boost::asio::ip::tcp::socket>(runtime.serialized_executor())),
          timer_(runtime.serialized_executor()), handler_(std::move(handler)) {}

    void start() {
        if (config_.id.empty() || config_.server_host.empty() || config_.server_port == 0 ||
            config_.password.empty()) {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration,
                 "Trojan outbound ID, server, port, and password are required"}));
            return;
        }
        if (config_.network != "" && config_.network != "tcp" && config_.network != "ws" &&
            config_.network != "wss" && config_.network != "grpc") {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration,
                 "Trojan outbound network must be tcp, ws, wss, or grpc"}));
            return;
        }
        if (!config_.reality_public_key.empty() && !config_.security_mode.empty()) {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration,
                 "Trojan REALITY and security overlays are mutually exclusive"}));
            return;
        }
        if (config_.security_mode != "" && config_.security_mode != "shadow-tls" &&
            config_.security_mode != "restls" && config_.security_mode != "jls") {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration,
                 "Trojan security mode must be shadow-tls, restls, or jls"}));
            return;
        }
        deadline_ = std::chrono::steady_clock::now() + kConnectTimeout;
        timer_.expires_at(deadline_);
        timer_.async_wait([self = shared_from_this()](const boost::system::error_code &error) {
            if (!error) {
                self->finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::timeout, "timed out opening Trojan stream"}));
            }
        });
        detail::resolve_host(runtime_, resolver_, config_.server_host,
                             [self = shared_from_this()](core::Result<detail::AddressList> result) {
                                 self->resolved(std::move(result));
                             });
    }

  private:
    // TLS-underlay camouflage over an established TCP stream. Each
    // proxy::async_open_* is bridged into the chain task; aborting the
    // operation cancels the late terminal like the SS plugin opens.
    static exec::task<core::Result<std::unique_ptr<io::StreamHandle>>>
    open_security_overlay(std::shared_ptr<TrojanConnectOperation> self,
                          std::unique_ptr<io::StreamHandle> stream) {
        const auto &mode = self->config_.security_mode;
        using Opened = core::Result<std::unique_ptr<io::StreamHandle>>;
        try {
            if (mode == "shadow-tls") {
                auto boxed = std::make_shared<std::unique_ptr<io::StreamHandle>>(std::move(stream));
                co_return co_await async::bridge_sender<Opened>(
                    [self, boxed](async::BridgeSender<Opened>::Handler done) mutable {
                        transport::proxy::async_open_shadow_tls(
                            std::move(*boxed), self->config_.shadow_tls_options,
                            [done](Opened opened) mutable { done(std::move(opened)); });
                        using AbortFn = async::BridgeSender<Opened>::AbortFn;
                        return AbortFn{[self] { self->abort(); }};
                    });
            }
            if (mode == "restls") {
                auto boxed = std::make_shared<std::unique_ptr<io::StreamHandle>>(std::move(stream));
                co_return co_await async::bridge_sender<Opened>(
                    [self, boxed](async::BridgeSender<Opened>::Handler done) mutable {
                        transport::proxy::async_open_restls(
                            std::move(*boxed), self->config_.restls_options,
                            [done](Opened opened) mutable { done(std::move(opened)); });
                        using AbortFn = async::BridgeSender<Opened>::AbortFn;
                        return AbortFn{[self] { self->abort(); }};
                    });
            }
            if (mode == "jls") {
                auto boxed = std::make_shared<std::unique_ptr<io::StreamHandle>>(std::move(stream));
                co_return co_await async::bridge_sender<Opened>(
                    [self, boxed](async::BridgeSender<Opened>::Handler done) mutable {
                        transport::proxy::async_open_jls(
                            std::move(*boxed), self->config_.jls_options,
                            [done](Opened opened) mutable { done(std::move(opened)); });
                        using AbortFn = async::BridgeSender<Opened>::AbortFn;
                        return AbortFn{[self] { self->abort(); }};
                    });
            }
            co_return core::fail({core::ErrorCode::configuration,
                                  "Trojan security mode must be shadow-tls, restls, or jls"});
        } catch (const core::Error &failure) {
            co_return core::fail(failure);
        } catch (...) {
            co_return core::fail(
                {core::ErrorCode::transport_io, "Trojan security overlay open failed"});
        }
    }

    // Straight-line connect chain: TCP connect, TLS or WebSocket transport,
    // Trojan request write. Every terminal funnels through finish(), so the
    // spawned task always ends with a value.
    static exec::task<void>
    run(std::shared_ptr<TrojanConnectOperation> self,
        std::shared_ptr<std::vector<boost::asio::ip::tcp::endpoint>> endpoints) {
        // gRPC dials its own pooled sessions; the direct TCP connect below
        // only serves the tcp/ws/wss transports.
        const bool direct_connect = self->config_.network != "grpc";
        try {
            if (direct_connect) {
                try {
                    co_await (boost::asio::async_connect(*self->socket_, *endpoints,
                                                         exec::asio::use_sender) |
                              stdexec::then([](const boost::asio::ip::tcp::endpoint &) {}) |
                              stdexec::let_error([](std::exception_ptr error) {
                                  try {
                                      std::rethrow_exception(std::move(error));
                                  } catch (const boost::system::system_error &failure) {
                                      return stdexec::just_error(std::make_exception_ptr(
                                          core::Error{core::ErrorCode::endpoint_connection,
                                                      "failed to connect to Trojan server",
                                                      to_std_error(failure.code())}));
                                  }
                                  std::rethrow_exception(std::current_exception());
                              }));
                } catch (const core::Error &failure) {
                    self->finish(core::StreamOpenResult::failed(failure));
                    co_return;
                } catch (...) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::endpoint_connection, "failed to connect to Trojan "
                                                               "server"}));
                    co_return;
                }
            }
            if (self->completed_) {
                co_return;
            }
            // Without the ss layer the WS handshake carries the request
            // header (early data or first message) and no post-write is
            // needed below.
            bool header_sent = false;
            if (self->config_.network == "grpc") {
                const auto gun_pool = self->gun_pool_;
                if (!gun_pool) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::configuration, "Trojan gRPC pool is not initialized"}));
                    co_return;
                }
                std::unique_ptr<io::StreamHandle> gun_stream;
                try {
                    gun_stream = co_await gun_pool->dial();
                } catch (const core::Error &failure) {
                    self->finish(core::StreamOpenResult::failed(failure));
                    co_return;
                } catch (...) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::transport_io, "Trojan gRPC dial failed"}));
                    co_return;
                }
                if (self->completed_) {
                    gun_stream->close();
                    co_return;
                }
                self->transport_stream_ = std::move(gun_stream);
            } else if (self->config_.network == "ws" || self->config_.network == "wss") {
                transport::WebSocketClientOptions ws_options;
                ws_options.host =
                    self->config_.websocket_host.empty()
                        ? (self->config_.server_name.empty() ? self->config_.server_host
                                                             : self->config_.server_name)
                        : self->config_.websocket_host;
                ws_options.target = self->config_.websocket_path;
                ws_options.headers = self->config_.websocket_headers;
                // With a security overlay the camouflage replaces the
                // WS-underlying TLS (matching Mihomo); otherwise the ws
                // client owns its TLS handshake.
                const bool overlayed = !self->config_.security_mode.empty();
                ws_options.tls =
                    !overlayed && (self->config_.network == "wss" || self->config_.websocket_tls);
                ws_options.tls_server_name = self->config_.server_name.empty()
                                                 ? self->config_.server_host
                                                 : self->config_.server_name;
                if (self->config_.ech_enabled) {
                    auto ech = co_await fetch_trojan_ech_config(self->resolver_, self->config_,
                                                                ws_options.tls_server_name);
                    if (!ech) {
                        self->finish(core::StreamOpenResult::failed(ech.error()));
                        co_return;
                    }
                    ws_options.tls_ech_config_list = std::move(ech.value());
                }
                ws_options.tls_verify_peer = self->config_.verify_peer;
                ws_options.tls_trusted_ca_pem = self->config_.trusted_ca_pem;
                ws_options.tls_verify_hostname = self->config_.name_cert_verify;
                ws_options.tls_client_certificate_pem = self->config_.certificate;
                ws_options.tls_client_private_key_pem = self->config_.private_key;
                ws_options.tls_alpn_protocols = self->config_.alpn_protocols.empty()
                                                    ? std::vector<std::string>{"http/1.1"}
                                                    : self->config_.alpn_protocols;
                ws_options.tls_fingerprint = self->config_.fingerprint;
                if (!self->config_.reality_public_key.empty()) {
                    ws_options.tls_reality = transport::TlsRealityOptions{
                        self->config_.reality_public_key, self->config_.reality_short_id};
                }
                ws_options.max_early_data = self->config_.websocket_max_early_data;
                ws_options.early_data_header_name = self->config_.websocket_early_data_header;
                ws_options.v2ray_http_upgrade = self->config_.websocket_v2ray_http_upgrade;
                ws_options.deadline = self->deadline_;
                if (!self->config_.ss_enabled) {
                    auto header = build_request_header(self->config_, self->request_.destination,
                                                       self->command_);
                    if (!header) {
                        self->finish(core::StreamOpenResult::failed(header.error()));
                        co_return;
                    }
                    ws_options.initial_payload = std::move(header.value());
                    header_sent = true;
                }
                std::unique_ptr<io::StreamHandle> ws_base =
                    std::make_unique<net::TcpStream>(std::move(*self->socket_));
                self->socket_.reset();
                if (overlayed) {
                    auto overlay = co_await open_security_overlay(self, std::move(ws_base));
                    if (!overlay) {
                        self->finish(core::StreamOpenResult::failed(overlay.error()));
                        co_return;
                    }
                    if (self->completed_) {
                        overlay.value()->close();
                        co_return;
                    }
                    ws_base = std::move(overlay.value());
                }
                auto plain_stream = std::move(ws_base);
                using WsSigs = stdexec::completion_signatures<
                    stdexec::set_value_t(core::Result<std::unique_ptr<io::StreamHandle>>),
                    stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>;
                core::Result<std::unique_ptr<io::StreamHandle>> ws_result;
                try {
                    ws_result = co_await async::callback_sender<WsSigs>(
                        [plain = std::move(plain_stream),
                         ws_options = std::move(ws_options)](auto terminal) mutable {
                            transport::async_websocket_client_handshake(
                                std::move(plain), std::move(ws_options), std::move(terminal));
                        },
                        [](auto receiver, core::Result<std::unique_ptr<io::StreamHandle>> result) {
                            stdexec::set_value(std::move(receiver), std::move(result));
                        });
                } catch (const core::Error &failure) {
                    self->finish(core::StreamOpenResult::failed(failure));
                    co_return;
                } catch (...) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::endpoint_connection, "Trojan WebSocket failed"}));
                    co_return;
                }
                if (self->completed_) {
                    if (ws_result && ws_result.value()) {
                        ws_result.value()->close();
                    }
                    co_return;
                }
                if (!ws_result) {
                    self->finish(core::StreamOpenResult::failed(ws_result.error()));
                    co_return;
                }
                self->transport_stream_ = std::move(ws_result.value());
            } else {
                transport::TlsClientOptions tls_options;
                tls_options.server_name = self->config_.server_name.empty()
                                              ? self->config_.server_host
                                              : self->config_.server_name;
                tls_options.verify_peer = self->config_.verify_peer;
                tls_options.trusted_ca_pem = self->config_.trusted_ca_pem;
                tls_options.verify_hostname = self->config_.name_cert_verify;
                tls_options.client_certificate_pem = self->config_.certificate;
                tls_options.client_private_key_pem = self->config_.private_key;
                tls_options.alpn_protocols = self->config_.alpn_protocols.empty()
                                                 ? std::vector<std::string>{"h2", "http/1.1"}
                                                 : self->config_.alpn_protocols;
                tls_options.fingerprint = self->config_.fingerprint;
                if (!self->config_.reality_public_key.empty()) {
                    tls_options.reality = transport::TlsRealityOptions{
                        self->config_.reality_public_key, self->config_.reality_short_id};
                }
                if (self->config_.ech_enabled) {
                    auto ech = co_await fetch_trojan_ech_config(self->resolver_, self->config_,
                                                                tls_options.server_name);
                    if (!ech) {
                        self->finish(core::StreamOpenResult::failed(ech.error()));
                        co_return;
                    }
                    tls_options.ech_config_list = std::move(ech.value());
                }
                tls_options.deadline = self->deadline_;
                auto plain_stream = std::make_unique<net::TcpStream>(std::move(*self->socket_));
                self->socket_.reset();
                std::unique_ptr<io::StreamHandle> camouflaged = std::move(plain_stream);
                // The camouflage layers carry their own TLS handshake and
                // replace the Trojan TLS step (matching Mihomo's
                // StreamTLSConn); without them the plain stream goes
                // through the shared TLS client below.
                if (!self->config_.security_mode.empty()) {
                    auto overlay = co_await open_security_overlay(self, std::move(camouflaged));
                    if (!overlay) {
                        self->finish(core::StreamOpenResult::failed(overlay.error()));
                        co_return;
                    }
                    if (self->completed_) {
                        overlay.value()->close();
                        co_return;
                    }
                    self->transport_stream_ = std::move(overlay.value());
                } else {
                    transport::TlsClientConnection connection;
                    try {
                        connection = co_await transport::async_tls_client_handshake(
                            std::move(camouflaged), std::move(tls_options));
                    } catch (const core::Error &failure) {
                        self->finish(core::StreamOpenResult::failed(failure));
                        co_return;
                    } catch (...) {
                        self->finish(core::StreamOpenResult::failed(
                            {core::ErrorCode::endpoint_connection, "Trojan TLS failed"}));
                        co_return;
                    }
                    if (self->completed_) {
                        if (connection.stream) {
                            connection.stream->close();
                        }
                        co_return;
                    }
                    self->transport_stream_ = std::move(connection.stream);
                }
            }
            if (self->config_.ss_enabled) {
                const auto method =
                    self->config_.ss_method.empty() ? "AES-128-GCM" : self->config_.ss_method;
                auto ss_stream = transport::trojan::make_trojan_ss_stream_handle(
                    std::move(self->transport_stream_), method, self->config_.ss_password);
                if (!ss_stream) {
                    self->finish(core::StreamOpenResult::failed(ss_stream.error()));
                    co_return;
                }
                self->transport_stream_ = std::move(ss_stream.value());
            }
            if (!header_sent) {
                const auto header =
                    build_request_header(self->config_, self->request_.destination, self->command_);
                if (!header) {
                    self->finish(core::StreamOpenResult::failed(header.error()));
                    co_return;
                }
                auto wire = std::make_shared<std::vector<std::uint8_t>>(std::move(header.value()));
                try {
                    co_await self->transport_stream_->async_write(boost::asio::buffer(*wire));
                } catch (const core::Error &failure) {
                    self->finish(core::StreamOpenResult::failed(failure));
                    co_return;
                } catch (...) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::transport_io, "failed to write Trojan request"}));
                    co_return;
                }
            }
            if (self->completed_) {
                co_return;
            }
            self->finish(core::StreamOpenResult::opened(std::move(self->transport_stream_)));
        } catch (...) {
            self->finish(core::StreamOpenResult::failed(
                {core::ErrorCode::transport_io, "Trojan connect failed"}));
        }
        co_return;
    }

    void resolved(core::Result<detail::AddressList> result) {
        if (completed_) {
            return;
        }
        if (!result) {
            finish(core::StreamOpenResult::failed(result.error()));
            return;
        }
        auto endpoints = std::make_shared<std::vector<boost::asio::ip::tcp::endpoint>>();
        endpoints->reserve(result.value().size());
        for (const auto &address : result.value()) {
            endpoints->emplace_back(address, config_.server_port);
        }
        // The scope only owns this chain task (merge-shaped usage);
        // teardown stays guard-driven, so no stop is ever requested.
        scope_.spawn(run(shared_from_this(), std::move(endpoints)));
    }

    void cancel_timer() noexcept { timer_.cancel(); }

  public:
    // Abort for sender-driven cancellation: posted to the strand so it stays
    // ordered with finish(). Marks completion so the chain task bails at its
    // next guard; the bridge drops the late terminal.
    void abort() noexcept {
        auto self = shared_from_this();
        try {
            // Runtime outlives every operation; socket_ may already be moved
            // into the stream chain, so never touch it here.
            boost::asio::post(runtime_.serialized_executor(), [self]() {
                if (self->completed_) {
                    return;
                }
                self->completed_ = true;
                boost::system::error_code ignored;
                self->cancel_timer();
                if (self->socket_) {
                    self->socket_->cancel(ignored);
                    self->socket_->close(ignored);
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
        if (!result.succeeded()) {
            boost::system::error_code ignored;
            if (socket_) {
                socket_->cancel(ignored);
                socket_->close(ignored);
            }
            if (transport_stream_) {
                transport_stream_->close();
            }
        }
        auto handler = std::move(handler_);
        handler(std::move(result));
    }

    runtime::AsioRuntime &runtime_;
    std::shared_ptr<dns::ResolverService> resolver_;
    TrojanOutboundConfig config_;
    core::StreamRequest request_;
    std::uint8_t command_ = 0x01;
    std::shared_ptr<transport::proxy::gun::GunClient> gun_pool_;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::unique_ptr<io::StreamHandle> transport_stream_;
    boost::asio::steady_timer timer_;
    core::StreamOpenHandler handler_;
    std::chrono::steady_clock::time_point deadline_{};
    // Owns the single connect chain task, which always ends with a value.
    exec::async_scope scope_;
    bool completed_ = false;
};

} // namespace

TrojanOutbound::TrojanOutbound(runtime::AsioRuntime &runtime, TrojanOutboundConfig config,
                               std::shared_ptr<dns::ResolverService> resolver)
    : runtime_(runtime), config_(std::move(config)), resolver_(std::move(resolver)),
      descriptor_{config_.id, "trojan"} {
    if (config_.network == "grpc") {
        transport::proxy::gun::GunClientOptions gun_options;
        gun_options.stream.service_name = config_.grpc_service_name;
        gun_options.stream.user_agent = config_.grpc_user_agent;
        gun_options.stream.host =
            config_.server_name.empty() ? config_.server_host : config_.server_name;
        gun_options.stream.executor = runtime_.serialized_executor();
        gun_options.max_connections = config_.grpc_max_connections;
        gun_options.min_streams = config_.grpc_min_streams;
        gun_options.max_streams = config_.grpc_max_streams;
        auto *runtime = &runtime_;
        auto resolver = resolver_;
        auto config = config_;
        gun_pool_ = std::make_shared<transport::proxy::gun::GunClient>(
            std::move(gun_options),
            [runtime, resolver, config]() -> io::AnySender<std::shared_ptr<io::ExchangeSession>> {
                return open_grpc_session(*runtime, resolver, config);
            });
    }
}

core::Status TrojanOutbound::validate() const {
    if (config_.id.empty() || config_.server_host.empty() || config_.server_port == 0 ||
        config_.password.empty()) {
        return core::fail({core::ErrorCode::configuration,
                           "Trojan outbound ID, server, port, and password are required"});
    }
    if (config_.network != "" && config_.network != "tcp" && config_.network != "ws" &&
        config_.network != "wss" && config_.network != "grpc") {
        return core::fail({core::ErrorCode::configuration,
                           "Trojan outbound network must be tcp, ws, wss, or grpc"});
    }
    if ((config_.network == "ws" || config_.network == "wss") && config_.websocket_path.empty()) {
        return core::fail(
            {core::ErrorCode::configuration, "Trojan WebSocket path must not be empty"});
    }
    if (config_.security_mode != "" && config_.security_mode != "shadow-tls" &&
        config_.security_mode != "restls" && config_.security_mode != "jls") {
        return core::fail({core::ErrorCode::configuration,
                           "Trojan security mode must be shadow-tls, restls, or jls"});
    }
    if (config_.ss_enabled) {
        if (config_.ss_password.empty()) {
            return core::fail(
                {core::ErrorCode::configuration, "Trojan ss-opts password must not be empty"});
        }
        const auto method = config_.ss_method.empty() ? "AES-128-GCM" : config_.ss_method;
        auto spec = transport::proxy::cipher_method(method);
        if (!spec) {
            return core::fail(spec.error());
        }
        if (spec.value().kind != transport::proxy::CipherKind::aead ||
            spec.value().shadowsocks_2022) {
            return core::fail({core::ErrorCode::configuration,
                               "Trojan ss-opts supports classic AEAD methods only"});
        }
    }
    return {};
}

const core::OutboundDescriptor &TrojanOutbound::descriptor() const noexcept { return descriptor_; }

core::OutboundCapabilities TrojanOutbound::capabilities() const noexcept { return capabilities_; }

io::AnySender<core::StreamOpenResult> TrojanOutbound::connect_stream(core::StreamRequest request) {
    auto &runtime = runtime_;
    auto resolver = resolver_;
    auto config = config_;
    auto gun_pool = gun_pool_;
    return async::bridge_sender<core::StreamOpenResult>(
        [&runtime, resolver = std::move(resolver), config = std::move(config),
         gun_pool = std::move(gun_pool), request = std::move(request)](
            async::BridgeSender<core::StreamOpenResult>::Handler terminal) mutable {
            auto operation = std::make_shared<TrojanConnectOperation>(
                runtime, std::move(resolver), std::move(config), std::move(request),
                std::move(terminal), 0x01, std::move(gun_pool));
            operation->start();
            return [operation] { operation->abort(); };
        });
}

io::AnySender<core::DatagramOpenResult>
TrojanOutbound::open_datagram(core::DatagramRequest request) {
    auto &runtime = runtime_;
    auto resolver = resolver_;
    auto config = config_;
    auto gun_pool = gun_pool_;
    return async::bridge_sender<core::DatagramOpenResult>(
        [&runtime, resolver = std::move(resolver), config = std::move(config),
         gun_pool = std::move(gun_pool), request = std::move(request)](
            async::BridgeSender<core::DatagramOpenResult>::Handler terminal) mutable {
            auto handler = std::move(terminal);
            if (!request.initial_destination) {
                handler(core::DatagramOpenResult::failed(
                    {core::ErrorCode::configuration,
                     "Trojan UDP association requires an initial destination"}));
                return async::BridgeSender<core::DatagramOpenResult>::AbortFn{};
            }
            core::StreamRequest stream_request{*request.initial_destination, std::nullopt,
                                               request.dial_trace};
            auto operation = std::make_shared<TrojanConnectOperation>(
                runtime, std::move(resolver), std::move(config), std::move(stream_request),
                [handler = std::move(handler)](core::StreamOpenResult result) mutable {
                    if (!result.succeeded()) {
                        handler(core::DatagramOpenResult::failed(result.error.value_or(
                            core::Error{core::ErrorCode::transport_io,
                                        "failed to open Trojan UDP association"})));
                        return;
                    }
                    auto packet =
                        transport::trojan::make_trojan_packet_conn(std::move(result.handle));
                    if (!packet) {
                        handler(core::DatagramOpenResult::failed(packet.error()));
                        return;
                    }
                    handler(core::DatagramOpenResult::opened(
                        std::move(packet.value()), core::DatagramSemantics::multi_destination));
                },
                transport::trojan::kCommandUdp, std::move(gun_pool));
            operation->start();
            return async::BridgeSender<core::DatagramOpenResult>::AbortFn{
                [operation] { operation->abort(); }};
        });
}

} // namespace clash_native::outbound
