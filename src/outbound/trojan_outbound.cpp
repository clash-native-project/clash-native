#include <clash_native/async/bridge.hpp>
#include <clash_native/async/callback_sender.hpp>

#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/outbound/trojan_outbound.hpp>
#include <clash_native/transport/tls_client.hpp>
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

class TrojanConnectOperation final : public std::enable_shared_from_this<TrojanConnectOperation> {
  public:
    TrojanConnectOperation(runtime::AsioRuntime &runtime,
                           std::shared_ptr<dns::ResolverService> resolver,
                           TrojanOutboundConfig config, core::StreamRequest request,
                           core::StreamOpenHandler handler)
        : runtime_(runtime), resolver_(std::move(resolver)), config_(std::move(config)),
          request_(std::move(request)),
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
            config_.network != "wss") {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration,
                 "Trojan outbound network must be tcp, ws, or wss"}));
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
    // Straight-line connect chain: TCP connect, TLS or WebSocket transport,
    // Trojan request write. Every terminal funnels through finish(), so the
    // spawned task always ends with a value.
    static exec::task<void>
    run(std::shared_ptr<TrojanConnectOperation> self,
        std::shared_ptr<std::vector<boost::asio::ip::tcp::endpoint>> endpoints) {
        try {
            try {
                co_await (
                    boost::asio::async_connect(*self->socket_, *endpoints, exec::asio::use_sender) |
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
                    {core::ErrorCode::endpoint_connection, "failed to connect to Trojan server"}));
                co_return;
            }
            if (self->completed_) {
                co_return;
            }
            if (self->config_.network == "ws" || self->config_.network == "wss") {
                transport::WebSocketClientOptions ws_options;
                ws_options.host =
                    self->config_.websocket_host.empty()
                        ? (self->config_.server_name.empty() ? self->config_.server_host
                                                             : self->config_.server_name)
                        : self->config_.websocket_host;
                ws_options.target = self->config_.websocket_path;
                ws_options.headers = self->config_.websocket_headers;
                ws_options.tls = self->config_.network == "wss" || self->config_.websocket_tls;
                ws_options.tls_server_name = self->config_.server_name.empty()
                                                 ? self->config_.server_host
                                                 : self->config_.server_name;
                ws_options.tls_verify_peer = self->config_.verify_peer;
                ws_options.tls_trusted_ca_pem = self->config_.trusted_ca_pem;
                ws_options.tls_alpn_protocols = {"http/1.1"};
                ws_options.deadline = self->deadline_;
                auto plain_stream = std::make_unique<net::TcpStream>(std::move(*self->socket_));
                self->socket_.reset();
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
                tls_options.deadline = self->deadline_;
                auto plain_stream = std::make_unique<net::TcpStream>(std::move(*self->socket_));
                self->socket_.reset();
                transport::TlsClientConnection connection;
                try {
                    connection = co_await transport::async_tls_client_handshake(
                        std::move(plain_stream), std::move(tls_options));
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
            const auto password_key = trojan_password_key(self->config_.password);
            const auto address = detail::encode_proxy_address(self->request_.destination);
            if (!password_key || !address) {
                self->finish(core::StreamOpenResult::failed(!password_key ? password_key.error()
                                                                          : address.error()));
                co_return;
            }
            auto wire = std::make_shared<std::vector<std::uint8_t>>();
            wire->reserve(password_key.value().size() + address.value().size() + 5);
            wire->insert(wire->end(), password_key.value().begin(), password_key.value().end());
            wire->push_back('\r');
            wire->push_back('\n');
            wire->push_back(0x01);
            wire->insert(wire->end(), address.value().begin(), address.value().end());
            wire->push_back('\r');
            wire->push_back('\n');
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
      descriptor_{config_.id, "trojan"} {}

core::Status TrojanOutbound::validate() const {
    if (config_.id.empty() || config_.server_host.empty() || config_.server_port == 0 ||
        config_.password.empty()) {
        return core::fail({core::ErrorCode::configuration,
                           "Trojan outbound ID, server, port, and password are required"});
    }
    if (config_.network != "" && config_.network != "tcp" && config_.network != "ws" &&
        config_.network != "wss") {
        return core::fail(
            {core::ErrorCode::configuration, "Trojan outbound network must be tcp, ws, or wss"});
    }
    if ((config_.network == "ws" || config_.network == "wss") && config_.websocket_path.empty()) {
        return core::fail(
            {core::ErrorCode::configuration, "Trojan WebSocket path must not be empty"});
    }
    return {};
}

const core::OutboundDescriptor &TrojanOutbound::descriptor() const noexcept { return descriptor_; }

core::OutboundCapabilities TrojanOutbound::capabilities() const noexcept { return capabilities_; }

io::AnySender<core::StreamOpenResult> TrojanOutbound::connect_stream(core::StreamRequest request) {
    auto &runtime = runtime_;
    auto resolver = resolver_;
    auto config = config_;
    return async::bridge_sender<core::StreamOpenResult>(
        [&runtime, resolver = std::move(resolver), config = std::move(config),
         request = std::move(request)](
            async::BridgeSender<core::StreamOpenResult>::Handler terminal) mutable {
            auto operation = std::make_shared<TrojanConnectOperation>(
                runtime, std::move(resolver), std::move(config), std::move(request),
                std::move(terminal));
            operation->start();
            return [operation] { operation->abort(); };
        });
}

io::AnySender<core::DatagramOpenResult> TrojanOutbound::open_datagram(core::DatagramRequest) {
    return io::AnySender<core::DatagramOpenResult>{
        stdexec::just(core::DatagramOpenResult::unsupported())};
}

} // namespace clash_native::outbound
