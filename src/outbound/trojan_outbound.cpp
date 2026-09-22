#include <clash_native/async/bridge.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/outbound/trojan_outbound.hpp>
#include <clash_native/transport/tls_client.hpp>

#include "outbound_utils.hpp"
#include "proxy_address.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

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
        auto self = shared_from_this();
        boost::asio::async_connect(
            *socket_, *endpoints,
            [self, endpoints](const boost::system::error_code &error,
                              const boost::asio::ip::tcp::endpoint &) {
                if (error) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::endpoint_connection, "failed to connect to Trojan server",
                         to_std_error(error)}));
                    return;
                }
                self->start_transport();
            });
    }

    void start_transport() {
        if (config_.network == "ws" || config_.network == "wss") {
            start_websocket();
            return;
        }
        start_tls();
    }

    void start_tls() {
        const auto server_name =
            config_.server_name.empty() ? config_.server_host : config_.server_name;
        transport::TlsClientOptions options;
        options.server_name = server_name;
        options.verify_peer = config_.verify_peer;
        options.trusted_ca_pem = config_.trusted_ca_pem;
        options.deadline = deadline_;
        auto self = shared_from_this();
        auto plain_stream = std::make_unique<net::TcpStream>(std::move(*socket_));
        socket_.reset();
        tls_handshake_ = transport::async_tls_client_handshake(
            std::move(plain_stream), std::move(options),
            [self](core::Result<transport::TlsClientConnection> result) mutable {
                self->tls_handshake_.reset();
                if (self->completed_) {
                    if (result && result->stream) {
                        result->stream->close();
                    }
                    return;
                }
                if (!result) {
                    self->finish(core::StreamOpenResult::failed(result.error()));
                    return;
                }
                self->transport_stream_ = std::move(result->stream);
                self->write_request_header();
            });
    }

    void start_websocket() {
        if (completed_ || !socket_) {
            return;
        }
        const auto server_name =
            config_.server_name.empty() ? config_.server_host : config_.server_name;
        transport::WebSocketClientOptions options;
        options.host =
            config_.websocket_host.empty()
                ? (config_.server_name.empty() ? config_.server_host : config_.server_name)
                : config_.websocket_host;
        options.target = config_.websocket_path;
        options.headers = config_.websocket_headers;
        options.tls = config_.network == "wss" || config_.websocket_tls;
        options.tls_server_name = server_name;
        options.tls_verify_peer = config_.verify_peer;
        options.tls_trusted_ca_pem = config_.trusted_ca_pem;
        options.tls_alpn_protocols = {"http/1.1"};
        options.deadline = deadline_;

        auto plain_stream = std::make_unique<net::TcpStream>(std::move(*socket_));
        socket_.reset();
        auto self = shared_from_this();
        websocket_handshake_ = transport::async_websocket_client_handshake(
            std::move(plain_stream), std::move(options),
            [self](core::Result<std::unique_ptr<io::StreamHandle>> result) mutable {
                self->websocket_handshake_.reset();
                if (self->completed_) {
                    if (result && result.value()) {
                        result.value()->close();
                    }
                    return;
                }
                if (!result) {
                    self->finish(core::StreamOpenResult::failed(result.error()));
                    return;
                }
                self->transport_stream_ = std::move(result.value());
                self->write_request_header();
            });
    }

    void write_request_header() {
        const auto password_key = trojan_password_key(config_.password);
        const auto address = detail::encode_proxy_address(request_.destination);
        if (!password_key || !address) {
            finish(core::StreamOpenResult::failed(!password_key ? password_key.error()
                                                                : address.error()));
            return;
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

        auto self = shared_from_this();
        struct WriteForwarder {
            std::shared_ptr<TrojanConnectOperation> self;
            std::shared_ptr<std::vector<std::uint8_t>> wire;
            void set_value(std::size_t) noexcept {
                self->completed_ = true;
                self->cancel_timer();
                auto handler = std::move(self->handler_);
                handler(core::StreamOpenResult::opened(std::move(self->transport_stream_)));
            }
            void set_error(std::exception_ptr error) noexcept {
                core::Error failure{
                    core::ErrorCode::transport_io, "failed to write Trojan request", {}};
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const core::Error &named) {
                    failure = named;
                } catch (...) {
                }
                self->finish(core::StreamOpenResult::failed(std::move(failure)));
            }
            void set_stopped() noexcept {
                self->finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::cancelled, "Trojan request write cancelled"}));
            }
        };
        async::start_with_receiver(transport_stream_->async_write(boost::asio::buffer(*wire)),
                                   WriteForwarder{self, wire});
    }

    void cancel_timer() noexcept { timer_.cancel(); }

  public:
    // Abort for sender-driven cancellation: runs on any thread, mirrors the
    // failure cleanup in finish() without completing (the bridge drops the
    // late terminal through its settled flag).
    void abort() noexcept {
        auto self = shared_from_this();
        try {
            // Runtime outlives every operation; socket_ may already be moved
            // into the stream chain, so never touch it here.
            boost::asio::post(runtime_.serialized_executor(), [self]() {
                if (self->completed_) {
                    return;
                }
                boost::system::error_code ignored;
                self->cancel_timer();
                if (self->tls_handshake_) {
                    self->tls_handshake_->cancel();
                }
                if (self->websocket_handshake_) {
                    self->websocket_handshake_->cancel();
                }
                if (self->socket_) {
                    self->socket_->cancel(ignored);
                    self->socket_->close(ignored);
                }
                if (self->transport_stream_) {
                    self->transport_stream_->close();
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
            if (tls_handshake_) {
                tls_handshake_->cancel();
            }
            if (websocket_handshake_) {
                websocket_handshake_->cancel();
            }
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
    std::shared_ptr<transport::TlsClientHandshake> tls_handshake_;
    std::shared_ptr<transport::WebSocketClientHandshake> websocket_handshake_;
    std::unique_ptr<io::StreamHandle> transport_stream_;
    boost::asio::steady_timer timer_;
    core::StreamOpenHandler handler_;
    std::chrono::steady_clock::time_point deadline_{};
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

void TrojanOutbound::open_datagram(core::DatagramRequest, core::DatagramOpenHandler handler) {
    runtime_.scheduler().post([handler = std::move(handler)]() mutable {
        handler(core::DatagramOpenResult::unsupported());
    });
}

} // namespace clash_native::outbound
