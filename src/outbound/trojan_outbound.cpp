#include <clash_native/net/tls_stream.hpp>
#include <clash_native/outbound/trojan_outbound.hpp>

#include "dns/builtin_ca_bundle.hpp"
#include "outbound_utils.hpp"
#include "proxy_address.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <chrono>
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
                           TrojanOutboundConfig config,
                           std::shared_ptr<boost::asio::ssl::context> tls_context,
                           core::StreamRequest request, core::StreamOpenHandler handler)
        : runtime_(runtime), resolver_(std::move(resolver)), config_(std::move(config)),
          tls_context_(std::move(tls_context)), request_(std::move(request)),
          stream_(std::make_shared<net::TlsStream::SslStream>(runtime.context(), *tls_context_)),
          timer_(runtime.context()), handler_(std::move(handler)) {}

    void start() {
        if (config_.id.empty() || config_.server_host.empty() || config_.server_port == 0 ||
            config_.password.empty()) {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration,
                 "Trojan outbound ID, server, port, and password are required"}));
            return;
        }
        timer_.expires_after(kConnectTimeout);
        timer_.async_wait([self = shared_from_this()](const boost::system::error_code &error) {
            if (!error) {
                boost::system::error_code ignored;
                self->stream_->next_layer().cancel(ignored);
                self->finish(core::StreamOpenResult::failed(
                    {core::ErrorCode::timeout, "timed out opening Trojan TLS stream"}));
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
            stream_->next_layer(), *endpoints,
            [self, endpoints](const boost::system::error_code &error,
                              const boost::asio::ip::tcp::endpoint &) {
                if (error) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::endpoint_connection, "failed to connect to Trojan server",
                         to_std_error(error)}));
                    return;
                }
                self->start_tls();
            });
    }

    void start_tls() {
        const auto server_name =
            config_.server_name.empty() ? config_.server_host : config_.server_name;
        boost::system::error_code address_error;
        boost::asio::ip::make_address(server_name, address_error);
        if (address_error &&
            SSL_set_tlsext_host_name(stream_->native_handle(), server_name.c_str()) != 1) {
            finish(core::StreamOpenResult::failed(
                {core::ErrorCode::carrier_handshake, "failed to configure Trojan TLS SNI"}));
            return;
        }
        if (config_.verify_peer) {
            stream_->set_verify_mode(boost::asio::ssl::verify_peer);
            stream_->set_verify_callback(boost::asio::ssl::host_name_verification(server_name));
        } else {
            stream_->set_verify_mode(boost::asio::ssl::verify_none);
        }

        auto self = shared_from_this();
        stream_->async_handshake(
            boost::asio::ssl::stream_base::client, [self](const boost::system::error_code &error) {
                if (error) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::carrier_handshake,
                         "Trojan TLS handshake failed: " + error.message(), to_std_error(error)}));
                    return;
                }
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
        boost::asio::async_write(
            *stream_, boost::asio::buffer(*wire),
            [self, wire](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    self->finish(core::StreamOpenResult::failed(
                        {core::ErrorCode::transport_io, "failed to write Trojan TCP request",
                         to_std_error(error)}));
                    return;
                }
                self->completed_ = true;
                self->cancel_timer();
                auto handler = std::move(self->handler_);
                handler(core::StreamOpenResult::opened(
                    std::make_unique<net::TlsStream>(self->tls_context_, self->stream_)));
            });
    }

    void cancel_timer() noexcept { timer_.cancel(); }

    void finish(core::StreamOpenResult result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        cancel_timer();
        if (!result.succeeded()) {
            boost::system::error_code ignored;
            stream_->next_layer().cancel(ignored);
            stream_->next_layer().close(ignored);
        }
        auto handler = std::move(handler_);
        handler(std::move(result));
    }

    runtime::AsioRuntime &runtime_;
    std::shared_ptr<dns::ResolverService> resolver_;
    TrojanOutboundConfig config_;
    std::shared_ptr<boost::asio::ssl::context> tls_context_;
    core::StreamRequest request_;
    std::shared_ptr<net::TlsStream::SslStream> stream_;
    boost::asio::steady_timer timer_;
    core::StreamOpenHandler handler_;
    bool completed_ = false;
};

} // namespace

TrojanOutbound::TrojanOutbound(runtime::AsioRuntime &runtime, TrojanOutboundConfig config,
                               std::shared_ptr<dns::ResolverService> resolver)
    : runtime_(runtime), config_(std::move(config)), resolver_(std::move(resolver)),
      tls_context_(
          std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tls_client)),
      descriptor_{config_.id, "trojan"} {
    tls_context_->set_options(boost::asio::ssl::context::default_workarounds |
                              boost::asio::ssl::context::no_sslv2 |
                              boost::asio::ssl::context::no_sslv3);
    if (config_.verify_peer) {
        const auto roots = dns::detail::builtin_ca_bundle_pem();
        tls_context_->add_certificate_authority(boost::asio::buffer(roots.data(), roots.size()));
        if (!config_.trusted_ca_pem.empty()) {
            tls_context_->add_certificate_authority(
                boost::asio::buffer(config_.trusted_ca_pem.data(), config_.trusted_ca_pem.size()));
        }
    }
}

core::Status TrojanOutbound::validate() const {
    if (config_.id.empty() || config_.server_host.empty() || config_.server_port == 0 ||
        config_.password.empty()) {
        return core::fail({core::ErrorCode::configuration,
                           "Trojan outbound ID, server, port, and password are required"});
    }
    return {};
}

const core::OutboundDescriptor &TrojanOutbound::descriptor() const noexcept { return descriptor_; }

core::OutboundCapabilities TrojanOutbound::capabilities() const noexcept { return capabilities_; }

void TrojanOutbound::connect_stream(core::StreamRequest request, core::StreamOpenHandler handler) {
    auto operation = std::make_shared<TrojanConnectOperation>(
        runtime_, resolver_, config_, tls_context_, std::move(request), std::move(handler));
    operation->start();
}

void TrojanOutbound::open_datagram(core::DatagramRequest, core::DatagramOpenHandler handler) {
    boost::asio::post(runtime_.context(), [handler = std::move(handler)]() mutable {
        handler(core::DatagramOpenResult::unsupported());
    });
}

} // namespace clash_native::outbound
