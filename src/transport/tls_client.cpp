#include <clash_native/net/tls_stream.hpp>
#include <clash_native/transport/tls_client.hpp>

#include "transport/builtin_ca_bundle.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/steady_timer.hpp>

#include <openssl/ssl.h>

#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::transport {

namespace {

core::Error configuration_error(std::string context) {
    return {core::ErrorCode::configuration, std::move(context), {}};
}

core::Error handshake_error(const boost::system::error_code &error) {
    return {core::ErrorCode::carrier_handshake, "TLS client handshake failed: " + error.message(),
            std::error_code(error.value(), std::system_category())};
}

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "TLS client handshake was cancelled", {}};
}

core::Error timeout_error() {
    return {core::ErrorCode::timeout, "TLS client handshake timed out", {}};
}

core::Error transport_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

} // namespace

namespace detail {

class TlsClientHandshakeOperationImpl final
    : public TlsClientHandshake,
      public std::enable_shared_from_this<TlsClientHandshakeOperationImpl> {
  public:
    TlsClientHandshakeOperationImpl(std::unique_ptr<core::StreamHandle> stream,
                                    TlsClientOptions options, TlsClientHandler handler)
        : executor_(stream->executor()), options_(std::move(options)), handler_(std::move(handler)),
          context_(
              std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tls_client)),
          stream_(std::make_unique<net::TlsStream>(context_, std::move(stream))),
          timer_(executor_) {}

    void start() {
        const auto self = shared_from_this();
        boost::asio::post(executor_, [self] { self->configure_and_handshake(); });
    }

    void cancel() noexcept override {
        try {
            const auto self = shared_from_this();
            boost::asio::dispatch(executor_,
                                  [self] { self->finish(core::fail(cancelled_error())); });
        } catch (...) {
            if (stream_) {
                stream_->close();
            }
        }
    }

  private:
    core::Status configure() {
        context_->set_options(boost::asio::ssl::context::default_workarounds |
                              boost::asio::ssl::context::no_sslv2 |
                              boost::asio::ssl::context::no_sslv3);

        if (options_.verify_peer) {
            if (options_.server_name.empty()) {
                return core::fail(
                    configuration_error("TLS peer verification requires a server name"));
            }
            const auto roots = detail::builtin_ca_bundle_pem();
            boost::system::error_code error;
            context_->add_certificate_authority(boost::asio::buffer(roots.data(), roots.size()),
                                                error);
            if (error) {
                return core::fail(
                    transport_error("failed to load embedded TLS trust roots", error));
            }
            if (!options_.trusted_ca_pem.empty()) {
                context_->add_certificate_authority(
                    boost::asio::buffer(options_.trusted_ca_pem.data(),
                                        options_.trusted_ca_pem.size()),
                    error);
                if (error) {
                    return core::fail(
                        transport_error("failed to load custom TLS trust roots", error));
                }
            }
            stream_->stream_->set_verify_mode(boost::asio::ssl::verify_peer);
            stream_->stream_->set_verify_callback(
                boost::asio::ssl::host_name_verification(options_.server_name));
        } else {
            stream_->stream_->set_verify_mode(boost::asio::ssl::verify_none);
        }

        if (options_.maximum_tls_version) {
            if (SSL_set_max_proto_version(stream_->stream_->native_handle(),
                                          *options_.maximum_tls_version) != 1) {
                return core::fail(configuration_error("failed to configure TLS maximum version"));
            }
        }

        if (!options_.server_name.empty()) {
            boost::system::error_code address_error;
            (void)boost::asio::ip::make_address(options_.server_name, address_error);
            if (address_error && SSL_set_tlsext_host_name(stream_->stream_->native_handle(),
                                                          options_.server_name.c_str()) != 1) {
                return core::fail(configuration_error("failed to configure TLS server name"));
            }
        }

        if (!options_.alpn_protocols.empty()) {
            std::vector<unsigned char> wire;
            std::size_t wire_size = 0;
            for (const auto &protocol : options_.alpn_protocols) {
                if (protocol.empty() || protocol.size() > 255 ||
                    wire_size + protocol.size() + 1 > 65535) {
                    return core::fail(configuration_error("TLS ALPN protocol list is invalid"));
                }
                wire_size += protocol.size() + 1;
            }
            wire.reserve(wire_size);
            for (const auto &protocol : options_.alpn_protocols) {
                wire.push_back(static_cast<unsigned char>(protocol.size()));
                wire.insert(wire.end(), protocol.begin(), protocol.end());
            }
            if (SSL_set_alpn_protos(stream_->stream_->native_handle(), wire.data(),
                                    static_cast<unsigned int>(wire.size())) != 0) {
                return core::fail(configuration_error("failed to configure TLS ALPN"));
            }
        }
        return {};
    }

    void configure_and_handshake() {
        if (completed_) {
            return;
        }
        if (options_.deadline) {
            if (*options_.deadline <= std::chrono::steady_clock::now()) {
                finish(core::fail(timeout_error()));
                return;
            }
            timer_.expires_at(*options_.deadline);
            const auto self = shared_from_this();
            timer_.async_wait([self](const boost::system::error_code &error) {
                if (!error) {
                    self->finish(core::fail(timeout_error()));
                }
            });
        }
        const auto configured = configure();
        if (!configured) {
            finish(core::fail(configured.error()));
            return;
        }
        const auto self = shared_from_this();
        stream_->stream_->async_handshake(
            boost::asio::ssl::stream_base::client, [self](const boost::system::error_code &error) {
                if (self->completed_) {
                    return;
                }
                if (error) {
                    self->finish(core::fail(handshake_error(error)));
                    return;
                }
                const unsigned char *protocol = nullptr;
                unsigned int protocol_length = 0;
                SSL_get0_alpn_selected(self->stream_->stream_->native_handle(), &protocol,
                                       &protocol_length);
                std::string negotiated_alpn;
                if (protocol_length != 0) {
                    negotiated_alpn.assign(reinterpret_cast<const char *>(protocol),
                                           protocol_length);
                }
                std::unique_ptr<core::StreamHandle> stream;
                if (self->options_.handoff_raw_transport) {
                    stream = self->stream_->take_transport();
                } else {
                    stream = std::move(self->stream_);
                }
                if (!stream) {
                    self->finish(core::fail(
                        transport_error("TLS client handshake lost its underlying stream",
                                        boost::asio::error::operation_aborted)));
                    return;
                }
                TlsClientConnection connection{std::move(stream), std::move(negotiated_alpn)};
                self->finish(std::move(connection));
            });
    }

    void finish(core::Result<TlsClientConnection> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        (void)timer_.cancel();
        if (!result && stream_) {
            stream_->close();
            stream_.reset();
        }
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    boost::asio::any_io_executor executor_;
    TlsClientOptions options_;
    TlsClientHandler handler_;
    std::shared_ptr<boost::asio::ssl::context> context_;
    std::unique_ptr<net::TlsStream> stream_;
    boost::asio::steady_timer timer_;
    bool completed_ = false;
};

} // namespace detail

std::shared_ptr<TlsClientHandshake>
async_tls_client_handshake(std::unique_ptr<core::StreamHandle> stream, TlsClientOptions options,
                           TlsClientHandler handler) {
    if (!stream || !handler) {
        if (stream) {
            stream->close();
        }
        if (handler) {
            handler(core::fail(configuration_error(
                "TLS client handshake requires a stream and completion handler")));
        }
        return {};
    }
    auto operation = std::make_shared<detail::TlsClientHandshakeOperationImpl>(
        std::move(stream), std::move(options), std::move(handler));
    operation->start();
    return operation;
}

} // namespace clash_native::transport
