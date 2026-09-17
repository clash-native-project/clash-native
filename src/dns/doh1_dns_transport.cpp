#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>

#include "builtin_ca_bundle.hpp"
#include "stream_handle_adapter.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

namespace beast = boost::beast;
namespace http = beast::http;

core::Error io_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

core::Error protocol_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context)};
}

core::Error handshake_error(const boost::system::error_code &error) {
    return {core::ErrorCode::carrier_handshake, "DoH/HTTP/1.1 TLS handshake failed",
            std::error_code(error.value(), std::system_category())};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "DoH/HTTP/1.1 query timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "DoH/HTTP/1.1 exchange was cancelled"};
}

std::string lower_trimmed(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

bool contains_http_control(std::string_view value) {
    return std::any_of(value.begin(), value.end(), [](unsigned char character) {
        return character <= 0x20 || character == 0x7f;
    });
}

bool matches_question(const DnsPacket &response, const DnsPacket &query) {
    if (!response.response() || response.questions.size() != query.questions.size()) {
        return false;
    }
    return std::equal(response.questions.begin(), response.questions.end(), query.questions.begin(),
                      [](const DnsQuestion &actual, const DnsQuestion &expected) {
                          return normalize_name(actual.name) == normalize_name(expected.name) &&
                                 actual.type == expected.type &&
                                 actual.class_code == expected.class_code;
                      });
}

} // namespace

class Doh1DnsTransport final : public DnsTransport {
  private:
    class Operation;

  public:
    Doh1DnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
        : runtime_(runtime), config_(std::move(config)) {
        if (!config_.dialer) {
            config_.dialer = make_direct_dns_upstream_dialer(runtime_);
        }
    }

    ExchangeId exchange(DnsExchangeRequest request, Handler handler) override;
    void cancel(ExchangeId exchange_id) noexcept override;
    void stop() noexcept override;

  private:
    void complete(ExchangeId exchange_id, core::Result<DnsPacket> result);

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    std::unordered_map<ExchangeId, std::shared_ptr<Operation>> operations_;
    ExchangeId next_exchange_id_ = 1;
    bool stopped_ = false;

    friend class Operation;
};

class Doh1DnsTransport::Operation final : public std::enable_shared_from_this<Operation> {
  public:
    using SslStream = beast::ssl_stream<StreamHandleAdapter>;
    using Request = http::request<http::vector_body<std::uint8_t>>;
    using RequestSerializer = http::request_serializer<http::vector_body<std::uint8_t>>;
    using ResponseParser = http::response_parser<http::vector_body<std::uint8_t>>;

    Operation(Doh1DnsTransport &owner, ExchangeId exchange_id, DnsExchangeRequest request,
              Handler handler)
        : owner_(owner), exchange_id_(exchange_id), request_(std::move(request)),
          handler_(std::move(handler)), timer_(owner.runtime_.context()),
          ssl_context_(boost::asio::ssl::context::tls_client) {}

    void start() {
        if (std::chrono::steady_clock::now() >= request_.deadline) {
            finish(core::fail(timeout_error()));
            return;
        }
        if (request_.query.wire.empty() || request_.query.wire.size() > 0xffff) {
            finish(core::fail(protocol_error("DoH DNS query wire length is invalid")));
            return;
        }
        if (owner_.config_.doh_path.empty() || owner_.config_.doh_path.front() != '/' ||
            contains_http_control(owner_.config_.doh_path)) {
            finish(core::fail({core::ErrorCode::configuration,
                               "DoH/HTTP/1.1 path is not a valid origin-form target"}));
            return;
        }

        authority_ = owner_.config_.doh_authority;
        if (authority_.empty()) {
            authority_ = !owner_.config_.server_name.empty()
                             ? owner_.config_.server_name
                             : (!owner_.config_.hostname.empty()
                                    ? owner_.config_.hostname
                                    : owner_.config_.endpoint.address().to_string());
            if (authority_.find(':') != std::string::npos && authority_.front() != '[') {
                authority_ = '[' + authority_ + ']';
            }
            const auto port = owner_.config_.endpoint.port() == 53 ? std::uint16_t{443}
                                                                   : owner_.config_.endpoint.port();
            if (port != 443) {
                authority_ += ':' + std::to_string(port);
            }
        }
        if (contains_http_control(authority_)) {
            finish(core::fail({core::ErrorCode::configuration,
                               "DoH/HTTP/1.1 authority contains invalid characters"}));
            return;
        }

        timer_.expires_at(request_.deadline);
        const auto self = shared_from_this();
        timer_.async_wait([self](const boost::system::error_code &error) {
            if (!error) {
                self->finish(core::fail(timeout_error()));
            }
        });
        connect();
    }

    void cancel() {
        if (!completed_) {
            finish(core::fail(cancelled_error()));
        }
    }

    Handler take_handler() { return std::move(handler_); }

  private:
    bool configure_tls() {
        boost::system::error_code error;
        if (owner_.config_.verify_peer) {
            const auto roots = detail::builtin_ca_bundle_pem();
            ssl_context_.add_certificate_authority(boost::asio::buffer(roots.data(), roots.size()),
                                                   error);
            if (error) {
                finish(core::fail(io_error("failed to load embedded DoH trust roots", error)));
                return false;
            }
        }
        ssl_stream_->set_verify_mode(owner_.config_.verify_peer ? boost::asio::ssl::verify_peer
                                                                : boost::asio::ssl::verify_none);
        const auto server_name = !owner_.config_.server_name.empty()
                                     ? owner_.config_.server_name
                                     : (!owner_.config_.hostname.empty()
                                            ? owner_.config_.hostname
                                            : owner_.config_.endpoint.address().to_string());
        if (!server_name.empty() &&
            SSL_set_tlsext_host_name(ssl_stream_->native_handle(), server_name.c_str()) != 1) {
            finish(core::fail(
                {core::ErrorCode::configuration, "failed to configure DoH/HTTP/1.1 server name"}));
            return false;
        }
        if (owner_.config_.verify_peer) {
            ssl_stream_->set_verify_callback(boost::asio::ssl::host_name_verification(server_name));
        }
        static constexpr unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        if (SSL_set_alpn_protos(ssl_stream_->native_handle(), alpn, sizeof(alpn)) != 0) {
            finish(core::fail(
                {core::ErrorCode::configuration, "failed to configure DoH/HTTP/1.1 ALPN"}));
            return false;
        }
        return true;
    }

    void connect() {
        const auto endpoint = owner_.config_.tcp_endpoint.value_or(boost::asio::ip::tcp::endpoint(
            owner_.config_.endpoint.address(),
            owner_.config_.endpoint.port() == 53 ? 443 : owner_.config_.endpoint.port()));
        const auto self = shared_from_this();
        owner_.config_.dialer->connect_stream(
            {core::Destination::address(endpoint.address(), endpoint.port()), std::nullopt},
            [self](core::StreamOpenResult result) mutable {
                if (self->completed_) {
                    if (result.handle) {
                        result.handle->close();
                    }
                    return;
                }
                if (!result.succeeded()) {
                    self->finish(core::fail(result.error.value_or(
                        core::Error{core::ErrorCode::endpoint_connection,
                                    "DoH/HTTP/1.1 dialer failed to open a stream"})));
                    return;
                }
                self->ssl_stream_ = std::make_unique<SslStream>(
                    StreamHandleAdapter(std::move(result.handle)), self->ssl_context_);
                if (self->configure_tls()) {
                    self->handshake();
                }
            });
    }

    void handshake() {
        const auto self = shared_from_this();
        ssl_stream_->async_handshake(
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
                SSL_get0_alpn_selected(self->ssl_stream_->native_handle(), &protocol,
                                       &protocol_length);
                constexpr std::string_view expected = "http/1.1";
                if (protocol_length != 0 &&
                    (protocol_length != expected.size() ||
                     !std::equal(protocol, protocol + protocol_length, expected.begin()))) {
                    self->finish(core::fail({core::ErrorCode::carrier_handshake,
                                             "DoH upstream did not negotiate HTTP/1.1"}));
                    return;
                }
                self->send_request();
            });
    }

    void send_request() {
        request_message_.version(11);
        request_message_.method(http::verb::post);
        request_message_.target(owner_.config_.doh_path);
        request_message_.set(http::field::host, authority_);
        request_message_.set(http::field::accept, "application/dns-message");
        request_message_.set(http::field::content_type, "application/dns-message");
        request_message_.keep_alive(false);
        request_message_.body() = request_.query.wire;
        request_message_.prepare_payload();

        RequestSerializer serializer(request_message_);
        boost::system::error_code error;
        while (!serializer.is_done()) {
            std::size_t serialized_size = 0;
            serializer.next(error, [this, &serialized_size](boost::system::error_code &visit_error,
                                                            const auto &buffers) {
                if (visit_error) {
                    return;
                }
                serialized_size = beast::buffer_bytes(buffers);
                const auto offset = request_wire_.size();
                request_wire_.resize(offset + serialized_size);
                serialized_size = boost::asio::buffer_copy(
                    boost::asio::buffer(request_wire_.data() + offset, serialized_size), buffers);
            });
            if (error || serialized_size == 0) {
                finish(core::fail(protocol_error("failed to serialize DoH/HTTP/1.1 request")));
                return;
            }
            serializer.consume(serialized_size);
        }

        const auto self = shared_from_this();
        boost::asio::async_write(*ssl_stream_, boost::asio::buffer(request_wire_),
                                 [self](const boost::system::error_code &error, std::size_t) {
                                     if (self->completed_) {
                                         return;
                                     }
                                     if (error) {
                                         self->finish(core::fail(io_error(
                                             "failed to send DoH/HTTP/1.1 request", error)));
                                         return;
                                     }
                                     self->read_response();
                                 });
    }

    void read_response() {
        response_parser_.body_limit(0xffff);
        response_parser_.eager(true);
        read_response_chunk();
    }

    void read_response_chunk() {
        const auto self = shared_from_this();
        ssl_stream_->async_read_some(
            boost::asio::buffer(read_buffer_),
            [self](const boost::system::error_code &error, std::size_t size) {
                if (self->completed_) {
                    return;
                }
                if (error) {
                    if (error == boost::asio::error::eof) {
                        boost::system::error_code parse_error;
                        self->response_parser_.put_eof(parse_error);
                        if (!parse_error && self->response_parser_.is_done()) {
                            self->finish_response();
                            return;
                        }
                    }
                    const bool framing_error = error == http::error::body_limit ||
                                               error == http::error::partial_message ||
                                               error == http::error::bad_chunk;
                    self->finish(core::fail(
                        framing_error ? protocol_error("DoH/HTTP/1.1 response framing failed")
                                      : io_error("failed to read DoH/HTTP/1.1 response", error)));
                    return;
                }
                boost::system::error_code parse_error;
                (void)self->response_parser_.put(
                    boost::asio::buffer(self->read_buffer_.data(), size), parse_error);
                if (parse_error == http::error::need_more) {
                    parse_error.clear();
                }
                if (parse_error) {
                    self->finish(
                        core::fail(protocol_error("DoH/HTTP/1.1 response framing failed")));
                    return;
                }
                if (self->response_parser_.is_done()) {
                    self->finish_response();
                    return;
                }
                self->read_response_chunk();
            });
    }

    void finish_response() {
        const auto response = response_parser_.get();
        if (response.version() != 11 || response.result() != http::status::ok) {
            finish(core::fail(protocol_error("DoH upstream returned an invalid HTTP response")));
            return;
        }
        const auto content_type = response.find(http::field::content_type);
        if (content_type == response.end()) {
            finish(core::fail(protocol_error("DoH upstream returned an invalid content type")));
            return;
        }
        auto media_type =
            std::string_view(content_type->value().data(), content_type->value().size());
        const auto parameter = media_type.find(';');
        if (lower_trimmed(media_type.substr(0, parameter)) != "application/dns-message") {
            finish(core::fail(protocol_error("DoH upstream returned an invalid content type")));
            return;
        }
        const auto &body = response.body();
        if (body.empty()) {
            finish(core::fail(protocol_error("DoH upstream returned an empty DNS message")));
            return;
        }
        const auto decoded = DnsMessageCodec::decode_packet(body, request_.query.id);
        if (!decoded) {
            finish(core::fail(decoded.error()));
            return;
        }
        if (!matches_question(decoded.value(), request_.query)) {
            finish(core::fail(protocol_error("DoH response question does not match the query")));
            return;
        }
        finish(decoded);
    }

    void finish(core::Result<DnsPacket> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        boost::system::error_code ignored;
        timer_.cancel();
        if (ssl_stream_) {
            ssl_stream_->next_layer().close();
            ssl_stream_.reset();
        }
        owner_.complete(exchange_id_, std::move(result));
    }

    Doh1DnsTransport &owner_;
    ExchangeId exchange_id_;
    DnsExchangeRequest request_;
    Handler handler_;
    boost::asio::steady_timer timer_;
    boost::asio::ssl::context ssl_context_;
    std::unique_ptr<SslStream> ssl_stream_;
    std::array<std::uint8_t, 16384> read_buffer_{};
    Request request_message_;
    std::vector<std::uint8_t> request_wire_;
    ResponseParser response_parser_;
    std::string authority_;
    bool completed_ = false;
};

DnsTransport::ExchangeId Doh1DnsTransport::exchange(DnsExchangeRequest request, Handler handler) {
    const auto exchange_id = next_exchange_id_++;
    auto operation =
        std::make_shared<Operation>(*this, exchange_id, std::move(request), std::move(handler));
    operations_.emplace(exchange_id, operation);
    if (stopped_) {
        operation->cancel();
    } else {
        operation->start();
    }
    return exchange_id;
}

void Doh1DnsTransport::cancel(ExchangeId exchange_id) noexcept {
    const auto found = operations_.find(exchange_id);
    if (found != operations_.end()) {
        found->second->cancel();
    }
}

void Doh1DnsTransport::stop() noexcept {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    while (!operations_.empty()) {
        operations_.begin()->second->cancel();
    }
}

void Doh1DnsTransport::complete(ExchangeId exchange_id, core::Result<DnsPacket> result) {
    const auto found = operations_.find(exchange_id);
    if (found == operations_.end()) {
        return;
    }
    auto operation = std::move(found->second);
    operations_.erase(found);
    auto handler = operation->take_handler();
    if (handler) {
        handler(std::move(result));
    }
}

std::shared_ptr<DnsTransport> make_doh1_dns_transport(runtime::AsioRuntime &runtime,
                                                      DnsUpstreamConfig config) {
    return std::make_shared<Doh1DnsTransport>(runtime, std::move(config));
}

} // namespace clash_native::dns
