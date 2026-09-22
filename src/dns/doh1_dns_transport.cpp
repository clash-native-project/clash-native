#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/transport/exchange_session.hpp>
#include <clash_native/transport/tls_client.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace clash_native::dns {

namespace {

core::Error protocol_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context)};
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

const std::string *find_header(const transport::ExchangeResponse &response, std::string_view name) {
    const auto found = std::find_if(response.headers.begin(), response.headers.end(),
                                    [name](const transport::ExchangeField &header) {
                                        return lower_trimmed(header.name) == name;
                                    });
    return found == response.headers.end() ? nullptr : &found->value;
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
    Operation(Doh1DnsTransport &owner, ExchangeId exchange_id, DnsExchangeRequest request,
              Handler handler)
        : owner_(owner), exchange_id_(exchange_id), request_(std::move(request)),
          handler_(std::move(handler)), timer_(owner.runtime_.serialized_executor()) {}

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
    void connect() {
        const auto endpoint = owner_.config_.tcp_endpoint.value_or(boost::asio::ip::tcp::endpoint(
            owner_.config_.endpoint.address(),
            owner_.config_.endpoint.port() == 53 ? 443 : owner_.config_.endpoint.port()));
        const auto self = shared_from_this();
        struct ConnectReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<Operation> self;
            void set_value(core::StreamOpenResult result) && noexcept {
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
                self->start_tls(std::move(result.handle));
            }
            void set_error(std::exception_ptr error) && noexcept {
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const core::Error &failure) {
                    self->finish(core::fail(failure));
                } catch (...) {
                    self->finish(core::fail(core::Error{core::ErrorCode::endpoint_connection,
                                                        "DoH/HTTP/1.1 dialer failed"}));
                }
            }
            void set_stopped() && noexcept {}
        };
        async::start_with_receiver(
            owner_.config_.dialer->connect_stream(
                {core::Destination::address(endpoint.address(), endpoint.port()), std::nullopt}),
            ConnectReceiver{self});
    }

    void start_tls(std::unique_ptr<io::StreamHandle> stream) {
        const auto server_name = !owner_.config_.server_name.empty()
                                     ? owner_.config_.server_name
                                     : (!owner_.config_.hostname.empty()
                                            ? owner_.config_.hostname
                                            : owner_.config_.endpoint.address().to_string());
        transport::TlsClientOptions options;
        options.server_name = server_name;
        options.verify_peer = owner_.config_.verify_peer;
        options.alpn_protocols = {"http/1.1"};
        options.deadline = request_.deadline;
        const auto self = shared_from_this();
        tls_handshake_ = transport::async_tls_client_handshake(
            std::move(stream), std::move(options),
            [self](core::Result<transport::TlsClientConnection> result) mutable {
                self->tls_handshake_.reset();
                if (self->completed_) {
                    if (result && result->stream) {
                        result->stream->close();
                    }
                    return;
                }
                if (!result) {
                    self->finish(core::fail(result.error()));
                    return;
                }
                if (!result->negotiated_alpn.empty() && result->negotiated_alpn != "http/1.1") {
                    self->finish(core::fail({core::ErrorCode::carrier_handshake,
                                             "DoH upstream did not negotiate HTTP/1.1"}));
                    return;
                }
                self->start_http(std::move(result->stream));
            });
    }

    void start_http(std::unique_ptr<io::StreamHandle> stream) {
        http_session_ = transport::make_http1_exchange_session(std::move(stream));
        if (!http_session_) {
            finish(core::fail(
                {core::ErrorCode::configuration, "failed to create an HTTP/1.1 client session"}));
            return;
        }

        transport::ExchangeRequest request;
        request.method = "POST";
        request.scheme = "https";
        request.authority = authority_;
        request.target = owner_.config_.doh_path;
        request.headers = {{"accept", "application/dns-message"},
                           {"content-type", "application/dns-message"}};
        request.body = request_.query.wire;
        request.response_body_limit = 0xffff;
        request.keep_alive = false;

        const auto self = shared_from_this();
        http_exchange_id_ = http_session_->exchange(
            std::move(request), request_.deadline,
            [self](core::Result<transport::ExchangeResponse> response) mutable {
                self->http_exchange_started_ = false;
                if (self->completed_) {
                    return;
                }
                self->http_response(std::move(response));
            });
        http_exchange_started_ = true;
    }

    void http_response(core::Result<transport::ExchangeResponse> result) {
        if (!result) {
            finish(core::fail(result.error()));
            return;
        }
        const auto &response = result.value();
        if (response.version != 11 || response.status != 200) {
            finish(core::fail(protocol_error("DoH upstream returned an invalid HTTP response")));
            return;
        }
        const auto *content_type = find_header(response, "content-type");
        if (content_type == nullptr) {
            finish(core::fail(protocol_error("DoH upstream returned an invalid content type")));
            return;
        }
        const auto media_type = std::string_view(*content_type);
        const auto parameter = media_type.find(';');
        if (lower_trimmed(media_type.substr(0, parameter)) != "application/dns-message") {
            finish(core::fail(protocol_error("DoH upstream returned an invalid content type")));
            return;
        }
        if (response.body.empty()) {
            finish(core::fail(protocol_error("DoH upstream returned an empty DNS message")));
            return;
        }
        const auto decoded = DnsMessageCodec::decode_packet(response.body, request_.query.id);
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
        (void)timer_.cancel();
        if (tls_handshake_) {
            tls_handshake_->cancel();
            tls_handshake_.reset();
        }
        if (http_session_) {
            if (http_exchange_started_) {
                http_session_->cancel(http_exchange_id_);
                http_exchange_started_ = false;
            }
            http_session_->stop();
            http_session_.reset();
        }
        owner_.complete(exchange_id_, std::move(result));
    }

    Doh1DnsTransport &owner_;
    ExchangeId exchange_id_;
    DnsExchangeRequest request_;
    Handler handler_;
    boost::asio::steady_timer timer_;
    std::shared_ptr<transport::TlsClientHandshake> tls_handshake_;
    std::shared_ptr<transport::ExchangeSession> http_session_;
    transport::ExchangeSession::ExchangeId http_exchange_id_ = 0;
    std::string authority_;
    bool http_exchange_started_ = false;
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
