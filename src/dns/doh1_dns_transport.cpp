#include <clash_native/async/bridge.hpp>
#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/transport/http_sessions.hpp>
#include <clash_native/transport/tls_client.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

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

const std::string *find_header(const io::ExchangeResponse &response, std::string_view name) {
    const auto found = std::find_if(
        response.headers.begin(), response.headers.end(),
        [name](const io::ExchangeField &header) { return lower_trimmed(header.name) == name; });
    return found == response.headers.end() ? nullptr : &found->value;
}

} // namespace

class Doh1DnsTransport final : public DnsTransport,
                               public std::enable_shared_from_this<Doh1DnsTransport> {
  private:
    class Operation;

    using OpenHandler = async::BridgeSender<DnsExchangeResult>::Handler;

  public:
    Doh1DnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
        : runtime_(runtime), config_(std::move(config)) {
        if (!config_.dialer) {
            config_.dialer = make_direct_dns_upstream_dialer(runtime_);
        }
    }

    io::AnySender<DnsExchangeResult> exchange(DnsExchangeRequest request) override;
    void stop() noexcept override;
    DnsExchangeId open_exchange(DnsExchangeRequest request, OpenHandler handler);
    void cancel_exchange(DnsExchangeId exchange_id) noexcept;

  private:
    void complete(DnsExchangeId exchange_id, core::Result<DnsPacket> result);

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    std::unordered_map<DnsExchangeId, std::shared_ptr<Operation>> operations_;
    DnsExchangeId next_exchange_id_ = 1;
    bool stopped_ = false;

    friend class Operation;
};

class Doh1DnsTransport::Operation final : public std::enable_shared_from_this<Operation> {
  public:
    Operation(Doh1DnsTransport &owner, DnsExchangeId exchange_id, DnsExchangeRequest request,
              OpenHandler handler)
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
        // The scope only owns this exchange task (merge-shaped usage);
        // teardown is guard-driven, so no stop is ever requested: the
        // request deadline bounds any orphaned chain.
        scope_.spawn(run(shared_from_this()));
    }

    void cancel() {
        if (!completed_) {
            finish(core::fail(cancelled_error()));
        }
    }

    OpenHandler take_handler() { return std::move(handler_); }

  private:
    // Straight-line exchange chain: dial, TLS handshake, HTTP exchange,
    // response validation. Every terminal funnels through finish(), so the
    // spawned task always ends with a value.
    static exec::task<void> run(std::shared_ptr<Operation> self) {
        try {
            const auto endpoint = self->owner_.config_.tcp_endpoint.value_or(
                boost::asio::ip::tcp::endpoint(self->owner_.config_.endpoint.address(),
                                               self->owner_.config_.endpoint.port() == 53
                                                   ? 443
                                                   : self->owner_.config_.endpoint.port()));
            auto opened = co_await self->owner_.config_.dialer->connect_stream(
                {core::Destination::address(endpoint.address(), endpoint.port()), std::nullopt});
            if (self->completed_) {
                if (opened.handle) {
                    opened.handle->close();
                }
                co_return;
            }
            if (!opened.succeeded()) {
                self->finish(core::fail(opened.error.value_or(
                    core::Error{core::ErrorCode::endpoint_connection,
                                "DoH/HTTP/1.1 dialer failed to open a stream"})));
                co_return;
            }

            const auto server_name = !self->owner_.config_.server_name.empty()
                                         ? self->owner_.config_.server_name
                                     : !self->owner_.config_.hostname.empty()
                                         ? self->owner_.config_.hostname
                                         : self->owner_.config_.endpoint.address().to_string();
            transport::TlsClientOptions tls_options;
            tls_options.server_name = server_name;
            tls_options.verify_peer = self->owner_.config_.verify_peer;
            tls_options.alpn_protocols = {"http/1.1"};
            tls_options.deadline = self->request_.deadline;
            transport::TlsClientConnection tls;
            try {
                tls = co_await transport::async_tls_client_handshake(std::move(opened.handle),
                                                                     std::move(tls_options));
            } catch (const core::Error &failure) {
                self->finish(core::fail(failure));
                co_return;
            } catch (...) {
                self->finish(core::fail(core::Error{core::ErrorCode::endpoint_connection,
                                                    "DoH/HTTP/1.1 TLS handshake failed"}));
                co_return;
            }
            if (self->completed_) {
                if (tls.stream) {
                    tls.stream->close();
                }
                co_return;
            }
            if (!tls.negotiated_alpn.empty() && tls.negotiated_alpn != "http/1.1") {
                self->finish(core::fail({core::ErrorCode::carrier_handshake,
                                         "DoH upstream did not negotiate HTTP/1.1"}));
                co_return;
            }

            self->http_session_ = transport::make_http1_exchange_session(std::move(tls.stream));
            if (!self->http_session_) {
                self->finish(core::fail({core::ErrorCode::configuration,
                                         "failed to create an HTTP/1.1 client session"}));
                co_return;
            }
            io::ExchangeRequest request;
            request.method = "POST";
            request.scheme = "https";
            request.authority = self->authority_;
            request.target = self->owner_.config_.doh_path;
            request.headers = {{"accept", "application/dns-message"},
                               {"content-type", "application/dns-message"}};
            request.body = self->request_.query.wire;
            request.response_body_limit = 0xffff;
            request.keep_alive = false;
            io::ExchangeResponse response;
            try {
                response = co_await self->http_session_->exchange(std::move(request),
                                                                  self->request_.deadline);
            } catch (const core::Error &failure) {
                self->finish(core::fail(failure));
                co_return;
            } catch (...) {
                self->finish(core::fail(core::Error{core::ErrorCode::endpoint_connection,
                                                    "DoH/HTTP/1.1 exchange failed"}));
                co_return;
            }
            if (self->completed_) {
                co_return;
            }
            self->http_response(std::move(response));
        } catch (...) {
            self->finish(core::fail(
                core::Error{core::ErrorCode::transport_io, "DoH/HTTP/1.1 exchange failed"}));
        }
        co_return;
    }

    void http_response(io::ExchangeResponse response) {
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
        if (http_session_) {
            // Single-use session: stop() fails the in-flight exchange and
            // tears the session down; no per-exchange cancel is needed.
            http_session_->stop();
            http_session_.reset();
        }
        owner_.complete(exchange_id_, std::move(result));
    }

    Doh1DnsTransport &owner_;
    DnsExchangeId exchange_id_;
    DnsExchangeRequest request_;
    OpenHandler handler_;
    boost::asio::steady_timer timer_;
    std::shared_ptr<io::ExchangeSession> http_session_;
    std::string authority_;
    // Owns the single exchange chain task, which always ends with a value.
    exec::async_scope scope_;
    bool completed_ = false;
};

io::AnySender<DnsExchangeResult> Doh1DnsTransport::exchange(DnsExchangeRequest request) {
    auto box = std::make_shared<std::optional<DnsExchangeRequest>>(std::move(request));
    auto self = shared_from_this();
    return async::bridge_sender<DnsExchangeResult>(
        [self, box](async::BridgeSender<DnsExchangeResult>::Handler done) mutable {
            if (!box || !*box) {
                done(core::fail(cancelled_error()));
                using AbortFn = async::BridgeSender<DnsExchangeResult>::AbortFn;
                return AbortFn{[] {}};
            }
            const auto exchange_id = self->open_exchange(std::move(**box), std::move(done));
            box->reset();
            using AbortFn = async::BridgeSender<DnsExchangeResult>::AbortFn;
            return AbortFn{[self, exchange_id] { self->cancel_exchange(exchange_id); }};
        });
}

DnsExchangeId Doh1DnsTransport::open_exchange(DnsExchangeRequest request, OpenHandler handler) {
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

void Doh1DnsTransport::cancel_exchange(DnsExchangeId exchange_id) noexcept {
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

void Doh1DnsTransport::complete(DnsExchangeId exchange_id, core::Result<DnsPacket> result) {
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
