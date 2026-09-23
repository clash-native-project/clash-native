#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/transport/exchange_session.hpp>
#include <clash_native/transport/exchange_session_adapter.hpp>
#include <clash_native/transport/tls_client.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

core::Error protocol_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context)};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "DoH2 DNS query timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "DoH2 DNS query was cancelled"};
}

std::string lower_copy(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

std::string_view trim_ascii(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

const std::string *find_header(const transport::ExchangeResponse &response, std::string_view name) {
    const auto found = std::find_if(
        response.headers.begin(), response.headers.end(),
        [name](const transport::ExchangeField &header) { return lower_copy(header.name) == name; });
    return found == response.headers.end() ? nullptr : &found->value;
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

std::string authority_for(const DnsUpstreamConfig &config,
                          const boost::asio::ip::tcp::endpoint &endpoint) {
    if (!config.doh_authority.empty()) {
        return config.doh_authority;
    }
    std::string authority =
        !config.server_name.empty()
            ? config.server_name
            : (!config.hostname.empty() ? config.hostname : endpoint.address().to_string());
    if (authority.find(':') != std::string::npos && authority.front() != '[') {
        authority = '[' + authority + ']';
    }
    const auto port = endpoint.port();
    if (port != 443) {
        authority += ':' + std::to_string(port);
    }
    return authority;
}

} // namespace

class Doh2DnsTransport final : public DnsTransport {
  private:
    class Operation;
    class Session;

  public:
    Doh2DnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
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
    std::shared_ptr<Session> session();
    std::optional<std::uint16_t> next_query_id() noexcept;

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    std::unordered_map<ExchangeId, std::shared_ptr<Operation>> operations_;
    std::shared_ptr<Session> session_;
    std::unordered_set<std::uint16_t> active_query_ids_;
    ExchangeId next_exchange_id_ = 1;
    std::uint16_t next_query_id_ = 1;
    bool stopped_ = false;

    friend class Operation;
};

// This DNS adapter owns endpoint dialing and TLS negotiation. Once ALPN has
// selected h2, all HTTP/2 framing and stream multiplexing belongs to transport.
class Doh2DnsTransport::Session final : public std::enable_shared_from_this<Session> {
  public:
    using Handler = transport::ExchangeSession::Handler;

    Session(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint,
            std::string server_name, std::string authority, std::string path, bool verify_peer,
            std::shared_ptr<DnsUpstreamDialer> dialer)
        : runtime_(runtime), endpoint_(std::move(endpoint)), server_name_(std::move(server_name)),
          authority_(std::move(authority)), path_(std::move(path)), verify_peer_(verify_peer),
          dialer_(std::move(dialer)) {}

    ~Session() { stop(); }

    void exchange(std::uint16_t query_id, io::ExchangeRequest request,
                  std::chrono::steady_clock::time_point deadline, Handler handler) {
        if (stopped_ || retired_) {
            complete_immediately(std::move(handler), cancelled_error());
            return;
        }
        if (request.body.empty() || request.body.size() > 0xffff) {
            complete_immediately(std::move(handler),
                                 protocol_error("DoH2 DNS query exceeds message capacity"));
            return;
        }
        if (path_.empty() || path_.front() != '/' ||
            std::any_of(path_.begin(), path_.end(),
                        [](unsigned char value) { return value <= 0x20 || value == 0x7f; })) {
            complete_immediately(std::move(handler),
                                 core::Error{core::ErrorCode::configuration,
                                             "DoH2 path is not a valid origin-form target"});
            return;
        }

        auto pending = std::make_shared<Pending>(runtime_.serialized_executor());
        pending->request = std::move(request);
        pending->handler = std::move(handler);
        pending->timer.expires_at(deadline);
        const auto self = shared_from_this();
        pending->timer.async_wait([self, query_id](const boost::system::error_code &error) {
            if (!error) {
                self->fail_pending(query_id, timeout_error());
            }
        });
        pending_.emplace(query_id, pending);
        if (http_session_) {
            submit(query_id, pending);
        } else {
            connect_if_needed();
        }
    }

    void cancel(std::uint16_t query_id) noexcept { fail_pending(query_id, cancelled_error()); }

    void stop() noexcept {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        retired_ = true;
        ++connection_generation_;
        if (tls_handshake_) {
            tls_handshake_->cancel();
            tls_handshake_.reset();
        }
        if (http_session_) {
            auto session = std::move(http_session_);
            session->stop();
        }
        fail_all(cancelled_error());
    }

    bool retired() const noexcept { return retired_; }

  private:
    struct Pending {
        explicit Pending(boost::asio::any_io_executor executor) : timer(std::move(executor)) {}

        io::ExchangeRequest request;
        Handler handler;
        boost::asio::steady_timer timer;
        bool http_exchange_started = false;
    };

    void complete_immediately(Handler handler, core::Error error) {
        runtime_.scheduler().post(
            [handler = std::move(handler), error = std::move(error)]() mutable {
                if (handler) {
                    handler(core::fail(std::move(error)));
                }
            });
    }

    void connect_if_needed() {
        if (stopped_ || retired_ || connecting_ || http_session_ || pending_.empty()) {
            return;
        }
        connecting_ = true;
        const auto generation = connection_generation_;
        const auto self = shared_from_this();
        struct ConnectReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<Session> self;
            std::uint64_t generation;
            void set_value(core::StreamOpenResult result) && noexcept {
                const auto self = this->self;
                const auto generation = this->generation;
                if (generation != self->connection_generation_ || self->stopped_) {
                    if (result.handle) {
                        result.handle->close();
                    }
                    return;
                }
                if (!result.succeeded()) {
                    self->connection_failed(
                        result.error.value_or(core::Error{core::ErrorCode::endpoint_connection,
                                                          "DoH2 dialer failed to open a stream"}));
                    return;
                }
                transport::TlsClientOptions options;
                options.server_name = self->server_name_;
                options.verify_peer = self->verify_peer_;
                options.alpn_protocols = {"h2"};
                self->tls_handshake_ = transport::async_tls_client_handshake(
                    std::move(result.handle), std::move(options),
                    [self, generation](core::Result<transport::TlsClientConnection> tls) mutable {
                        self->tls_handshake_.reset();
                        if (generation != self->connection_generation_ || self->stopped_) {
                            if (tls && tls->stream) {
                                tls->stream->close();
                            }
                            return;
                        }
                        if (!tls) {
                            self->connection_failed(tls.error());
                            return;
                        }
                        if (tls->negotiated_alpn != "h2") {
                            tls->stream->close();
                            self->connection_failed(
                                {core::ErrorCode::carrier_handshake,
                                 "DoH2 upstream did not negotiate the h2 protocol"});
                            return;
                        }
                        self->connecting_ = false;
                        // Exchange-plane debt: the HTTP/2 session still speaks
                        // transport::; the adapter bridges it at the edge.
                        self->http_session_ = transport::adapt_transport_session(
                            transport::make_http2_exchange_session(std::move(tls->stream)));
                        if (!self->http_session_) {
                            self->connection_failed(
                                protocol_error("failed to create an HTTP/2 client session"));
                            return;
                        }
                        self->submit_waiting();
                    });
            }
            void set_error(std::exception_ptr error) && noexcept {
                if (generation != self->connection_generation_ || self->stopped_) {
                    return;
                }
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const core::Error &failure) {
                    self->connection_failed(failure);
                } catch (...) {
                    self->connection_failed(
                        core::Error{core::ErrorCode::endpoint_connection, "DoH2 dialer failed"});
                }
            }
            void set_stopped() && noexcept {}
        };
        async::start_with_receiver(
            dialer_->connect_stream(
                {core::Destination::address(endpoint_.address(), endpoint_.port()), std::nullopt}),
            ConnectReceiver{self, generation});
    }

    void submit_waiting() {
        std::vector<std::uint16_t> query_ids;
        query_ids.reserve(pending_.size());
        for (const auto &[query_id, pending] : pending_) {
            if (!pending->http_exchange_started) {
                query_ids.push_back(query_id);
            }
        }
        for (const auto query_id : query_ids) {
            const auto found = pending_.find(query_id);
            if (found != pending_.end() && !found->second->http_exchange_started) {
                submit(query_id, found->second);
            }
        }
    }

    void submit(std::uint16_t query_id, const std::shared_ptr<Pending> &pending) {
        if (!http_session_ || pending->http_exchange_started) {
            return;
        }
        struct SubmitReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<Session> self;
            std::uint16_t query_id;
            void set_value(io::ExchangeResponse response) && noexcept {
                self->finish_pending(query_id, transport::to_transport_response(response));
            }
            void set_error(std::exception_ptr error) && noexcept {
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const core::Error &failure) {
                    self->finish_pending(query_id, core::fail(failure));
                } catch (...) {
                    self->finish_pending(
                        query_id, core::fail(core::Error{core::ErrorCode::endpoint_connection,
                                                         "DoH2 exchange failed"}));
                }
            }
            void set_stopped() && noexcept {
                self->finish_pending(query_id, core::fail(cancelled_error()));
            }
        };
        const auto self = shared_from_this();
        pending->http_exchange_started = true;
        async::start_with_receiver(
            http_session_->exchange(std::move(pending->request), pending->timer.expiry()),
            SubmitReceiver{self, query_id});
    }

    void fail_pending(std::uint16_t query_id, core::Error error) {
        const auto found = pending_.find(query_id);
        if (found == pending_.end()) {
            return;
        }
        auto pending = std::move(found->second);
        pending_.erase(found);
        (void)pending->timer.cancel();
        // No per-exchange cancel: the io:: vocabulary cancels through the
        // stop token, and this edge owns no stop source. The orphaned HTTP
        // exchange still terminates on its own deadline and its late
        // terminal finds no pending and is dropped.
        auto handler = std::move(pending->handler);
        if (handler) {
            handler(core::fail(std::move(error)));
        }
        abandon_connect_if_idle();
    }

    void finish_pending(std::uint16_t query_id, core::Result<transport::ExchangeResponse> result) {
        const auto found = pending_.find(query_id);
        if (found == pending_.end()) {
            return;
        }
        auto pending = std::move(found->second);
        pending_.erase(found);
        (void)pending->timer.cancel();
        if (http_session_ && http_session_->retired()) {
            retired_ = true;
        }
        auto handler = std::move(pending->handler);
        if (handler) {
            handler(std::move(result));
        }
        abandon_connect_if_idle();
    }

    void fail_all(const core::Error &error) {
        std::vector<Handler> handlers;
        handlers.reserve(pending_.size());
        for (auto &[query_id, pending] : pending_) {
            (void)query_id;
            (void)pending->timer.cancel();
            if (pending->handler) {
                handlers.push_back(std::move(pending->handler));
            }
        }
        pending_.clear();
        for (auto &handler : handlers) {
            handler(core::fail(error));
        }
    }

    void connection_failed(core::Error error) {
        if (stopped_) {
            return;
        }
        retired_ = true;
        connecting_ = false;
        ++connection_generation_;
        if (tls_handshake_) {
            tls_handshake_->cancel();
            tls_handshake_.reset();
        }
        if (http_session_) {
            auto session = std::move(http_session_);
            session->stop();
        }
        fail_all(error);
    }

    void abandon_connect_if_idle() {
        if (!pending_.empty() || !connecting_) {
            return;
        }
        ++connection_generation_;
        connecting_ = false;
        if (tls_handshake_) {
            tls_handshake_->cancel();
            tls_handshake_.reset();
        }
    }

    runtime::AsioRuntime &runtime_;
    boost::asio::ip::tcp::endpoint endpoint_;
    std::string server_name_;
    std::string authority_;
    std::string path_;
    bool verify_peer_;
    std::shared_ptr<DnsUpstreamDialer> dialer_;
    std::shared_ptr<transport::TlsClientHandshake> tls_handshake_;
    std::shared_ptr<io::ExchangeSession> http_session_;
    std::unordered_map<std::uint16_t, std::shared_ptr<Pending>> pending_;
    std::uint64_t connection_generation_ = 0;
    bool connecting_ = false;
    bool retired_ = false;
    bool stopped_ = false;
};

class Doh2DnsTransport::Operation final
    : public std::enable_shared_from_this<Doh2DnsTransport::Operation> {
  public:
    Operation(Doh2DnsTransport &owner, ExchangeId exchange_id, DnsExchangeRequest request,
              Handler handler)
        : owner_(owner), exchange_id_(exchange_id), request_(std::move(request)),
          handler_(std::move(handler)) {}

    void start() {
        if (std::chrono::steady_clock::now() >= request_.deadline) {
            finish(core::fail(timeout_error()));
            return;
        }
        if (owner_.config_.doh_path.empty() || owner_.config_.doh_path.front() != '/' ||
            std::any_of(owner_.config_.doh_path.begin(), owner_.config_.doh_path.end(),
                        [](unsigned char value) { return value <= 0x20 || value == 0x7f; })) {
            finish(core::fail(
                {core::ErrorCode::configuration, "DoH2 path is not a valid origin-form target"}));
            return;
        }
        if (request_.query.wire.empty() || request_.query.wire.size() > 0xffff) {
            finish(core::fail(protocol_error("DoH2 DNS query wire length is invalid")));
            return;
        }
        const auto query_id = owner_.next_query_id();
        if (!query_id) {
            finish(core::fail({core::ErrorCode::configuration,
                               "DoH2 transport has no available transaction IDs"}));
            return;
        }
        query_id_ = *query_id;
        owner_.active_query_ids_.insert(query_id_);
        const auto encoded = DnsMessageCodec::rewrite_id(request_.query, query_id_);
        if (!encoded) {
            finish(core::fail(encoded.error()));
            return;
        }

        session_ = owner_.session();
        if (!session_) {
            finish(core::fail(
                {core::ErrorCode::configuration, "DoH2 transport session is not available"}));
            return;
        }
        const auto endpoint = owner_.config_.tcp_endpoint.value_or(boost::asio::ip::tcp::endpoint(
            owner_.config_.endpoint.address(),
            owner_.config_.endpoint.port() == 53 ? 443 : owner_.config_.endpoint.port()));
        io::ExchangeRequest request;
        request.method = "POST";
        request.scheme = "https";
        request.authority = authority_for(owner_.config_, endpoint);
        request.target = owner_.config_.doh_path;
        request.headers = {{"accept", "application/dns-message"},
                           {"content-type", "application/dns-message"}};
        request.body = encoded.value();
        request.response_body_limit = 0xffff;
        const auto self = shared_from_this();
        session_->exchange(query_id_, std::move(request), request_.deadline,
                           [self](core::Result<transport::ExchangeResponse> result) mutable {
                               self->session_finished(std::move(result));
                           });
        exchange_started_ = true;
    }

    void cancel() {
        if (completed_) {
            return;
        }
        completed_ = true;
        close_session_exchange();
        owner_.complete(exchange_id_, core::fail(cancelled_error()));
    }

    Handler take_handler() { return std::move(handler_); }
    std::uint16_t query_id() const noexcept { return query_id_; }

  private:
    void session_finished(core::Result<transport::ExchangeResponse> result) {
        exchange_started_ = false;
        if (completed_) {
            return;
        }
        if (!result) {
            finish(core::fail(result.error()));
            return;
        }
        const auto &response = result.value();
        if (response.version != 20 || response.status != 200) {
            finish(core::fail(protocol_error("DoH2 upstream returned a non-success response")));
            return;
        }
        const auto *content_type = find_header(response, "content-type");
        const auto media_type =
            content_type == nullptr
                ? std::string_view{}
                : std::string_view(*content_type).substr(0, content_type->find(';'));
        if (lower_copy(trim_ascii(media_type)) != "application/dns-message") {
            finish(core::fail(protocol_error("DoH2 upstream returned an invalid content type")));
            return;
        }
        if (response.body.empty()) {
            finish(core::fail(protocol_error("DoH2 upstream returned an empty DNS message")));
            return;
        }
        const auto decoded = DnsMessageCodec::decode_packet(response.body, query_id_);
        if (!decoded) {
            finish(core::fail(decoded.error()));
            return;
        }
        if (!matches_question(decoded.value(), request_.query)) {
            finish(core::fail(protocol_error("DoH2 response question does not match the query")));
            return;
        }
        finish(decoded);
    }

    void close_session_exchange() noexcept {
        if (session_ && exchange_started_) {
            session_->cancel(query_id_);
            exchange_started_ = false;
        }
    }

    void finish(core::Result<DnsPacket> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        close_session_exchange();
        owner_.complete(exchange_id_, std::move(result));
    }

    Doh2DnsTransport &owner_;
    ExchangeId exchange_id_;
    DnsExchangeRequest request_;
    Handler handler_;
    std::shared_ptr<Session> session_;
    std::uint16_t query_id_ = 0;
    bool exchange_started_ = false;
    bool completed_ = false;
};

std::optional<std::uint16_t> Doh2DnsTransport::next_query_id() noexcept {
    for (std::size_t attempt = 0; attempt < 0xffff; ++attempt) {
        const auto query_id = next_query_id_++;
        if (next_query_id_ == 0) {
            next_query_id_ = 1;
        }
        if (query_id != 0 && !active_query_ids_.contains(query_id)) {
            return query_id;
        }
    }
    return std::nullopt;
}

std::shared_ptr<Doh2DnsTransport::Session> Doh2DnsTransport::session() {
    if (stopped_) {
        return nullptr;
    }
    if (!session_ || session_->retired()) {
        const auto endpoint = config_.tcp_endpoint.value_or(boost::asio::ip::tcp::endpoint(
            config_.endpoint.address(),
            config_.endpoint.port() == 53 ? 443 : config_.endpoint.port()));
        const auto server_name =
            config_.server_name.empty()
                ? (!config_.hostname.empty() ? config_.hostname : endpoint.address().to_string())
                : config_.server_name;
        session_ = std::make_shared<Session>(runtime_, endpoint, server_name,
                                             authority_for(config_, endpoint), config_.doh_path,
                                             config_.verify_peer, config_.dialer);
    }
    return session_;
}

DnsTransport::ExchangeId Doh2DnsTransport::exchange(DnsExchangeRequest request, Handler handler) {
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

void Doh2DnsTransport::cancel(ExchangeId exchange_id) noexcept {
    const auto operation = operations_.find(exchange_id);
    if (operation != operations_.end()) {
        operation->second->cancel();
    }
}

void Doh2DnsTransport::stop() noexcept {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    if (session_) {
        session_->stop();
    }
    while (!operations_.empty()) {
        operations_.begin()->second->cancel();
    }
}

void Doh2DnsTransport::complete(ExchangeId exchange_id, core::Result<DnsPacket> result) {
    const auto operation = operations_.find(exchange_id);
    if (operation == operations_.end()) {
        return;
    }
    auto current = std::move(operation->second);
    operations_.erase(operation);
    active_query_ids_.erase(current->query_id());
    auto handler = current->take_handler();
    if (handler) {
        handler(std::move(result));
    }
}

std::shared_ptr<DnsTransport> make_doh2_dns_transport(runtime::AsioRuntime &runtime,
                                                      DnsUpstreamConfig config) {
    return std::make_shared<Doh2DnsTransport>(runtime, std::move(config));
}

} // namespace clash_native::dns
