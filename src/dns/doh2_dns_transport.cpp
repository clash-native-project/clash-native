#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/detached.hpp>
#include <clash_native/async/timer.hpp>
#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/transport/http_sessions.hpp>
#include <clash_native/transport/tls_client.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <exec/async_scope.hpp>
#include <exec/task.hpp>
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

const std::string *find_header(const io::ExchangeResponse &response, std::string_view name) {
    const auto found = std::find_if(
        response.headers.begin(), response.headers.end(),
        [name](const io::ExchangeField &header) { return lower_copy(header.name) == name; });
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

class Doh2DnsTransport final : public DnsTransport,
                               public std::enable_shared_from_this<Doh2DnsTransport> {
  private:
    class Operation;
    class Session;

    using OpenHandler = async::BridgeHandler<DnsExchangeResult>;

  public:
    Doh2DnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
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
    std::shared_ptr<Session> session();
    std::optional<std::uint16_t> next_query_id() noexcept;

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    std::unordered_map<DnsExchangeId, std::shared_ptr<Operation>> operations_;
    std::shared_ptr<Session> session_;
    std::unordered_set<std::uint16_t> active_query_ids_;
    // Owns per-exchange run() tasks, which always end with a value.
    exec::async_scope run_scope_;
    DnsExchangeId next_exchange_id_ = 1;
    std::uint16_t next_query_id_ = 1;
    bool stopped_ = false;

    friend class Operation;
};

// This DNS adapter owns endpoint dialing and TLS negotiation. Once ALPN has
// selected h2, all HTTP/2 framing and stream multiplexing belongs to transport.
class Doh2DnsTransport::Session final : public std::enable_shared_from_this<Session> {
  public:
    using Handler = std::function<void(core::Result<io::ExchangeResponse>)>;

    Session(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint,
            std::string server_name, std::string authority, std::string path, bool verify_peer,
            std::shared_ptr<DnsUpstreamDialer> dialer)
        : runtime_(runtime), endpoint_(std::move(endpoint)), server_name_(std::move(server_name)),
          authority_(std::move(authority)), path_(std::move(path)), verify_peer_(verify_peer),
          dialer_(std::move(dialer)) {}

    // Strand hop: every state touch below runs on the runtime strand. The
    // bridge starter, aborters, stop(), and task continuations after
    // co_await all run on arbitrary threads; they post here and return.
    // stopped_/retired_ are atomic fast flags so arbitrary threads can
    // early-out; the authoritative checks still run on the strand.
    template <typename Fn> void post_state(Fn &&fn) {
        const auto self = shared_from_this();
        boost::asio::post(runtime_.serialized_executor(),
                          [self, fn = std::forward<Fn>(fn)]() mutable { fn(self); });
    }

    ~Session() {
        // Must not touch strand state here: a posted lambda may still hold
        // `self` (keeping the Session alive past the last owner), and
        // handlers/anchors are drained on the strand. If this destructor
        // runs, no posted lambda is outstanding... except the runtime may
        // already be stopped, in which case posted work never runs and the
        // Session must still release its handlers inline. Guard each.
        stopped_ = true;
        retired_ = true;
    }

    io::AnySender<core::Result<io::ExchangeResponse>>
    exchange(std::uint16_t query_id, io::ExchangeRequest request,
             std::chrono::steady_clock::time_point deadline) {
        auto self = shared_from_this();
        // Shared: the bridge starter is a std::function and must be
        // copyable; a second start after the moves fails fast instead of
        // hanging.
        auto state = std::make_shared<
            std::tuple<io::ExchangeRequest, std::chrono::steady_clock::time_point, bool>>(
            std::move(request), deadline, true);
        return async::bridge_sender<core::Result<io::ExchangeResponse>>(
            [self, query_id, state](Handler terminal) mutable {
                if (!std::get<2>(*state)) {
                    terminal(core::fail(cancelled_error()));
                    return async::CallbackAbortFn{};
                }
                std::get<2>(*state) = false;
                auto owned_request = std::move(std::get<0>(*state));
                const auto owned_deadline = std::get<1>(*state);
                // Validation is thread-local; state touches hop below.
                if (self->stopped_.load() || self->retired_.load()) {
                    terminal(core::fail(cancelled_error()));
                    return async::CallbackAbortFn{};
                }
                if (owned_request.body.empty() || owned_request.body.size() > 0xffff) {
                    terminal(core::fail(protocol_error("DoH2 DNS query exceeds message capacity")));
                    return async::CallbackAbortFn{};
                }
                if (self->path_.empty() || self->path_.front() != '/' ||
                    std::any_of(self->path_.begin(), self->path_.end(), [](unsigned char value) {
                        return value <= 0x20 || value == 0x7f;
                    })) {
                    terminal(
                        core::fail(core::Error{core::ErrorCode::configuration,
                                               "DoH2 path is not a valid origin-form target"}));
                    return async::CallbackAbortFn{};
                }
                auto terminal_box = std::make_shared<std::optional<Handler>>(std::move(terminal));
                self->post_state([query_id, owned_request = std::move(owned_request),
                                  owned_deadline,
                                  terminal_box](const std::shared_ptr<Session> &session) mutable {
                    Handler start_terminal = std::move(terminal_box->value());
                    terminal_box->reset();
                    session->start_exchange(query_id, std::move(owned_request), owned_deadline,
                                            std::move(start_terminal));
                });
                return async::CallbackAbortFn{[self, query_id] {
                    self->post_state([query_id](const std::shared_ptr<Session> &session) {
                        session->fail_pending(query_id, cancelled_error());
                    });
                }};
            });
    }

    void cancel(std::uint16_t query_id) noexcept {
        post_state([query_id](const std::shared_ptr<Session> &session) {
            session->fail_pending(query_id, cancelled_error());
        });
    }

    void stop() noexcept {
        stopped_ = true;
        retired_ = true;
        post_state([](const std::shared_ptr<Session> &session) {
            // Stop the HTTP/2 session inline (not posted): its read/write
            // pumps run on the stream executor, not this strand, and its
            // scope_ must not outlive runtime.stop()'s join. fail_all is
            // strand-side below.
            if (session->http_session_) {
                auto http = std::move(session->http_session_);
                http->stop();
            }
            session->drain_stopped();
        });
    }

    bool retired() const noexcept { return retired_.load(); }

  private:
    // Snapshot carried from the IO-thread connect chain back to the
    // strand. Holds no Session state; the strand step decides from it.
    struct ConnectEvent {
        bool opened = false;
        bool tls_ok = false;
        std::optional<core::Error> error;
        core::Error tls_error{core::ErrorCode::endpoint_connection, "DoH2 connect failed"};
        std::unique_ptr<io::StreamHandle> handle;
        std::unique_ptr<io::StreamHandle> tls_stream;
    };

    struct Pending {
        io::ExchangeRequest request;
        Handler handler;
        std::chrono::steady_clock::time_point deadline{};
        bool http_exchange_started = false;
    };

    // Runs on the strand (called only from the posted starter body).
    void start_exchange(std::uint16_t query_id, io::ExchangeRequest owned_request,
                        std::chrono::steady_clock::time_point owned_deadline, Handler terminal) {
        if (stopped_ || retired_) {
            terminal(core::fail(cancelled_error()));
            return;
        }
        auto pending = std::make_shared<Pending>();
        pending->handler = std::move(terminal);
        pending_.emplace(query_id, pending);
        if (http_session_) {
            submit(query_id, pending, std::move(owned_request), owned_deadline);
        } else {
            pending->request = std::move(owned_request);
            pending->deadline = owned_deadline;
            connect_if_needed();
        }
        // Per-request deadline task: fires once at the deadline;
        // the map lookup drops it when the exchange already won.
        // Bounded by the deadline, so no stop is ever requested.
        // Detached (not on scope_): see spawn_detached_deadline.
        scope_anchor_ = shared_from_this();
        spawn_detached_deadline(shared_from_this(), query_id, owned_deadline);
    }

    // Runs on the strand (called only from the posted stop body or the
    // last-owner destructor). The HTTP/2 session is already stopped inline
    // by the stop body; only the map drain happens here.
    void drain_stopped() {
        ++connection_generation_;
        fail_all(cancelled_error());
    }

    // Per-request deadline: fires once at the deadline; the map lookup
    // drops it when the exchange already won. Runs detached (not on
    // scope_).
    static exec::task<void> run_deadline(std::shared_ptr<Session> self, std::uint16_t query_id,
                                         std::chrono::steady_clock::time_point deadline) {
        try {
            co_await async::sleep_until(self->runtime_.serialized_executor(), deadline);
        } catch (...) {
        }
        // Coroutine resumption after co_await has no strand affinity: hop
        // back before touching state.
        self->post_state([query_id](const std::shared_ptr<Session> &session) {
            if (!session->stopped_) {
                session->fail_pending(query_id, timeout_error());
            }
        });
        co_return;
    }

    // Strand-side connect step: runs on the strand; decides the next move
    // from a snapshot taken on the IO thread. Spawning here keeps scope_
    // ownership on the strand while the dial/TLS awaits run free.
    void on_connect_progress(std::uint64_t generation, ConnectEvent event) {
        if (generation != connection_generation_ || stopped_) {
            if (event.handle) {
                event.handle->close();
            }
            return;
        }
        if (!event.opened) {
            connection_failed(event.error.value_or(core::Error{
                core::ErrorCode::endpoint_connection, "DoH2 dialer failed to open a stream"}));
            return;
        }
        if (!event.tls_ok) {
            connection_failed(event.tls_error);
            return;
        }
        connecting_ = false;
        http_session_ = transport::make_http2_exchange_session(std::move(event.tls_stream));
        if (!http_session_) {
            connection_failed(protocol_error("failed to create an HTTP/2 client session"));
            return;
        }
        submit_waiting();
    }

    // Straight-line connect chain: dial, TLS handshake on IO threads, then
    // hop to the strand for every state decision. The task always ends
    // with a value.
    static exec::task<void> run_connect(std::shared_ptr<Session> self, std::uint64_t generation) {
        ConnectEvent event;
        try {
            auto opened = co_await self->dialer_->connect_stream(
                {core::Destination::address(self->endpoint_.address(), self->endpoint_.port()),
                 std::nullopt});
            if (!opened.succeeded()) {
                event.opened = false;
                event.error = opened.error;
                self->post_state([generation, event = std::move(event)](
                                     const std::shared_ptr<Session> &session) mutable {
                    session->on_connect_progress(generation, std::move(event));
                });
                co_return;
            }
            transport::TlsClientOptions options;
            options.server_name = self->server_name_;
            options.verify_peer = self->verify_peer_;
            options.alpn_protocols = {"h2"};
            try {
                auto tls = co_await transport::async_tls_client_handshake(std::move(opened.handle),
                                                                          std::move(options));
                if (tls.negotiated_alpn != "h2") {
                    tls.stream->close();
                    event.opened = true;
                    event.tls_ok = false;
                    event.tls_error = {core::ErrorCode::carrier_handshake,
                                       "DoH2 upstream did not negotiate the h2 protocol"};
                } else {
                    event.opened = true;
                    event.tls_ok = true;
                    event.tls_stream = std::move(tls.stream);
                }
            } catch (const core::Error &failure) {
                event.opened = true;
                event.tls_ok = false;
                event.tls_error = failure;
            } catch (...) {
                event.opened = true;
                event.tls_ok = false;
            }
        } catch (...) {
            event.opened = true;
            event.tls_ok = false;
            event.tls_error = {core::ErrorCode::endpoint_connection, "DoH2 connect failed"};
        }
        self->post_state([generation, event = std::move(event)](
                             const std::shared_ptr<Session> &session) mutable {
            session->on_connect_progress(generation, std::move(event));
        });
        co_return;
    }

    // Strand-side exchange terminal: runs on the strand.
    void on_exchange_done(std::uint16_t query_id, core::Result<io::ExchangeResponse> result) {
        finish_pending(query_id, std::move(result));
    }

    // One multiplexed exchange: the deadline task may erase the pending
    // first, in which case finish_pending() drops the late terminal. The
    // HTTP await runs on IO threads; the terminal hops to the strand.
    static exec::task<void> run_exchange(std::shared_ptr<Session> self, std::uint16_t query_id,
                                         std::shared_ptr<io::ExchangeSession> http_session,
                                         io::ExchangeRequest request,
                                         std::chrono::steady_clock::time_point deadline) {
        core::Result<io::ExchangeResponse> result = core::fail(cancelled_error());
        try {
            result = co_await http_session->exchange(std::move(request), deadline);
        } catch (const core::Error &failure) {
            result = core::fail(failure);
        } catch (...) {
            result = core::fail(
                core::Error{core::ErrorCode::endpoint_connection, "DoH2 exchange failed"});
        }
        self->post_state([query_id, result = std::move(result)](
                             const std::shared_ptr<Session> &session) mutable {
            session->finish_pending(query_id, std::move(result));
        });
        co_return;
    }

    void connect_if_needed() {
        if (stopped_ || retired_ || connecting_ || http_session_ || pending_.empty()) {
            return;
        }
        connecting_ = true;
        const auto generation = connection_generation_;
        const auto self = shared_from_this();
        // The scope only owns chain tasks (merge-shaped usage); teardown stays
        // guard-driven, so no stop is ever requested.
        scope_.spawn(run_connect(self, generation));
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
                submit(query_id, found->second, io::ExchangeRequest{},
                       std::chrono::steady_clock::time_point{});
            }
        }
    }

    // The guarded emission pump: submit() moves the stored request out of
    // the pending exactly once (http_exchange_started guard) and spawns one
    // exchange task per request. Empty request/deadline means "use stored".
    void submit(std::uint16_t query_id, const std::shared_ptr<Pending> &pending,
                io::ExchangeRequest request = {},
                std::chrono::steady_clock::time_point deadline = {}) {
        if (!http_session_ || pending->http_exchange_started) {
            return;
        }
        const auto self = shared_from_this();
        pending->http_exchange_started = true;
        if (deadline == std::chrono::steady_clock::time_point{}) {
            request = std::move(pending->request);
            deadline = pending->deadline;
        }
        scope_.spawn(run_exchange(self, query_id, http_session_, std::move(request), deadline));
    }

    // Detached deadline via async::spawn_detached.
    static void spawn_detached_deadline(std::shared_ptr<Session> self, std::uint16_t query_id,
                                        std::chrono::steady_clock::time_point deadline) {
        async::spawn_detached(run_deadline(std::move(self), query_id, deadline));
    }

    void fail_pending(std::uint16_t query_id, core::Error error) {
        const auto found = pending_.find(query_id);
        if (found == pending_.end()) {
            return;
        }
        auto pending = std::move(found->second);
        pending_.erase(found);
        // No per-exchange cancel: the io:: vocabulary cancels through the
        // stop token, and this edge owns no stop source. The orphaned HTTP
        // exchange still terminates on its own deadline and its late
        // terminal finds no pending and is dropped.
        auto handler = std::move(pending->handler);
        if (pending_.empty()) {
            scope_anchor_.reset();
        }
        if (handler) {
            handler(core::fail(std::move(error)));
        }
        abandon_connect_if_idle();
    }

    void finish_pending(std::uint16_t query_id, core::Result<io::ExchangeResponse> result) {
        const auto found = pending_.find(query_id);
        if (found == pending_.end()) {
            return;
        }
        auto pending = std::move(found->second);
        pending_.erase(found);
        if (http_session_ && http_session_->retired()) {
            retired_ = true;
        }
        auto handler = std::move(pending->handler);
        if (pending_.empty()) {
            scope_anchor_.reset();
        }
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
    }

    runtime::AsioRuntime &runtime_;
    boost::asio::ip::tcp::endpoint endpoint_;
    std::string server_name_;
    std::string authority_;
    std::string path_;
    bool verify_peer_;
    std::shared_ptr<DnsUpstreamDialer> dialer_;
    std::shared_ptr<io::ExchangeSession> http_session_;
    // Lifetime anchor: tasks spawned on scope_ hold only `self`; finish
    // paths run continuations inline, which may drop the last owner while
    // a task still unwinds through __complete. The anchor is released on
    // the strand after the terminal is delivered. The destructor must not
    // touch it: a posted lambda may still hold `self` when the last owner
    // drops, and the lambda runs next on the strand.
    std::shared_ptr<void> scope_anchor_;
    // Owns the connect/exchange chain tasks, which always end with a value.
    exec::async_scope scope_;
    std::unordered_map<std::uint16_t, std::shared_ptr<Pending>> pending_;
    std::uint64_t connection_generation_ = 0;
    bool connecting_ = false;
    std::atomic_bool retired_{false};
    std::atomic_bool stopped_{false};
};

class Doh2DnsTransport::Operation final
    : public std::enable_shared_from_this<Doh2DnsTransport::Operation> {
  public:
    Operation(Doh2DnsTransport &owner, DnsExchangeId exchange_id, DnsExchangeRequest request,
              OpenHandler handler)
        : owner_(owner), exchange_id_(exchange_id), request_(std::move(request)),
          handler_(std::move(handler)) {}

    void start() { owner_.run_scope_.spawn(run(shared_from_this())); }

    // One multiplexed exchange: build the request, co_await the session
    // sender (deadline enforced inside), validate, and finish exactly
    // once. Always ends with a value; finish() drops late terminals.
    static exec::task<void> run(std::shared_ptr<Operation> self) {
        try {
            if (std::chrono::steady_clock::now() >= self->request_.deadline) {
                self->finish(core::fail(timeout_error()));
                co_return;
            }
            if (self->owner_.config_.doh_path.empty() ||
                self->owner_.config_.doh_path.front() != '/' ||
                std::any_of(self->owner_.config_.doh_path.begin(),
                            self->owner_.config_.doh_path.end(),
                            [](unsigned char value) { return value <= 0x20 || value == 0x7f; })) {
                self->finish(core::fail({core::ErrorCode::configuration,
                                         "DoH2 path is not a valid origin-form target"}));
                co_return;
            }
            if (self->request_.query.wire.empty() || self->request_.query.wire.size() > 0xffff) {
                self->finish(core::fail(protocol_error("DoH2 DNS query wire length is invalid")));
                co_return;
            }
            const auto query_id = self->owner_.next_query_id();
            if (!query_id) {
                self->finish(core::fail({core::ErrorCode::configuration,
                                         "DoH2 transport has no available transaction IDs"}));
                co_return;
            }
            self->query_id_ = *query_id;
            self->owner_.active_query_ids_.insert(self->query_id_);
            const auto encoded = DnsMessageCodec::rewrite_id(self->request_.query, self->query_id_);
            if (!encoded) {
                self->finish(core::fail(encoded.error()));
                co_return;
            }
            auto session = self->owner_.session();
            if (!session) {
                self->finish(core::fail(
                    {core::ErrorCode::configuration, "DoH2 transport session is not available"}));
                co_return;
            }
            const auto endpoint = self->owner_.config_.tcp_endpoint.value_or(
                boost::asio::ip::tcp::endpoint(self->owner_.config_.endpoint.address(),
                                               self->owner_.config_.endpoint.port() == 53
                                                   ? 443
                                                   : self->owner_.config_.endpoint.port()));
            io::ExchangeRequest http_request;
            http_request.method = "POST";
            http_request.scheme = "https";
            http_request.authority = authority_for(self->owner_.config_, endpoint);
            http_request.target = self->owner_.config_.doh_path;
            http_request.headers = {{"accept", "application/dns-message"},
                                    {"content-type", "application/dns-message"}};
            http_request.body = encoded.value();
            http_request.response_body_limit = 0xffff;
            self->session_ = session;
            self->exchange_started_ = true;
            core::Result<io::ExchangeResponse> http_result = core::fail(cancelled_error());
            try {
                http_result = co_await session->exchange(self->query_id_, std::move(http_request),
                                                         self->request_.deadline);
            } catch (const core::Error &failure) {
                self->finish(core::fail(failure));
                co_return;
            } catch (...) {
                self->finish(core::fail(
                    core::Error{core::ErrorCode::endpoint_connection, "DoH2 exchange failed"}));
                co_return;
            }
            self->exchange_started_ = false;
            if (self->completed_) {
                co_return;
            }
            if (!http_result) {
                self->finish(core::fail(http_result.error()));
                co_return;
            }
            self->validate_response(http_result.value());
        } catch (...) {
            self->finish(
                core::fail(core::Error{core::ErrorCode::transport_io, "DoH2 exchange failed"}));
        }
        co_return;
    }

    void validate_response(const io::ExchangeResponse &response) {
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

    void cancel() {
        if (completed_) {
            return;
        }
        completed_ = true;
        close_session_exchange();
        owner_.complete(exchange_id_, core::fail(cancelled_error()));
    }

    OpenHandler take_handler() { return std::move(handler_); }
    std::uint16_t query_id() const noexcept { return query_id_; }

  private:
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
    DnsExchangeId exchange_id_;
    DnsExchangeRequest request_;
    OpenHandler handler_;
    std::shared_ptr<Session> session_;
    std::uint16_t query_id_ = 0;
    bool exchange_started_ = false;
    bool completed_ = false;
};

std::optional<std::uint16_t> Doh2DnsTransport::next_query_id() noexcept {
    // Called only from Operation::run's synchronous prefix, which itself
    // runs on run_scope_'s spawn thread; single exchange per test keeps
    // this uncontended, but route through the strand for safety.
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

io::AnySender<DnsExchangeResult> Doh2DnsTransport::exchange(DnsExchangeRequest request) {
    auto box = std::make_shared<std::optional<DnsExchangeRequest>>(std::move(request));
    auto self = shared_from_this();
    return async::bridge_sender<DnsExchangeResult>(
        [self, box](async::BridgeHandler<DnsExchangeResult> done) mutable {
            if (!box || !*box) {
                done(core::fail(cancelled_error()));
                return async::CallbackAbortFn{};
            }
            const auto exchange_id = self->open_exchange(std::move(**box), std::move(done));
            box->reset();
            return async::CallbackAbortFn{
                [self, exchange_id] { self->cancel_exchange(exchange_id); }};
        });
}

DnsExchangeId Doh2DnsTransport::open_exchange(DnsExchangeRequest request, OpenHandler handler) {
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

void Doh2DnsTransport::cancel_exchange(DnsExchangeId exchange_id) noexcept {
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
        auto session = session_;
        session->stop();
        // Release the transport's ownership on the strand, after the
        // posted drain runs: dropping it here could destroy the Session
        // (and its scope_) while a posted lambda still references it.
        // The lambda holds `self`, so destruction happens after it runs.
        auto strand = runtime_.serialized_executor();
        boost::asio::post(strand, [session]() mutable { session.reset(); });
        session_.reset();
    }
    while (!operations_.empty()) {
        operations_.begin()->second->cancel();
    }
}
void Doh2DnsTransport::complete(DnsExchangeId exchange_id, core::Result<DnsPacket> result) {
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
