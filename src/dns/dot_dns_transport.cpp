#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/timer.hpp>
#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/transport/tls_client.hpp>

#include <boost/asio/buffer.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

core::Error timeout_error() { return {core::ErrorCode::timeout, "DoT DNS query timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "DoT DNS query was cancelled"};
}

} // namespace

class DotDnsTransport final : public DnsTransport,
                              public std::enable_shared_from_this<DotDnsTransport> {
  private:
    class Operation;
    class Session;

    using OpenHandler = async::BridgeHandler<DnsExchangeResult>;

  public:
    DotDnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
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

class DotDnsTransport::Session final
    : public std::enable_shared_from_this<DotDnsTransport::Session> {
  public:
    using Handler = std::function<void(core::Result<std::vector<std::uint8_t>>)>;

    Session(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint,
            std::string server_name, bool verify_peer, std::shared_ptr<DnsUpstreamDialer> dialer)
        : runtime_(runtime), endpoint_(endpoint), server_name_(std::move(server_name)),
          verify_peer_(verify_peer), dialer_(std::move(dialer)) {}

    io::AnySender<core::Result<std::vector<std::uint8_t>>>
    exchange(std::uint16_t query_id, std::vector<std::uint8_t> query,
             std::chrono::steady_clock::time_point deadline) {
        auto self = shared_from_this();
        // Shared: the bridge starter is a std::function and must be
        // copyable; a second start after the moves fails fast instead of
        // hanging.
        auto state = std::make_shared<
            std::tuple<std::vector<std::uint8_t>, std::chrono::steady_clock::time_point, bool>>(
            std::move(query), deadline, true);
        return async::bridge_sender<core::Result<std::vector<std::uint8_t>>>(
            [self, query_id, state](Session::Handler terminal) mutable {
                if (!std::get<2>(*state)) {
                    terminal(core::fail(cancelled_error()));
                    return async::CallbackAbortFn{};
                }
                std::get<2>(*state) = false;
                auto query = std::move(std::get<0>(*state));
                const auto deadline = std::get<1>(*state);
                if (self->stopped_ || self->retired_) {
                    terminal(core::fail(cancelled_error()));
                    return async::CallbackAbortFn{};
                }
                if (query.empty() || query.size() > 0xffff) {
                    terminal(core::fail(
                        {core::ErrorCode::protocol_framing, "DoT DNS query length is invalid"}));
                    return async::CallbackAbortFn{};
                }
                if (self->pending_.contains(query_id)) {
                    terminal(core::fail({core::ErrorCode::protocol_framing,
                                         "DoT DNS transaction ID is already in use"}));
                    return async::CallbackAbortFn{};
                }
                auto pending = std::make_shared<Pending>();
                pending->frame.reserve(2 + query.size());
                pending->frame.push_back(static_cast<std::uint8_t>(query.size() >> 8));
                pending->frame.push_back(static_cast<std::uint8_t>(query.size() & 0xff));
                pending->frame.insert(pending->frame.end(), query.begin(), query.end());
                pending->handler = std::move(terminal);
                self->pending_.emplace(query_id, pending);
                self->write_queue_.push_back(query_id);
                self->connect_if_needed();
                self->ensure_write_loop();
                // Per-request deadline task: fires once at the deadline;
                // the map lookup drops it when the response already won.
                // Bounded by the deadline, so no stop is ever requested.
                self->scope_.spawn(run_deadline(self, query_id, deadline));
                return async::CallbackAbortFn{
                    [self, query_id] { self->fail_request(query_id, cancelled_error()); }};
            });
    }

    void cancel(std::uint16_t query_id) noexcept { fail_request(query_id, cancelled_error()); }

    void stop() noexcept {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        retired_ = true;
        close_connection();
        fail_all(cancelled_error());
    }

    bool retired() const noexcept { return retired_; }

    struct Pending {
        std::vector<std::uint8_t> frame;
        Handler handler;
    };

    using PendingPtr = std::shared_ptr<Pending>;

    // Per-request deadline task: fires once at the deadline; the map
    // lookup drops it when the response already won. Bounded by the
    // deadline, so no stop is ever requested.
    static exec::task<void> run_deadline(std::shared_ptr<Session> self, std::uint16_t query_id,
                                         std::chrono::steady_clock::time_point deadline) {
        try {
            co_await async::sleep_until(self->runtime_.serialized_executor(), deadline);
        } catch (...) {
        }
        if (!self->stopped_) {
            self->fail_request(query_id, timeout_error());
        }
        co_return;
    }

    // Straight-line connect chain: dial, TLS handshake, then frame pumps.
    // Every terminal funnels through connection_failed() or the pump
    // starters, so the spawned task always ends with a value.
    static exec::task<void> run_connect(std::shared_ptr<Session> self, std::uint64_t generation) {
        try {
            auto opened = co_await self->dialer_->connect_stream(
                {core::Destination::address(self->endpoint_.address(), self->endpoint_.port()),
                 std::nullopt});
            if (generation != self->connection_generation_ || self->stopped_) {
                if (opened.handle) {
                    opened.handle->close();
                }
                co_return;
            }
            if (!opened.succeeded()) {
                self->connection_failed(
                    opened.error.value_or(core::Error{core::ErrorCode::endpoint_connection,
                                                      "DoT dialer failed to open a stream"}),
                    generation);
                co_return;
            }
            transport::TlsClientOptions options;
            options.server_name = self->server_name_;
            options.verify_peer = self->verify_peer_;
            bool tls_ok = false;
            transport::TlsClientConnection tls;
            core::Error tls_error{core::ErrorCode::endpoint_connection, "DoT TLS handshake failed"};
            try {
                tls = co_await transport::async_tls_client_handshake(std::move(opened.handle),
                                                                     std::move(options));
                tls_ok = true;
            } catch (const core::Error &failure) {
                tls_error = failure;
            } catch (...) {
            }
            if (generation != self->connection_generation_ || self->stopped_) {
                if (tls_ok && tls.stream) {
                    tls.stream->close();
                }
                co_return;
            }
            if (!tls_ok) {
                self->connection_failed(tls_error, generation);
                co_return;
            }
            self->tls_stream_ = std::move(tls.stream);
            self->connecting_ = false;
            self->connected_ = true;
            // The scope only owns chain tasks (merge-shaped usage); teardown
            // stays guard-driven, so no stop is ever requested.
            self->scope_.spawn(run_read_loop(self, generation));
            self->ensure_write_loop(generation);
        } catch (...) {
            if (generation == self->connection_generation_ && !self->stopped_) {
                self->connection_failed(
                    core::Error{core::ErrorCode::endpoint_connection, "DoT connect failed"},
                    generation);
            }
        }
        co_return;
    }

    void connect_if_needed() {
        if (stopped_ || retired_ || connected_ || connecting_ || pending_.empty()) {
            return;
        }

        connecting_ = true;
        const auto generation = connection_generation_;
        auto self = shared_from_this();
        // The scope only owns chain tasks (merge-shaped usage); teardown stays
        // guard-driven, so no stop is ever requested.
        scope_.spawn(run_connect(self, generation));
    }

    void ensure_write_loop(std::uint64_t generation = 0) {
        if (generation == 0) {
            generation = connection_generation_;
        }
        if (stopped_ || retired_ || generation != connection_generation_ || !connected_ ||
            write_in_progress_) {
            return;
        }
        write_in_progress_ = true;
        scope_.spawn(run_write_loop(shared_from_this(), generation));
    }

    // Sequential write pump: drains the queue frame by frame with co_await
    // on the io:: write sender. Ends with a value on every path: normal
    // drain, stale generation, or connection failure.
    static exec::task<void> run_write_loop(std::shared_ptr<Session> self,
                                           std::uint64_t generation) {
        try {
            while (!self->stopped_ && !self->retired_ &&
                   generation == self->connection_generation_ && self->connected_) {
                while (!self->write_queue_.empty() &&
                       !self->pending_.contains(self->write_queue_.front())) {
                    self->write_queue_.pop_front();
                }
                if (self->write_queue_.empty()) {
                    break;
                }
                const auto query_id = self->write_queue_.front();
                const auto found = self->pending_.find(query_id);
                if (found == self->pending_.end()) {
                    self->write_queue_.pop_front();
                    continue;
                }
                auto frame = found->second->frame;
                try {
                    co_await self->tls_stream_->async_write(boost::asio::buffer(frame));
                } catch (const core::Error &failure) {
                    self->write_in_progress_ = false;
                    self->connection_failed(
                        core::Error{core::ErrorCode::transport_io,
                                    std::string("failed to send DoT DNS query: ") +
                                        failure.context},
                        generation);
                    co_return;
                } catch (...) {
                    self->write_in_progress_ = false;
                    self->connection_failed(
                        {core::ErrorCode::transport_io, "failed to send DoT DNS query"},
                        generation);
                    co_return;
                }
                if (!self->write_queue_.empty() && self->write_queue_.front() == query_id) {
                    self->write_queue_.pop_front();
                }
            }
        } catch (...) {
        }
        self->write_in_progress_ = false;
        if (!self->stopped_ && !self->retired_ && generation == self->connection_generation_ &&
            self->connected_) {
            self->ensure_write_loop(generation);
        }
        co_return;
    }

    // Sequential read pump: length prefix then body with co_await on the
    // io:: read sender, dispatching complete frames in order. Ends with a
    // value on every path; the connection failure path retires the session.
    static exec::task<void> run_read_loop(std::shared_ptr<Session> self, std::uint64_t generation) {
        try {
            while (!self->stopped_ && !self->retired_ &&
                   generation == self->connection_generation_ && self->connected_) {
                std::array<std::uint8_t, 2> length{};
                try {
                    co_await read_exact_task(self, generation, length);
                } catch (const core::Error &failure) {
                    self->connection_failed(
                        core::Error{core::ErrorCode::transport_io,
                                    std::string("failed to receive DoT DNS length: ") +
                                        failure.context},
                        generation);
                    co_return;
                } catch (...) {
                    self->connection_failed(
                        {core::ErrorCode::transport_io, "failed to receive DoT DNS length"},
                        generation);
                    co_return;
                }
                const auto size = static_cast<std::size_t>(length[0] << 8 | length[1]);
                if (size == 0 || size > 0xffff) {
                    self->connection_failed(
                        {core::ErrorCode::protocol_framing, "DoT DNS response length is invalid"},
                        generation);
                    co_return;
                }
                std::vector<std::uint8_t> body(size);
                try {
                    co_await read_exact_task(self, generation, body);
                } catch (const core::Error &failure) {
                    self->connection_failed(
                        core::Error{core::ErrorCode::transport_io,
                                    std::string("failed to receive DoT DNS response: ") +
                                        failure.context},
                        generation);
                    co_return;
                } catch (...) {
                    self->connection_failed(
                        {core::ErrorCode::transport_io, "failed to receive DoT DNS response"},
                        generation);
                    co_return;
                }
                self->dispatch_response(std::move(body), generation);
            }
        } catch (...) {
            if (generation == self->connection_generation_ && !self->stopped_) {
                self->connection_failed(
                    core::Error{core::ErrorCode::transport_io, "DoT read loop failed"}, generation);
            }
        }
        co_return;
    }

    // Reads exactly buffer.size() bytes with co_await on async_read_some,
    // throwing core::Error on EOF or wire failure. Array/vector overloads
    // share one path for the prefix and the body.
    template <typename Buffer>
    static exec::task<void> read_exact_task(std::shared_ptr<Session> self, std::uint64_t generation,
                                            Buffer &buffer) {
        std::size_t offset = 0;
        const auto total = std::size(buffer);
        auto *data = std::data(buffer);
        while (offset < total) {
            if (self->stopped_ || self->retired_ || generation != self->connection_generation_ ||
                !self->connected_) {
                throw core::Error{core::ErrorCode::cancelled, "DoT session is not connected"};
            }
            std::optional<std::size_t> count;
            try {
                count = co_await self->tls_stream_->async_read_some(
                    boost::asio::buffer(data + offset, total - offset));
            } catch (const core::Error &failure) {
                throw failure;
            } catch (...) {
                throw core::Error{core::ErrorCode::transport_io,
                                  "failed to receive DoT DNS response"};
            }
            if (!count) {
                throw core::Error{core::ErrorCode::transport_io,
                                  "DoT upstream closed the connection"};
            }
            if (*count == 0) {
                throw core::Error{core::ErrorCode::transport_io,
                                  "failed to receive DoT DNS response"};
            }
            offset += *count;
        }
        co_return;
    }

    void dispatch_response(std::vector<std::uint8_t> response, std::uint64_t generation) {
        if (response.size() < 2) {
            connection_failed({core::ErrorCode::protocol_framing,
                               "DoT DNS response is shorter than its transaction ID"},
                              generation);
            return;
        }
        const auto query_id = static_cast<std::uint16_t>(response[0] << 8 | response[1]);
        Handler handler;
        if (const auto found = pending_.find(query_id); found != pending_.end()) {
            auto pending = std::move(found->second);
            pending_.erase(found);
            handler = std::move(pending->handler);
        }
        if (handler) {
            handler(std::move(response));
        }
        (void)generation;
    }

    void fail_request(std::uint16_t query_id, core::Error error) {
        const auto found = pending_.find(query_id);
        if (found == pending_.end()) {
            return;
        }
        auto pending = std::move(found->second);
        pending_.erase(found);
        write_queue_.erase(std::remove(write_queue_.begin(), write_queue_.end(), query_id),
                           write_queue_.end());
        if (pending_.empty() && connecting_) {
            retired_ = true;
            close_connection();
        }
        if (pending->handler) {
            auto handler = std::move(pending->handler);
            handler(core::fail(std::move(error)));
        }
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
        write_queue_.clear();
        for (auto &handler : handlers) {
            handler(core::fail(error));
        }
    }

    void connection_failed(core::Error error, std::uint64_t generation) {
        if (generation != connection_generation_ || stopped_) {
            return;
        }
        retired_ = true;
        close_connection();
        fail_all(error);
    }

    void close_connection() noexcept {
        ++connection_generation_;
        connecting_ = false;
        connected_ = false;
        write_in_progress_ = false;
        boost::system::error_code ignored;
        if (tls_stream_) {
            tls_stream_->close();
            tls_stream_.reset();
        }
    }

    runtime::AsioRuntime &runtime_;
    boost::asio::ip::tcp::endpoint endpoint_;
    std::string server_name_;
    bool verify_peer_;
    std::shared_ptr<DnsUpstreamDialer> dialer_;
    std::unique_ptr<io::StreamHandle> tls_stream_;
    // Owns the connect chain task, which always ends with a value.
    exec::async_scope scope_;
    std::unordered_map<std::uint16_t, PendingPtr> pending_;
    std::deque<std::uint16_t> write_queue_;
    std::uint64_t connection_generation_ = 0;
    bool connecting_ = false;
    bool connected_ = false;
    bool write_in_progress_ = false;
    bool retired_ = false;
    bool stopped_ = false;
};

class DotDnsTransport::Operation final
    : public std::enable_shared_from_this<DotDnsTransport::Operation> {
  public:
    Operation(DotDnsTransport &owner, DnsExchangeId exchange_id, DnsExchangeRequest request,
              OpenHandler handler)
        : owner_(owner), exchange_id_(exchange_id), request_(std::move(request)),
          handler_(std::move(handler)) {}

    void start() { owner_.run_scope_.spawn(run(shared_from_this())); }

    // One multiplexed exchange: build the query, co_await the session
    // sender (deadline enforced inside), validate, and finish exactly
    // once. Always ends with a value; finish() drops late terminals.
    static exec::task<void> run(std::shared_ptr<Operation> self) {
        try {
            if (std::chrono::steady_clock::now() >= self->request_.deadline) {
                self->finish(core::fail(timeout_error()));
                co_return;
            }
            const auto query_id = self->owner_.next_query_id();
            if (!query_id) {
                self->finish(core::fail({core::ErrorCode::configuration,
                                         "DoT transport has no available transaction IDs"}));
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
                    {core::ErrorCode::configuration, "DoT transport session is not available"}));
                co_return;
            }
            self->session_ = session;
            self->exchange_started_ = true;
            core::Result<std::vector<std::uint8_t>> wire_result = core::fail(cancelled_error());
            try {
                wire_result = co_await session->exchange(self->query_id_, encoded.value(),
                                                         self->request_.deadline);
            } catch (const core::Error &failure) {
                self->finish(core::fail(failure));
                co_return;
            } catch (...) {
                self->finish(
                    core::fail(core::Error{core::ErrorCode::transport_io, "DoT exchange failed"}));
                co_return;
            }
            self->exchange_started_ = false;
            if (self->completed_) {
                co_return;
            }
            if (!wire_result) {
                self->finish(core::fail(wire_result.error()));
                co_return;
            }
            const auto response =
                DnsMessageCodec::decode_packet(wire_result.value(), self->query_id_);
            if (!response) {
                self->finish(core::fail(response.error()));
                co_return;
            }
            if (!self->matches_question(response.value())) {
                self->finish(core::fail({core::ErrorCode::protocol_framing,
                                         "DoT DNS response question does not match the query"}));
                co_return;
            }
            self->finish(response);
        } catch (...) {
            self->finish(
                core::fail(core::Error{core::ErrorCode::transport_io, "DoT exchange failed"}));
        }
        co_return;
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
    bool matches_question(const DnsPacket &response) const {
        if (!response.response() || response.questions.size() != request_.query.questions.size()) {
            return false;
        }
        return std::equal(response.questions.begin(), response.questions.end(),
                          request_.query.questions.begin(),
                          [](const DnsQuestion &actual, const DnsQuestion &expected) {
                              return normalize_name(actual.name) == normalize_name(expected.name) &&
                                     actual.type == expected.type &&
                                     actual.class_code == expected.class_code;
                          });
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

    DotDnsTransport &owner_;
    DnsExchangeId exchange_id_;
    DnsExchangeRequest request_;
    OpenHandler handler_;
    std::shared_ptr<Session> session_;
    std::uint16_t query_id_ = 0;
    bool exchange_started_ = false;
    bool completed_ = false;
};

std::optional<std::uint16_t> DotDnsTransport::next_query_id() noexcept {
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

std::shared_ptr<DotDnsTransport::Session> DotDnsTransport::session() {
    if (stopped_) {
        return nullptr;
    }
    if (!session_ || session_->retired()) {
        const auto endpoint = config_.tcp_endpoint.value_or(boost::asio::ip::tcp::endpoint(
            config_.endpoint.address(),
            config_.endpoint.port() == 53 ? 853 : config_.endpoint.port()));
        const auto server_name =
            config_.server_name.empty() ? endpoint.address().to_string() : config_.server_name;
        session_ = std::make_shared<Session>(runtime_, endpoint, server_name, config_.verify_peer,
                                             config_.dialer);
    }
    return session_;
}

io::AnySender<DnsExchangeResult> DotDnsTransport::exchange(DnsExchangeRequest request) {
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

DnsExchangeId DotDnsTransport::open_exchange(DnsExchangeRequest request, OpenHandler handler) {
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

void DotDnsTransport::cancel_exchange(DnsExchangeId exchange_id) noexcept {
    const auto operation = operations_.find(exchange_id);
    if (operation != operations_.end()) {
        operation->second->cancel();
    }
}

void DotDnsTransport::stop() noexcept {
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

void DotDnsTransport::complete(DnsExchangeId exchange_id, core::Result<DnsPacket> result) {
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

std::shared_ptr<DnsTransport> make_dot_dns_transport(runtime::AsioRuntime &runtime,
                                                     DnsUpstreamConfig config) {
    return std::make_shared<DotDnsTransport>(runtime, std::move(config));
}

} // namespace clash_native::dns
