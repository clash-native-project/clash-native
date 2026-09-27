#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/oneshot.hpp>
#include <clash_native/async/timer.hpp>
#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/outbound/builtin_outbound.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace clash_native::dns {

std::shared_ptr<DnsTransport> make_dot_dns_transport(runtime::AsioRuntime &runtime,
                                                     DnsUpstreamConfig config);
std::shared_ptr<DnsTransport> make_doh1_dns_transport(runtime::AsioRuntime &runtime,
                                                      DnsUpstreamConfig config);
std::shared_ptr<DnsTransport> make_doh2_dns_transport(runtime::AsioRuntime &runtime,
                                                      DnsUpstreamConfig config);
std::shared_ptr<DnsTransport> make_quic_dns_transport(runtime::AsioRuntime &runtime,
                                                      DnsUpstreamConfig config);
std::shared_ptr<DnsTransport> make_bootstrap_dns_transport(runtime::AsioRuntime &runtime,
                                                           DnsUpstreamConfig config);

namespace {

core::Error upstream_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "DNS upstream query timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "DNS upstream query was cancelled"};
}

class PlannedDnsUpstreamDialer final : public DnsUpstreamDialer {
  public:
    PlannedDnsUpstreamDialer(runtime::AsioRuntime &runtime,
                             core::Result<transport::EndpointDialPlan> plan)
        : runtime_(runtime) {
        if (!plan) {
            plan_error_ = plan.error();
            return;
        }
        endpoint_dialer_ = std::make_shared<transport::EndpointDialer>(
            runtime_.serialized_executor(), std::move(plan).value());
    }

    io::AnySender<core::StreamOpenResult> connect_stream(core::StreamRequest request) override {
        if (endpoint_dialer_) {
            return endpoint_dialer_->connect_stream(std::move(request));
        }
        const auto error = plan_error_.value_or(
            core::Error{core::ErrorCode::configuration, "DNS endpoint dial plan is missing"});
        return io::AnySender<core::StreamOpenResult>{
            stdexec::just(core::StreamOpenResult::failed(error))};
    }

    io::AnySender<core::DatagramOpenResult> open_datagram(core::DatagramRequest request) override {
        if (endpoint_dialer_) {
            return endpoint_dialer_->open_datagram(std::move(request));
        }
        const auto error = plan_error_.value_or(
            core::Error{core::ErrorCode::configuration, "DNS endpoint dial plan is missing"});
        return io::AnySender<core::DatagramOpenResult>{
            stdexec::just(core::DatagramOpenResult::failed(error))};
    }

  private:
    runtime::AsioRuntime &runtime_;
    std::shared_ptr<transport::EndpointDialer> endpoint_dialer_;
    std::optional<core::Error> plan_error_;
};

class TrafficRulesDnsUpstreamDialer final : public DnsUpstreamDialer {
  public:
    TrafficRulesDnsUpstreamDialer(runtime::AsioRuntime &runtime,
                                  outbound::OutboundRegistry::Snapshot registry,
                                  router::TrafficRouter::Snapshot traffic_router,
                                  std::string egress_hostname)
        : runtime_(runtime), registry_(std::move(registry)),
          traffic_router_(std::move(traffic_router)), egress_hostname_(std::move(egress_hostname)),
          direct_outbound_(std::make_shared<outbound::DirectOutbound>(runtime_)) {}

    io::AnySender<core::StreamOpenResult> connect_stream(core::StreamRequest request) override {
        const auto plan =
            make_plan(request.destination, core::Network::tcp, request.resolved_address);
        if (!plan) {
            return io::AnySender<core::StreamOpenResult>{
                stdexec::just(core::StreamOpenResult::failed(plan.error()))};
        }
        transport::EndpointDialer dialer(runtime_.serialized_executor(), plan.value());
        return dialer.connect_stream(std::move(request));
    }

    io::AnySender<core::DatagramOpenResult> open_datagram(core::DatagramRequest request) override {
        using ResultSender = io::AnySender<core::DatagramOpenResult>;
        if (!request.initial_destination) {
            return ResultSender{stdexec::just(core::DatagramOpenResult::failed(
                {core::ErrorCode::configuration, "DNS egress request has no destination", {}}))};
        }
        const auto plan = make_plan(*request.initial_destination, core::Network::udp, std::nullopt);
        if (!plan) {
            return ResultSender{stdexec::just(core::DatagramOpenResult::failed(plan.error()))};
        }
        transport::EndpointDialer dialer(runtime_.serialized_executor(), plan.value());
        return dialer.open_datagram(std::move(request));
    }

  private:
    core::Result<transport::EndpointDialPlan>
    make_plan(const core::Destination &destination, core::Network network,
              std::optional<boost::asio::ip::address> resolved_address) const {
        if (!traffic_router_) {
            return core::fail(
                {core::ErrorCode::configuration, "DNS traffic router is missing", {}});
        }
        if (!resolved_address && destination.is_address()) {
            resolved_address = destination.address();
        }

        const auto route_destination =
            egress_hostname_.empty()
                ? destination
                : core::Destination::domain(egress_hostname_, destination.port());
        core::ConnectionMetadata metadata{network, std::nullopt, route_destination, "dns-egress",
                                          "dns",   std::nullopt, std::nullopt};
        router::RoutingContext context;
        if (resolved_address) {
            context.destination_lookup = router::LookupState::resolved;
            context.destination_address = *resolved_address;
            context.destination_addresses.push_back(*resolved_address);
        }

        const auto evaluation = traffic_router_->evaluate(metadata, context);
        const auto *matched = std::get_if<router::Matched>(&evaluation);
        if (matched == nullptr) {
            return core::fail({core::ErrorCode::configuration,
                               "DNS egress route requires metadata that is not available",
                               {}});
        }
        switch (matched->decision.action.kind) {
        case router::RouteActionKind::direct:
            return transport::EndpointDialPlan::from_outbound(
                direct_outbound_, "direct",
                {network == core::Network::tcp, network == core::Network::udp});
        case router::RouteActionKind::reject:
            return core::fail(
                {core::ErrorCode::rejected, "DNS egress was rejected by traffic rules", {}});
        case router::RouteActionKind::named:
            return transport::EndpointDialPlan::from_registry(
                registry_, matched->decision.action.target,
                {network == core::Network::tcp, network == core::Network::udp});
        }
        return core::fail(
            {core::ErrorCode::configuration, "DNS egress route returned an invalid action", {}});
    }

    runtime::AsioRuntime &runtime_;
    outbound::OutboundRegistry::Snapshot registry_;
    router::TrafficRouter::Snapshot traffic_router_;
    std::string egress_hostname_;
    std::shared_ptr<core::Outbound> direct_outbound_;
};

} // namespace

OutboundDnsUpstreamDialer::OutboundDnsUpstreamDialer(
    runtime::AsioRuntime &runtime, outbound::OutboundRegistry::Snapshot registry,
    std::string outbound_id, transport::EndpointDialRequirements requirements)
    : runtime_(runtime) {
    const auto plan = transport::EndpointDialPlan::from_registry(
        std::move(registry), std::move(outbound_id), requirements);
    if (!plan) {
        plan_error_ = plan.error();
        return;
    }
    endpoint_dialer_ =
        std::make_shared<transport::EndpointDialer>(runtime_.serialized_executor(), plan.value());
}

io::AnySender<core::StreamOpenResult>
OutboundDnsUpstreamDialer::connect_stream(core::StreamRequest request) {
    if (plan_error_) {
        const auto error = *plan_error_;
        return io::AnySender<core::StreamOpenResult>{
            stdexec::just(core::StreamOpenResult::failed(error))};
    }
    return endpoint_dialer_->connect_stream(std::move(request));
}

io::AnySender<core::DatagramOpenResult>
OutboundDnsUpstreamDialer::open_datagram(core::DatagramRequest request) {
    if (plan_error_) {
        const auto error = *plan_error_;
        return io::AnySender<core::DatagramOpenResult>{
            stdexec::just(core::DatagramOpenResult::failed(error))};
    }
    return endpoint_dialer_->open_datagram(std::move(request));
}

class AsioDnsTransport final : public DnsTransport,
                               public std::enable_shared_from_this<AsioDnsTransport> {
  private:
    class Operation;
    class TcpSession;

  public:
    AsioDnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
        : runtime_(runtime), config_(std::move(config)) {
        if (!config_.dialer) {
            config_.dialer = make_direct_dns_upstream_dialer(runtime_);
        }
    }

    io::AnySender<DnsExchangeResult> exchange(DnsExchangeRequest request) override;
    void stop() noexcept override;
    DnsExchangeId open_exchange(DnsExchangeRequest request,
                                async::BridgeHandler<DnsExchangeResult> handler);
    void cancel_exchange(DnsExchangeId exchange_id) noexcept;

  private:
    void complete(DnsExchangeId exchange_id, core::Result<DnsPacket> result);
    std::optional<std::uint16_t> next_query_id() noexcept;
    std::shared_ptr<TcpSession> tcp_session();

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    std::unordered_map<DnsExchangeId, std::shared_ptr<Operation>> operations_;
    std::shared_ptr<TcpSession> tcp_session_;
    std::unordered_set<std::uint16_t> active_query_ids_;
    DnsExchangeId next_exchange_id_ = 1;
    std::uint16_t next_query_id_ = 1;
    bool stopped_ = false;

    friend class Operation;
};

class AsioDnsTransport::TcpSession final
    : public std::enable_shared_from_this<AsioDnsTransport::TcpSession> {
  public:
    using Handler = std::function<void(core::Result<std::vector<std::uint8_t>>)>;

    TcpSession(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint,
               std::shared_ptr<DnsUpstreamDialer> dialer)
        : runtime_(runtime), endpoint_(endpoint), dialer_(std::move(dialer)) {}

    void exchange(std::uint16_t query_id, std::vector<std::uint8_t> query,
                  std::chrono::steady_clock::time_point deadline, Handler handler) {
        if (stopped_) {
            complete_immediately(std::move(handler), cancelled_error());
            return;
        }
        if (query.empty() || query.size() > 0xffff) {
            complete_immediately(std::move(handler), {core::ErrorCode::protocol_framing,
                                                      "DNS TCP query length is invalid"});
            return;
        }
        if (pending_.contains(query_id)) {
            complete_immediately(std::move(handler),
                                 {core::ErrorCode::protocol_framing,
                                  "DNS TCP transaction ID is already in use on the session"});
            return;
        }

        auto pending = std::make_shared<Pending>();
        pending->frame.reserve(2 + query.size());
        pending->frame.push_back(static_cast<std::uint8_t>(query.size() >> 8));
        pending->frame.push_back(static_cast<std::uint8_t>(query.size() & 0xff));
        pending->frame.insert(pending->frame.end(), query.begin(), query.end());
        pending->handler = std::move(handler);
        pending_.emplace(query_id, pending);
        write_queue_.push_back(query_id);
        connect_if_needed();
        flush_writes();
        // The scope only owns chain tasks (merge-shaped usage); teardown
        // stays guard-driven, so no stop is ever requested.
        scope_.spawn(run_deadline(shared_from_this(), query_id, deadline));
    }

    void cancel(std::uint16_t query_id) noexcept { fail_request(query_id, cancelled_error()); }

    void stop() noexcept {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        close_connection();
        fail_all(cancelled_error());
    }

  private:
    struct Pending {
        std::vector<std::uint8_t> frame;
        Handler handler;
    };

    // Per-request deadline task: fires once at the deadline; the map lookup
    // in fail_request drops it when the response already won. Bounded by the
    // deadline, so no stop is ever requested.
    static exec::task<void> run_deadline(std::shared_ptr<TcpSession> self, std::uint16_t query_id,
                                         std::chrono::steady_clock::time_point deadline) {
        try {
            co_await async::sleep_until(self->runtime_.serialized_executor(), deadline);
        } catch (...) {
            co_return;
        }
        self->fail_request(query_id, timeout_error());
        co_return;
    }

    using PendingPtr = std::shared_ptr<Pending>;
    using ReadCompletion = std::function<void(const boost::system::error_code &)>;

    void complete_immediately(Handler handler, core::Error error) {
        runtime_.scheduler().post(
            [handler = std::move(handler), error = std::move(error)]() mutable {
                if (handler) {
                    handler(core::fail(std::move(error)));
                }
            });
    }

    // Straight-line connect chain: dial the stream, then start the read
    // pump and flush queued writes. Every terminal funnels through
    // connection_failed() or the pump starters, so the spawned task always
    // ends with a value.
    static exec::task<void> run_connect(std::shared_ptr<TcpSession> self,
                                        std::uint64_t generation) {
        if (!self->dialer_) {
            self->connection_failed(
                {core::ErrorCode::configuration, "DNS upstream stream dialer is not configured"},
                generation);
            co_return;
        }
        core::StreamOpenResult opened;
        try {
            opened = co_await self->dialer_->connect_stream(
                {core::Destination::address(self->endpoint_.address(), self->endpoint_.port()),
                 std::nullopt});
        } catch (const core::Error &failure) {
            if (generation == self->connection_generation_ && !self->stopped_) {
                self->connection_failed(failure, generation);
            }
            co_return;
        } catch (...) {
            if (generation == self->connection_generation_ && !self->stopped_) {
                self->connection_failed(core::Error{core::ErrorCode::endpoint_connection,
                                                    "DNS upstream dialer failed to open a stream"},
                                        generation);
            }
            co_return;
        }
        if (!opened.succeeded()) {
            self->connection_failed(
                opened.error.value_or(core::Error{core::ErrorCode::endpoint_connection,
                                                  "DNS upstream dialer failed to open a stream"}),
                generation);
            co_return;
        }
        self->stream_ = std::move(opened.handle);
        self->on_connected(generation);
        co_return;
    }

    void connect_if_needed() {
        if (stopped_ || connected_ || connecting_ || pending_.empty()) {
            return;
        }

        connecting_ = true;
        const auto generation = connection_generation_;
        auto self = shared_from_this();
        // The scope only owns chain tasks (merge-shaped usage); teardown
        // stays guard-driven, so no stop is ever requested.
        scope_.spawn(run_connect(self, generation));
    }

    void on_connected(std::uint64_t generation) {
        if (generation != connection_generation_ || stopped_) {
            return;
        }
        connecting_ = false;
        connected_ = true;
        read_frame(generation);
        flush_writes(generation);
    }

    void flush_writes(std::uint64_t generation = 0) {
        if (generation == 0) {
            generation = connection_generation_;
        }
        if (stopped_ || generation != connection_generation_ || !connected_ || write_in_progress_) {
            return;
        }
        while (!write_queue_.empty() && !pending_.contains(write_queue_.front())) {
            write_queue_.pop_front();
        }
        if (write_queue_.empty()) {
            return;
        }

        const auto query_id = write_queue_.front();
        const auto pending = pending_.at(query_id);
        write_in_progress_ = true;
        auto self = shared_from_this();
        const auto on_write = [self, pending, query_id,
                               generation](const boost::system::error_code &error, std::size_t) {
            if (generation != self->connection_generation_ || self->stopped_) {
                return;
            }
            self->write_in_progress_ = false;
            if (error) {
                self->connection_failed(upstream_error("failed to send DNS TCP query", error),
                                        generation);
                return;
            }
            if (!self->write_queue_.empty() && self->write_queue_.front() == query_id) {
                self->write_queue_.pop_front();
            }
            self->flush_writes(generation);
        };
        net::start_write_for_handler(stream_->async_write(boost::asio::buffer(pending->frame)),
                                     std::move(on_write));
    }

    void read_frame(std::uint64_t generation) {
        if (stopped_ || generation != connection_generation_ || !connected_ || read_in_progress_) {
            return;
        }
        read_in_progress_ = true;
        auto length = std::make_shared<std::vector<std::uint8_t>>(2);
        auto self = shared_from_this();
        read_exact(
            length, 0, generation,
            [self, length, generation](const boost::system::error_code &error) {
                self->read_in_progress_ = false;
                if (generation != self->connection_generation_ || self->stopped_) {
                    return;
                }
                if (error) {
                    self->connection_failed(
                        upstream_error("failed to receive DNS TCP length", error), generation);
                    return;
                }
                const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
                if (size == 0 || size > 65535) {
                    self->connection_failed(
                        {core::ErrorCode::protocol_framing, "DNS TCP response length is invalid"},
                        generation);
                    return;
                }
                auto body = std::make_shared<std::vector<std::uint8_t>>(size);
                self->read_exact(
                    body, 0, generation,
                    [self, body, generation](const boost::system::error_code &body_error) {
                        if (generation != self->connection_generation_ || self->stopped_) {
                            return;
                        }
                        if (body_error) {
                            self->connection_failed(
                                upstream_error("failed to receive DNS TCP response", body_error),
                                generation);
                            return;
                        }
                        self->dispatch_response(std::move(*body), generation);
                    });
            });
    }

    void read_exact(std::shared_ptr<std::vector<std::uint8_t>> buffer, std::size_t offset,
                    std::uint64_t generation, ReadCompletion handler) {
        if (stopped_ || generation != connection_generation_ || !connected_ ||
            offset >= buffer->size()) {
            return;
        }
        auto self = shared_from_this();
        auto on_read = [self, buffer, offset, generation, handler = std::move(handler)](
                           const boost::system::error_code &error, std::size_t size) mutable {
            if (generation != self->connection_generation_ || self->stopped_) {
                return;
            }
            if (error) {
                handler(error);
                return;
            }
            if (size == 0) {
                handler(boost::asio::error::eof);
                return;
            }
            const auto next_offset = offset + size;
            if (next_offset >= buffer->size()) {
                handler({});
                return;
            }
            self->read_exact(buffer, next_offset, generation, std::move(handler));
        };
        net::start_read_for_handler(stream_->async_read_some(boost::asio::buffer(
                                        buffer->data() + offset, buffer->size() - offset)),
                                    std::move(on_read));
    }

    void dispatch_response(std::vector<std::uint8_t> response, std::uint64_t generation) {
        if (response.size() < 2) {
            connection_failed({core::ErrorCode::protocol_framing,
                               "DNS TCP response is shorter than its transaction ID"},
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
        read_frame(generation);
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
        close_connection();
        fail_all(error);
    }

    void close_connection() noexcept {
        ++connection_generation_;
        connecting_ = false;
        connected_ = false;
        write_in_progress_ = false;
        read_in_progress_ = false;
        if (stream_) {
            stream_->close();
            stream_.reset();
        }
    }

    runtime::AsioRuntime &runtime_;
    boost::asio::ip::tcp::endpoint endpoint_;
    std::shared_ptr<DnsUpstreamDialer> dialer_;
    std::unique_ptr<io::StreamHandle> stream_;
    // Owns the connect/deadline chain tasks, which always end with a value.
    exec::async_scope scope_;
    std::unordered_map<std::uint16_t, PendingPtr> pending_;
    std::deque<std::uint16_t> write_queue_;
    std::uint64_t connection_generation_ = 0;
    bool connecting_ = false;
    bool connected_ = false;
    bool write_in_progress_ = false;
    bool read_in_progress_ = false;
    bool stopped_ = false;
};

class AsioDnsTransport::Operation final
    : public std::enable_shared_from_this<AsioDnsTransport::Operation> {
  public:
    Operation(AsioDnsTransport &owner, DnsExchangeId exchange_id, DnsExchangeRequest request,
              async::BridgeHandler<DnsExchangeResult> handler)
        : owner_(owner), exchange_id_(exchange_id), request_(std::move(request)),
          handler_(std::move(handler)), udp_endpoint_(owner.config_.endpoint) {}

    void start() {
        const auto query_id = owner_.next_query_id();
        if (!query_id) {
            finish(core::fail({core::ErrorCode::configuration,
                               "DNS transport has no available transaction IDs"}));
            return;
        }
        query_id_ = *query_id;
        owner_.active_query_ids_.insert(query_id_);
        const auto encoded = DnsMessageCodec::rewrite_id(request_.query, query_id_);
        if (!encoded) {
            finish(core::fail(encoded.error()));
            return;
        }
        query_ = encoded.value();
        auto self = shared_from_this();
        // The scope only owns this exchange task (merge-shaped usage);
        // teardown is guard-driven, so no stop is ever requested: the
        // request deadline bounds any orphaned chain, and the map lookup in
        // complete() drops late terminals.
        scope_.spawn(run(shared_from_this()));
        scope_.spawn(run_deadline(self, request_.deadline));
    }

    void cancel() {
        if (completed_) {
            return;
        }
        completed_ = true;
        close_sockets();
        owner_.complete(exchange_id_, core::fail(cancelled_error()));
    }

    async::BridgeHandler<DnsExchangeResult> take_handler() { return std::move(handler_); }
    std::uint16_t query_id() const noexcept { return query_id_; }

  private:
    // Straight-line exchange chain: datagram (or TCP) send/receive, then
    // decode. Every terminal funnels through finish(), so the spawned task
    // always ends with a value.
    static exec::task<void> run(std::shared_ptr<Operation> self) {
        if (std::chrono::steady_clock::now() >= self->request_.deadline) {
            self->finish(core::fail(timeout_error()));
            co_return;
        }
        if (self->owner_.config_.prefer_tcp) {
            co_await run_tcp(self);
            co_return;
        }
        if (!self->owner_.config_.dialer) {
            self->finish(core::fail(
                {core::ErrorCode::configuration, "DNS upstream datagram dialer is not available"}));
            co_return;
        }
        core::DatagramOpenResult opened;
        try {
            opened =
                co_await self->owner_.config_.dialer->open_datagram({core::Destination::address(
                    self->udp_endpoint_.address(), self->udp_endpoint_.port())});
        } catch (const core::Error &failure) {
            self->finish(core::fail(failure));
            co_return;
        } catch (...) {
            self->finish(core::fail(core::Error{core::ErrorCode::endpoint_connection,
                                                "DNS upstream datagram dialer failed to open "
                                                "a handle"}));
            co_return;
        }
        if (self->completed_) {
            if (opened.handle) {
                opened.handle->close();
            }
            co_return;
        }
        if (!opened.succeeded()) {
            self->finish(core::fail(opened.error.value_or(
                core::Error{core::ErrorCode::endpoint_connection,
                            "DNS upstream datagram dialer failed to open a handle"})));
            co_return;
        }
        self->datagram_ = std::move(opened.handle);
        co_await run_udp(self);
        co_return;
    }

    // Deadline task: fires once at the deadline; the completed_ guard in
    // finish() drops it when the exchange already won. Bounded by the
    // deadline, so no stop is ever requested.
    static exec::task<void> run_deadline(std::shared_ptr<Operation> self,
                                         std::chrono::steady_clock::time_point deadline) {
        try {
            co_await async::sleep_until(self->owner_.runtime_.serialized_executor(), deadline);
        } catch (...) {
            co_return;
        }
        self->finish(core::fail(timeout_error()));
        co_return;
    }

    // UDP send/receive loop in one task: mismatched packets re-arm the
    // receive await; truncation falls through to the TCP task.
    static exec::task<void> run_udp(std::shared_ptr<Operation> self) {
        try {
            co_await self->datagram_->async_send_to(
                boost::asio::buffer(self->query_),
                io::DatagramAddress::from_endpoint(self->udp_endpoint_));
        } catch (const core::Error &failure) {
            self->finish(core::fail(failure));
            co_return;
        } catch (...) {
            self->finish(core::fail(
                core::Error{core::ErrorCode::transport_io, "failed to send DNS UDP query"}));
            co_return;
        }
        if (self->completed_) {
            co_return;
        }
        while (!self->completed_) {
            io::DatagramPacket packet;
            try {
                packet = co_await self->datagram_->async_receive_from(
                    boost::asio::buffer(self->response_buffer_));
            } catch (const core::Error &failure) {
                self->finish(core::fail(failure));
                co_return;
            } catch (...) {
                self->finish(core::fail(core::Error{core::ErrorCode::transport_io,
                                                    "failed to receive DNS UDP response"}));
                co_return;
            }
            if (self->completed_) {
                co_return;
            }
            const auto size = packet.size;
            if (!packet.address.is_address() ||
                packet.address.address() != self->udp_endpoint_.address() ||
                packet.address.port() != self->udp_endpoint_.port() || size < 2 ||
                static_cast<std::uint16_t>(self->response_buffer_[0] << 8 |
                                           self->response_buffer_[1]) != self->query_id_) {
                continue;
            }
            const auto response = DnsMessageCodec::decode_packet(
                std::span<const std::uint8_t>(self->response_buffer_.data(), size),
                self->query_id_);
            if (!response) {
                self->finish(core::fail(response.error()));
                co_return;
            }
            if (!self->matches_question(response.value())) {
                continue;
            }
            if (response.value().truncated()) {
                co_await run_tcp(self);
                co_return;
            }
            self->finish(response);
            co_return;
        }
        co_return;
    }

    // TCP fallback: register on the shared session with a oneshot terminal,
    // then await it. cancel() (or the deadline) aborts the session entry so
    // a late response drops by map lookup.
    static exec::task<void> run_tcp(std::shared_ptr<Operation> self) {
        if (self->completed_) {
            co_return;
        }
        if (self->datagram_) {
            self->datagram_->close();
            self->datagram_.reset();
        }
        auto session = self->owner_.tcp_session();
        if (!session) {
            self->finish(
                core::fail({core::ErrorCode::configuration, "DNS TCP session is not available"}));
            co_return;
        }
        self->tcp_session_ = session;
        auto channel = async::oneshot::channel<core::Result<std::vector<std::uint8_t>>>();
        auto sender =
            std::make_shared<async::oneshot::Sender<core::Result<std::vector<std::uint8_t>>>>(
                std::move(channel.sender));
        session->exchange(self->query_id_, self->query_, self->request_.deadline,
                          [sender](core::Result<std::vector<std::uint8_t>> result) mutable {
                              sender->send(std::move(result));
                          });
        auto outcome = co_await std::move(channel.receiver);
        if (self->completed_) {
            co_return;
        }
        if (!outcome) {
            self->finish(core::fail(cancelled_error()));
            co_return;
        }
        if (!*outcome) {
            self->finish(core::fail(outcome->error()));
            co_return;
        }
        self->complete_tcp_response(std::move(outcome->value()));
        co_return;
    }

    void complete_tcp_response(std::vector<std::uint8_t> response_wire) {
        const auto response = DnsMessageCodec::decode_packet(response_wire, query_id_);
        if (!response) {
            finish(core::fail(response.error()));
            return;
        }
        if (!matches_question(response.value())) {
            finish(core::fail({core::ErrorCode::protocol_framing,
                               "DNS response question does not match the query"}));
            return;
        }
        finish(response);
    }

    void close_sockets() noexcept {
        if (datagram_) {
            datagram_->cancel();
            datagram_->close();
            datagram_.reset();
        }
        if (tcp_session_) {
            tcp_session_->cancel(query_id_);
        }
    }

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

    void finish(core::Result<DnsPacket> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        close_sockets();
        owner_.complete(exchange_id_, std::move(result));
    }

    AsioDnsTransport &owner_;
    DnsExchangeId exchange_id_;
    DnsExchangeRequest request_;
    async::BridgeHandler<DnsExchangeResult> handler_;
    boost::asio::ip::udp::endpoint udp_endpoint_;
    std::vector<std::uint8_t> response_buffer_ = std::vector<std::uint8_t>(65535);
    std::vector<std::uint8_t> query_;
    std::unique_ptr<io::DatagramHandle> datagram_;
    std::shared_ptr<AsioDnsTransport::TcpSession> tcp_session_;
    std::uint16_t query_id_ = 0;
    bool completed_ = false;
    // Owns the exchange/deadline chain tasks, which always end with a value.
    exec::async_scope scope_;
};

std::optional<std::uint16_t> AsioDnsTransport::next_query_id() noexcept {
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

std::shared_ptr<AsioDnsTransport::TcpSession> AsioDnsTransport::tcp_session() {
    if (stopped_) {
        return nullptr;
    }
    if (!tcp_session_) {
        const auto endpoint = config_.tcp_endpoint.value_or(
            boost::asio::ip::tcp::endpoint(config_.endpoint.address(), config_.endpoint.port()));
        tcp_session_ = std::make_shared<TcpSession>(runtime_, endpoint, config_.dialer);
    }
    return tcp_session_;
}

io::AnySender<DnsExchangeResult> AsioDnsTransport::exchange(DnsExchangeRequest request) {
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

DnsExchangeId AsioDnsTransport::open_exchange(DnsExchangeRequest request,
                                              async::BridgeHandler<DnsExchangeResult> handler) {
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

void AsioDnsTransport::cancel_exchange(DnsExchangeId exchange_id) noexcept {
    const auto operation = operations_.find(exchange_id);
    if (operation != operations_.end()) {
        operation->second->cancel();
    }
}

void AsioDnsTransport::stop() noexcept {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    while (!operations_.empty()) {
        operations_.begin()->second->cancel();
    }
    if (tcp_session_) {
        tcp_session_->stop();
    }
}

void AsioDnsTransport::complete(DnsExchangeId exchange_id, core::Result<DnsPacket> result) {
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

std::shared_ptr<DnsTransport> make_asio_dns_transport(runtime::AsioRuntime &runtime,
                                                      DnsUpstreamConfig config) {
    if (!config.hostname.empty()) {
        return make_bootstrap_dns_transport(runtime, std::move(config));
    }
    if (config.mode == DnsTransportMode::dot) {
        return make_dot_dns_transport(runtime, std::move(config));
    }
    if (config.mode == DnsTransportMode::doh1) {
        return make_doh1_dns_transport(runtime, std::move(config));
    }
    if (config.mode == DnsTransportMode::doh2) {
        return make_doh2_dns_transport(runtime, std::move(config));
    }
    if (config.mode == DnsTransportMode::doq || config.mode == DnsTransportMode::doh3) {
        return make_quic_dns_transport(runtime, std::move(config));
    }
    return std::make_shared<AsioDnsTransport>(runtime, std::move(config));
}

std::shared_ptr<DnsUpstreamDialer> make_direct_dns_upstream_dialer(runtime::AsioRuntime &runtime) {
    auto outbound = std::make_shared<outbound::DirectOutbound>(runtime);
    auto plan = transport::EndpointDialPlan::from_outbound(std::move(outbound), "direct");
    return std::make_shared<PlannedDnsUpstreamDialer>(runtime, std::move(plan));
}

std::shared_ptr<DnsUpstreamDialer> make_outbound_dns_upstream_dialer(
    runtime::AsioRuntime &runtime, outbound::OutboundRegistry::Snapshot registry,
    std::string outbound_id, transport::EndpointDialRequirements requirements) {
    return std::make_shared<OutboundDnsUpstreamDialer>(runtime, std::move(registry),
                                                       std::move(outbound_id), requirements);
}

std::shared_ptr<DnsUpstreamDialer> make_traffic_rules_dns_upstream_dialer(
    runtime::AsioRuntime &runtime, outbound::OutboundRegistry::Snapshot registry,
    router::TrafficRouter::Snapshot traffic_router, std::string egress_hostname) {
    return std::make_shared<TrafficRulesDnsUpstreamDialer>(
        runtime, std::move(registry), std::move(traffic_router), std::move(egress_hostname));
}

} // namespace clash_native::dns
