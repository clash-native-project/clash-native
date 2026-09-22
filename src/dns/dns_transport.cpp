#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/outbound/builtin_outbound.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>

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

    void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) override {
        if (endpoint_dialer_) {
            endpoint_dialer_->open_datagram(std::move(request), std::move(handler));
            return;
        }
        const auto error = plan_error_.value_or(
            core::Error{core::ErrorCode::configuration, "DNS endpoint dial plan is missing"});
        runtime_.scheduler().post([handler = std::move(handler), error]() mutable {
            handler(core::DatagramOpenResult::failed(error));
        });
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

    void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) override {
        if (!request.initial_destination) {
            post_datagram_error(
                std::move(handler),
                {core::ErrorCode::configuration, "DNS egress request has no destination", {}});
            return;
        }
        const auto plan = make_plan(*request.initial_destination, core::Network::udp, std::nullopt);
        if (!plan) {
            post_datagram_error(std::move(handler), plan.error());
            return;
        }
        transport::EndpointDialer dialer(runtime_.serialized_executor(), plan.value());
        dialer.open_datagram(std::move(request), std::move(handler));
    }

  private:
    void post_datagram_error(core::DatagramOpenHandler handler, core::Error error) const {
        runtime_.scheduler().post(
            [handler = std::move(handler), error = std::move(error)]() mutable {
                handler(core::DatagramOpenResult::failed(std::move(error)));
            });
    }

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

void OutboundDnsUpstreamDialer::open_datagram(core::DatagramRequest request,
                                              core::DatagramOpenHandler handler) {
    if (plan_error_) {
        const auto error = *plan_error_;
        runtime_.scheduler().post([handler = std::move(handler), error]() mutable {
            handler(core::DatagramOpenResult::failed(error));
        });
        return;
    }
    endpoint_dialer_->open_datagram(std::move(request), std::move(handler));
}

class AsioDnsTransport final : public DnsTransport {
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

    ExchangeId exchange(DnsExchangeRequest request, Handler handler) override;
    void cancel(ExchangeId exchange_id) noexcept override;
    void stop() noexcept override;

  private:
    void complete(ExchangeId exchange_id, core::Result<DnsPacket> result);
    std::optional<std::uint16_t> next_query_id() noexcept;
    std::shared_ptr<TcpSession> tcp_session();

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    std::unordered_map<ExchangeId, std::shared_ptr<Operation>> operations_;
    std::shared_ptr<TcpSession> tcp_session_;
    std::unordered_set<std::uint16_t> active_query_ids_;
    ExchangeId next_exchange_id_ = 1;
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

        auto pending = std::make_shared<Pending>(runtime_.serialized_executor());
        pending->frame.reserve(2 + query.size());
        pending->frame.push_back(static_cast<std::uint8_t>(query.size() >> 8));
        pending->frame.push_back(static_cast<std::uint8_t>(query.size() & 0xff));
        pending->frame.insert(pending->frame.end(), query.begin(), query.end());
        pending->handler = std::move(handler);
        pending->timer.expires_at(deadline);
        auto self = shared_from_this();
        pending->timer.async_wait([self, query_id](const boost::system::error_code &error) {
            if (!error) {
                self->fail_request(query_id, timeout_error());
            }
        });
        pending_.emplace(query_id, pending);
        write_queue_.push_back(query_id);
        connect_if_needed();
        flush_writes();
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
        explicit Pending(boost::asio::any_io_executor executor) : timer(std::move(executor)) {}

        std::vector<std::uint8_t> frame;
        Handler handler;
        boost::asio::steady_timer timer;
    };

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

    void connect_if_needed() {
        if (stopped_ || connected_ || connecting_ || pending_.empty()) {
            return;
        }

        connecting_ = true;
        const auto generation = connection_generation_;
        if (!dialer_) {
            connection_failed(
                {core::ErrorCode::configuration, "DNS upstream stream dialer is not configured"},
                generation);
            return;
        }
        auto self = shared_from_this();
        struct ConnectReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<TcpSession> self;
            std::uint64_t generation;
            void set_value(core::StreamOpenResult result) && noexcept {
                if (generation != self->connection_generation_ || self->stopped_) {
                    if (result.handle) {
                        result.handle->close();
                    }
                    return;
                }
                if (!result.succeeded()) {
                    self->connection_failed(result.error.value_or(core::Error{
                                                core::ErrorCode::endpoint_connection,
                                                "DNS upstream dialer failed to open a stream"}),
                                            generation);
                    return;
                }
                self->stream_ = std::move(result.handle);
                self->on_connected(generation);
            }
            void set_error(std::exception_ptr error) && noexcept {
                if (generation != self->connection_generation_ || self->stopped_) {
                    return;
                }
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const core::Error &failure) {
                    self->connection_failed(failure, generation);
                } catch (...) {
                    self->connection_failed(core::Error{core::ErrorCode::endpoint_connection,
                                                        "DNS upstream dialer failed"},
                                            generation);
                }
            }
            void set_stopped() && noexcept {}
        };
        async::start_with_receiver(
            dialer_->connect_stream(
                {core::Destination::address(endpoint_.address(), endpoint_.port()), std::nullopt}),
            ConnectReceiver{self, generation});
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
            pending->timer.cancel();
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
        pending->timer.cancel();
        if (pending->handler) {
            auto handler = std::move(pending->handler);
            handler(core::fail(std::move(error)));
        }
    }

    void fail_all(const core::Error &error) {
        std::vector<Handler> handlers;
        handlers.reserve(pending_.size());
        for (auto &[query_id, pending] : pending_) {
            pending->timer.cancel();
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
    Operation(AsioDnsTransport &owner, ExchangeId exchange_id, DnsExchangeRequest request,
              Handler handler)
        : owner_(owner), exchange_id_(exchange_id), request_(std::move(request)),
          handler_(std::move(handler)), timeout_timer_(owner.runtime_.serialized_executor()),
          udp_endpoint_(owner.config_.endpoint) {}

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

        timeout_timer_.expires_at(request_.deadline);
        auto self = shared_from_this();
        timeout_timer_.async_wait([self](const boost::system::error_code &error) {
            if (!error && !self->completed_) {
                self->retry_or_finish(timeout_error());
            }
        });
        start_attempt();
    }

    void cancel() {
        if (completed_) {
            return;
        }
        completed_ = true;
        close_sockets();
        owner_.complete(exchange_id_, core::fail(cancelled_error()));
    }

    Handler take_handler() { return std::move(handler_); }
    std::uint16_t query_id() const noexcept { return query_id_; }

  private:
    void start_attempt() {
        if (completed_) {
            return;
        }
        if (std::chrono::steady_clock::now() >= request_.deadline) {
            finish(core::fail(timeout_error()));
            return;
        }

        const auto generation = ++attempt_generation_;
        if (owner_.config_.prefer_tcp) {
            start_tcp(generation);
            return;
        }

        auto self = shared_from_this();
        if (!owner_.config_.dialer) {
            retry_or_finish(
                {core::ErrorCode::configuration, "DNS upstream datagram dialer is not available"});
            return;
        }
        owner_.config_.dialer->open_datagram(
            {core::Destination::address(udp_endpoint_.address(), udp_endpoint_.port())},
            [self, generation](core::DatagramOpenResult result) mutable {
                if (generation != self->attempt_generation_ || self->completed_) {
                    if (result.handle) {
                        result.handle->close();
                    }
                    return;
                }
                if (!result.succeeded()) {
                    self->retry_or_finish(result.error.value_or(
                        core::Error{core::ErrorCode::endpoint_connection,
                                    "DNS upstream datagram dialer failed to open a handle"}));
                    return;
                }
                self->datagram_ = std::move(result.handle);
                self->send_udp(generation);
            });
    }

    void send_udp(std::uint64_t generation) {
        if (completed_ || generation != attempt_generation_ || !datagram_) {
            return;
        }
        auto self = shared_from_this();
        datagram_->async_send_to(
            boost::asio::buffer(query_), core::DatagramAddress::from_endpoint(udp_endpoint_),
            [self, generation](const boost::system::error_code &send_error, std::size_t) {
                if (generation != self->attempt_generation_ || self->completed_) {
                    return;
                }
                if (send_error) {
                    self->retry_or_finish(
                        upstream_error("failed to send DNS UDP query", send_error));
                    return;
                }
                self->receive_udp(generation);
            });
    }

    void receive_udp(std::uint64_t generation) {
        if (completed_ || generation != attempt_generation_) {
            return;
        }
        auto self = shared_from_this();
        datagram_->async_receive_from(
            boost::asio::buffer(response_buffer_),
            [self, generation](const boost::system::error_code &error, std::size_t size,
                               core::DatagramAddress sender) {
                if (generation != self->attempt_generation_ || self->completed_) {
                    return;
                }
                if (error) {
                    self->retry_or_finish(
                        upstream_error("failed to receive DNS UDP response", error));
                    return;
                }
                if (!sender.is_address() || sender.address() != self->udp_endpoint_.address() ||
                    sender.port() != self->udp_endpoint_.port() || size < 2 ||
                    static_cast<std::uint16_t>(self->response_buffer_[0] << 8 |
                                               self->response_buffer_[1]) != self->query_id_) {
                    self->receive_udp(generation);
                    return;
                }

                const auto response = DnsMessageCodec::decode_packet(
                    std::span<const std::uint8_t>(self->response_buffer_.data(), size),
                    self->query_id_);
                if (!response) {
                    self->finish(core::fail(response.error()));
                    return;
                }
                if (!self->matches_question(response.value())) {
                    self->receive_udp(generation);
                    return;
                }
                if (response.value().truncated()) {
                    self->start_tcp(generation);
                    return;
                }
                self->finish(response);
            });
    }

    void start_tcp(std::uint64_t generation) {
        if (completed_ || generation != attempt_generation_) {
            return;
        }
        if (datagram_) {
            datagram_->close();
            datagram_.reset();
        }
        tcp_session_ = owner_.tcp_session();
        if (!tcp_session_) {
            retry_or_finish({core::ErrorCode::configuration, "DNS TCP session is not available"});
            return;
        }
        auto self = shared_from_this();
        tcp_session_->exchange(
            query_id_, query_, request_.deadline,
            [self, generation](core::Result<std::vector<std::uint8_t>> result) {
                if (generation != self->attempt_generation_ || self->completed_) {
                    return;
                }
                if (!result) {
                    self->retry_or_finish(result.error());
                    return;
                }
                self->complete_tcp_response(generation, std::move(result.value()));
            });
    }

    void complete_tcp_response(std::uint64_t generation, std::vector<std::uint8_t> response_wire) {
        if (generation != attempt_generation_ || completed_) {
            return;
        }
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

    void retry_or_finish(core::Error error) { finish(core::fail(std::move(error))); }

    void close_sockets() noexcept {
        timeout_timer_.cancel();
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
    ExchangeId exchange_id_;
    DnsExchangeRequest request_;
    Handler handler_;
    boost::asio::steady_timer timeout_timer_;
    boost::asio::ip::udp::endpoint udp_endpoint_;
    std::vector<std::uint8_t> response_buffer_ = std::vector<std::uint8_t>(65535);
    std::vector<std::uint8_t> query_;
    std::unique_ptr<core::DatagramHandle> datagram_;
    std::shared_ptr<AsioDnsTransport::TcpSession> tcp_session_;
    std::uint16_t query_id_ = 0;
    bool completed_ = false;
    std::uint64_t attempt_generation_ = 0;
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

DnsTransport::ExchangeId AsioDnsTransport::exchange(DnsExchangeRequest request, Handler handler) {
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

void AsioDnsTransport::cancel(ExchangeId exchange_id) noexcept {
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

void AsioDnsTransport::complete(ExchangeId exchange_id, core::Result<DnsPacket> result) {
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
