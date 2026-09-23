#include "quic_dns_transport_internal.hpp"
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/io/datagram_handle.hpp>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

using Clock = std::chrono::steady_clock;
constexpr std::size_t kMaximumIdleQuicSessions = 4;
constexpr std::size_t kMaximumConcurrentExchangesPerSession = 64;
constexpr auto kMinimumQuicHandshakeTimeout = std::chrono::seconds(30);
constexpr std::uint64_t kDoqRequestCancelled = 0x3;
constexpr std::uint64_t kHttp3RequestCancelled = 0x10c;

using quic_dns_detail::protocol_error;
using quic_dns_detail::transport_error;

core::Error timeout_error() { return {core::ErrorCode::timeout, "QUIC DNS query timed out", {}}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "QUIC DNS query was cancelled", {}};
}

bool same_question(const DnsPacket &response, const DnsPacket &query) {
    if (!response.response() || response.questions.size() != query.questions.size()) {
        return false;
    }
    return std::equal(response.questions.begin(), response.questions.end(), query.questions.begin(),
                      [](const DnsQuestion &left, const DnsQuestion &right) {
                          return normalize_name(left.name) == normalize_name(right.name) &&
                                 left.type == right.type && left.class_code == right.class_code;
                      });
}

std::uint16_t remote_port(const DnsUpstreamConfig &config) {
    if (config.endpoint.port() != 53) {
        return config.endpoint.port();
    }
    return config.mode == DnsTransportMode::doq ? std::uint16_t{853} : std::uint16_t{443};
}

std::string remote_name(const DnsUpstreamConfig &config) {
    if (!config.server_name.empty()) {
        return config.server_name;
    }
    if (!config.hostname.empty()) {
        return config.hostname;
    }
    return config.endpoint.address().to_string();
}

std::string authority(const DnsUpstreamConfig &config, std::string host, std::uint16_t port) {
    if (!config.doh_authority.empty()) {
        return config.doh_authority;
    }
    if (host.find(':') != std::string::npos && (host.empty() || host.front() != '[')) {
        host = '[' + host + ']';
    }
    if (port != 443) {
        host += ':' + std::to_string(port);
    }
    return host;
}

} // namespace

QuicDnsTransport::QuicDnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
    : runtime_(runtime), config_(std::move(config)), strand_(runtime.serialized_executor()) {
    if (!config_.dialer) {
        config_.dialer = make_direct_dns_upstream_dialer(runtime_);
    }
}

QuicDnsTransport::Operation::Operation(QuicDnsTransport &owner)
    : owner_(owner), idle_timer_(owner.runtime_.serialized_executor()), mode_(owner.config_.mode),
      host_(remote_name(owner.config_)), port_(remote_port(owner.config_)),
      remote_endpoint_(owner.config_.endpoint.address(), port_),
      authority_(authority(owner.config_, host_, port_)),
      path_(owner.config_.doh_path.empty() ? "/dns-query" : owner.config_.doh_path) {}

bool QuicDnsTransport::Operation::can_accept_exchange() const noexcept {
    return !retired_ && exchanges_.size() < kMaximumConcurrentExchangesPerSession;
}

std::size_t QuicDnsTransport::Operation::active_exchange_count() const noexcept {
    return exchanges_.size();
}

void QuicDnsTransport::Operation::close_idle() noexcept { retire_idle(); }

bool QuicDnsTransport::Operation::is_idle() const noexcept { return idle_ && !retired_; }

void QuicDnsTransport::Operation::start_on_strand() {
    if (started_ || retired_ || exchanges_.empty()) {
        return;
    }
    started_ = true;
    const auto self = shared_from_this();
    const auto destination = core::Destination::address(owner_.config_.endpoint.address(), port_);
    struct OpenReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<Operation> self;

        void set_value(core::DatagramOpenResult result) && noexcept {
            auto operation = std::move(self);
            std::unique_ptr<io::DatagramHandle> handle = std::move(result.handle);
            std::optional<core::Error> error = std::move(result.error);
            if (handle) {
                error.reset();
            }
            dispatch_opened(std::move(operation), std::move(handle), std::move(error));
        }

        void set_error(std::exception_ptr error) && noexcept {
            auto operation = std::move(self);
            std::optional<core::Error> failure =
                core::Error{core::ErrorCode::endpoint_connection,
                            "QUIC DNS datagram dialer failed to open a handle"};
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &open_error) {
                failure = open_error;
            } catch (...) {
            }
            dispatch_opened(std::move(operation), nullptr, std::move(failure));
        }

        void set_stopped() && noexcept {
            auto operation = std::move(self);
            dispatch_opened(
                std::move(operation), nullptr,
                core::Error{core::ErrorCode::cancelled, "QUIC DNS datagram open was cancelled"});
        }

        // Copyable strand hop: ferrying move-only captures through
        // asio::dispatch on this path proved unreliable, so the payload
        // rides a shared state instead. Sessions-plane debt with the
        // adapter above.
        static void dispatch_opened(std::shared_ptr<Operation> operation,
                                    std::unique_ptr<io::DatagramHandle> handle,
                                    std::optional<core::Error> error) noexcept {
            struct StrandState {
                std::shared_ptr<Operation> operation;
                std::unique_ptr<io::DatagramHandle> handle;
                std::optional<core::Error> error;
            };
            auto state = std::make_shared<StrandState>(
                StrandState{std::move(operation), std::move(handle), std::move(error)});
            boost::asio::dispatch(state->operation->owner_.strand_, [state]() mutable {
                state->operation->datagram_opened(std::move(state->handle),
                                                  std::move(state->error));
            });
        }
    };
    async::start_with_receiver(owner_.config_.dialer->open_datagram({destination}),
                               OpenReceiver{std::move(self)});
}

void QuicDnsTransport::Operation::add_exchange(ExchangeId id, DnsExchangeRequest request) {
    if (retired_) {
        owner_.complete(id, core::fail(transport_error("QUIC DNS session is retired")));
        return;
    }
    idle_timer_.cancel();
    idle_ = false;
    auto exchange =
        std::make_shared<Exchange>(id, std::move(request), owner_.runtime_.serialized_executor());
    exchanges_.emplace(id, exchange);
    const auto &wire = exchange->request.query.wire;
    if (wire.size() < 12 || wire.size() > 0xffff) {
        set_exchange_error(*exchange,
                           protocol_error("QUIC DNS query has an invalid message length"));
        drain_exchange_results();
        return;
    }
    if (mode_ == DnsTransportMode::doh3 &&
        (path_.empty() || path_.front() != '/' ||
         std::any_of(path_.begin(), path_.end(),
                     [](unsigned char value) { return value <= 0x20 || value == 0x7f; }))) {
        set_exchange_error(*exchange,
                           core::Error{core::ErrorCode::configuration,
                                       "DoH/HTTP/3 path is not a valid origin-form target",
                                       {}});
        drain_exchange_results();
        return;
    }
    if (Clock::now() >= exchange->request.deadline) {
        set_exchange_error(*exchange, timeout_error());
        drain_exchange_results();
        return;
    }
    exchange->deadline_timer.expires_at(exchange->request.deadline);
    const auto self = shared_from_this();
    exchange->deadline_timer.async_wait(boost::asio::bind_executor(
        owner_.strand_, [self, id](const boost::system::error_code &error) {
            if (!error) {
                self->cancel_exchange(id, timeout_error());
            }
        }));
    if (mode_ == DnsTransportMode::doq || !http3_) {
        pending_exchanges_.push_back(id);
    } else {
        submit_http3_exchange(exchange);
    }
    if (mode_ == DnsTransportMode::doq && handshake_completed_) {
        pump_open_pending_exchanges();
    }
    start_on_strand();
}

void QuicDnsTransport::Operation::cancel_exchange(ExchangeId id, core::Error error) {
    const auto found = exchanges_.find(id);
    if (found == exchanges_.end() || found->second->result) {
        return;
    }
    set_exchange_error(*found->second, std::move(error));
    drain_exchange_results();
}

void QuicDnsTransport::Operation::cancel_all() {
    std::vector<ExchangeId> ids;
    ids.reserve(exchanges_.size());
    for (const auto &[id, exchange] : exchanges_) {
        (void)exchange;
        ids.push_back(id);
    }
    for (const auto id : ids) {
        cancel_exchange(id, cancelled_error());
    }
}

void QuicDnsTransport::Operation::datagram_opened(std::unique_ptr<io::DatagramHandle> handle,
                                                  std::optional<core::Error> error) {
    if (retired_ || exchanges_.empty()) {
        if (handle) {
            handle->close();
        }
        if (!retired_) {
            retire_session();
        }
        return;
    }
    if (!handle) {
        fail_session(error.value_or(core::Error{core::ErrorCode::endpoint_connection,
                                                "QUIC DNS datagram dialer failed to open a handle",
                                                {}}));
        return;
    }

    const auto latest_deadline =
        std::max_element(exchanges_.begin(), exchanges_.end(),
                         [](const auto &left, const auto &right) {
                             return left.second->request.deadline < right.second->request.deadline;
                         })
            ->second->request.deadline;
    const auto remaining = latest_deadline - Clock::now();
    transport::QuicClientOptions options;
    options.server_name = host_;
    options.verify_peer = owner_.config_.verify_peer;
    options.alpn_protocols = {mode_ == DnsTransportMode::doq ? "doq" : "h3"};
    options.handshake_timeout =
        std::max(std::chrono::duration_cast<Clock::duration>(remaining),
                 std::chrono::duration_cast<Clock::duration>(kMinimumQuicHandshakeTimeout));

    transport::QuicClientEvents events;
    if (mode_ == DnsTransportMode::doq) {
        events = make_doq_events();
    }

    quic_ = transport::make_quic_client_connection(
        owner_.strand_, std::move(handle), remote_endpoint_, std::move(options), std::move(events));
    if (!quic_) {
        fail_session(core::Error{
            core::ErrorCode::configuration, "failed to create shared QUIC connection", {}});
        return;
    }

    if (mode_ == DnsTransportMode::doh3) {
        start_doh3_session();
    }
}

void QuicDnsTransport::Operation::decode_dns_response(Exchange &exchange,
                                                      std::span<const std::uint8_t> wire) {
    const auto response = DnsMessageCodec::decode_packet(wire, exchange.request.query.id);
    if (!response) {
        set_exchange_error(exchange, response.error());
        return;
    }
    if (!same_question(response.value(), exchange.request.query)) {
        set_exchange_error(exchange,
                           protocol_error("QUIC DNS response question does not match the query"));
        return;
    }
    if (!exchange.result) {
        exchange.result.emplace(response.value());
    }
}

void QuicDnsTransport::Operation::set_exchange_error(Exchange &exchange, core::Error error) {
    if (!exchange.result) {
        exchange.result.emplace(core::fail(std::move(error)));
    }
}

void QuicDnsTransport::Operation::drain_exchange_results() {
    std::vector<std::pair<ExchangeId, core::Result<DnsPacket>>> completed;
    for (auto &[id, exchange] : exchanges_) {
        if (exchange->result) {
            completed.emplace_back(id, std::move(*exchange->result));
            exchange->result.reset();
        }
    }
    for (auto &[id, result] : completed) {
        complete_exchange(id, std::move(result));
    }
}

void QuicDnsTransport::Operation::complete_exchange(ExchangeId id, core::Result<DnsPacket> result) {
    const auto found = exchanges_.find(id);
    if (found == exchanges_.end()) {
        return;
    }
    const auto exchange = found->second;
    (void)exchange->deadline_timer.cancel();
    if (!result) {
        // The HTTP exchange already reached its terminal to get here; the
        // io:: vocabulary cancels in-flight work through the stop token.
        if (exchange->stream_id >= 0 && quic_) {
            quic_->shutdown_stream(exchange->stream_id, mode_ == DnsTransportMode::doq
                                                            ? kDoqRequestCancelled
                                                            : kHttp3RequestCancelled);
        }
    }
    exchanges_.erase(found);
    owner_.complete(id, std::move(result));
    if (exchanges_.empty()) {
        enter_idle_or_retire();
    }
}

void QuicDnsTransport::Operation::enter_idle_or_retire() {
    if (retired_) {
        return;
    }
    if (quic_ == nullptr || !quic_->ready()) {
        retire_session();
        return;
    }
    idle_ = true;
    const auto self = shared_from_this();
    idle_timer_.expires_after(std::chrono::seconds(30));
    idle_timer_.async_wait(
        boost::asio::bind_executor(owner_.strand_, [self](const boost::system::error_code &error) {
            if (!error && self->exchanges_.empty()) {
                self->retire_idle();
            }
        }));
    owner_.session_idle(self);
}

void QuicDnsTransport::Operation::retire_idle() noexcept {
    if (retired_ || !exchanges_.empty()) {
        return;
    }
    retire_session();
}

void QuicDnsTransport::Operation::retire_session() noexcept {
    if (retired_) {
        return;
    }
    retired_ = true;
    idle_ = false;
    (void)idle_timer_.cancel();
    if (http3_) {
        http3_->stop();
        http3_.reset();
    }
    if (quic_) {
        quic_->close();
        quic_.reset();
    }
    exchanges_.clear();
    stream_exchanges_.clear();
    pending_exchanges_.clear();
    owner_.session_retired(this);
}

void QuicDnsTransport::Operation::fail_session(core::Error error) {
    if (retired_) {
        return;
    }
    std::vector<ExchangeId> exchange_ids;
    exchange_ids.reserve(exchanges_.size());
    for (const auto &[id, exchange] : exchanges_) {
        exchange_ids.push_back(id);
        (void)exchange->deadline_timer.cancel();
    }
    retired_ = true;
    idle_ = false;
    (void)idle_timer_.cancel();
    if (http3_) {
        http3_->stop();
        http3_.reset();
    }
    if (quic_) {
        quic_->close();
        quic_.reset();
    }
    exchanges_.clear();
    stream_exchanges_.clear();
    pending_exchanges_.clear();
    owner_.session_retired(this);
    for (const auto id : exchange_ids) {
        owner_.complete(id, core::fail(error));
    }
}

DnsTransport::ExchangeId QuicDnsTransport::exchange(DnsExchangeRequest request, Handler handler) {
    const auto id = next_exchange_id_.fetch_add(1, std::memory_order_relaxed);
    const auto self = shared_from_this();
    boost::asio::post(
        strand_, [self, id, request = std::move(request), handler = std::move(handler)]() mutable {
            self->add_new_exchange(id, std::move(request), std::move(handler));
        });
    return id;
}

void QuicDnsTransport::add_new_exchange(ExchangeId id, DnsExchangeRequest request,
                                        Handler handler) {
    if (stopped_) {
        if (handler) {
            handler(core::fail(cancelled_error()));
        }
        return;
    }

    std::shared_ptr<Operation> operation;
    for (const auto &candidate : active_sessions_) {
        if (candidate->can_accept_exchange() &&
            (!operation ||
             candidate->active_exchange_count() < operation->active_exchange_count())) {
            operation = candidate;
        }
    }
    if (!operation && !idle_sessions_.empty()) {
        operation = std::move(idle_sessions_.back());
        idle_sessions_.pop_back();
        active_sessions_.push_back(operation);
    }
    if (!operation) {
        operation = std::make_shared<Operation>(*this);
        active_sessions_.push_back(operation);
    }
    exchanges_.emplace(id, ExchangeRegistration{operation, std::move(handler)});
    operation->add_exchange(id, std::move(request));
}

void QuicDnsTransport::cancel(ExchangeId exchange_id) noexcept {
    try {
        const auto self = shared_from_this();
        boost::asio::post(strand_, [self, exchange_id] {
            const auto found = self->exchanges_.find(exchange_id);
            if (found != self->exchanges_.end()) {
                found->second.operation->cancel_exchange(exchange_id, cancelled_error());
            }
        });
    } catch (...) {
    }
}

void QuicDnsTransport::stop() noexcept {
    try {
        const auto self = shared_from_this();
        boost::asio::post(strand_, [self] {
            if (self->stopped_) {
                return;
            }
            self->stopped_ = true;
            const auto active = self->active_sessions_;
            for (const auto &operation : active) {
                operation->cancel_all();
            }
            const auto idle = std::move(self->idle_sessions_);
            self->idle_sessions_.clear();
            for (const auto &operation : idle) {
                operation->close_idle();
            }
        });
    } catch (...) {
    }
}

void QuicDnsTransport::session_idle(const std::shared_ptr<Operation> &operation) {
    std::erase_if(active_sessions_, [&operation](const auto &candidate) {
        return candidate.get() == operation.get();
    });
    if (stopped_ || !operation->is_idle()) {
        operation->close_idle();
        return;
    }
    const auto already_idle = std::any_of(
        idle_sessions_.begin(), idle_sessions_.end(),
        [&operation](const auto &candidate) { return candidate.get() == operation.get(); });
    if (!already_idle) {
        idle_sessions_.push_back(operation);
    }
    if (idle_sessions_.size() > kMaximumIdleQuicSessions) {
        auto oldest = std::move(idle_sessions_.front());
        idle_sessions_.erase(idle_sessions_.begin());
        oldest->close_idle();
    }
}

void QuicDnsTransport::session_retired(const Operation *operation) noexcept {
    std::erase_if(active_sessions_,
                  [operation](const auto &candidate) { return candidate.get() == operation; });
    std::erase_if(idle_sessions_,
                  [operation](const auto &candidate) { return candidate.get() == operation; });
}

void QuicDnsTransport::complete(ExchangeId exchange_id, core::Result<DnsPacket> result) {
    const auto found = exchanges_.find(exchange_id);
    if (found == exchanges_.end()) {
        return;
    }
    auto handler = std::move(found->second.handler);
    exchanges_.erase(found);
    if (handler) {
        handler(std::move(result));
    }
}

std::shared_ptr<DnsTransport> make_quic_dns_transport(runtime::AsioRuntime &runtime,
                                                      DnsUpstreamConfig config) {
    return std::make_shared<QuicDnsTransport>(runtime, std::move(config));
}

} // namespace clash_native::dns
