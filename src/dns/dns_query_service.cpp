#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_query_service.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <semaphore>
#include <string_view>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

std::string cache_key(const DnsQuestion &question, std::string_view upstream_group,
                      std::uint64_t generation) {
    return normalize_name(question.name) + "|" +
           std::to_string(static_cast<std::uint16_t>(question.type)) + "|" +
           std::to_string(question.class_code) + "|" + std::string(upstream_group) + "|" +
           std::to_string(generation);
}

core::Error cancelled_error() { return {core::ErrorCode::cancelled, "DNS query was cancelled"}; }

core::Error invalid_query_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context)};
}

bool is_builtin_default_group(std::string_view group) {
    return group.empty() || group == "default" || group == "$default" || group == "system";
}

std::optional<std::chrono::seconds> cache_ttl(const DnsPacket &packet,
                                              std::chrono::seconds negative_cache_ttl) {
    if (packet.response_code() == 3 || (packet.response_code() == 0 && packet.answers.empty())) {
        auto ttl = negative_cache_ttl.count();
        for (const auto &record : packet.authorities) {
            if (record.type != static_cast<std::uint16_t>(DnsRecordType::soa) ||
                record.rdata.size() < 4) {
                continue;
            }
            const auto minimum =
                (static_cast<std::uint32_t>(record.rdata[record.rdata.size() - 4]) << 24) |
                (static_cast<std::uint32_t>(record.rdata[record.rdata.size() - 3]) << 16) |
                (static_cast<std::uint32_t>(record.rdata[record.rdata.size() - 2]) << 8) |
                static_cast<std::uint32_t>(record.rdata.back());
            ttl = std::min<std::int64_t>(ttl, record.ttl_seconds);
            ttl = std::min<std::int64_t>(ttl, minimum);
        }
        if (ttl <= 0) {
            return std::nullopt;
        }
        return std::chrono::seconds(ttl);
    }
    if (packet.response_code() != 0 || packet.answers.empty()) {
        return std::nullopt;
    }

    std::uint32_t ttl = std::numeric_limits<std::uint32_t>::max();
    for (const auto &record : packet.answers) {
        ttl = std::min(ttl, record.ttl_seconds);
    }
    if (ttl == 0 || ttl == std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }
    return std::chrono::seconds(ttl);
}

DnsTransportFactory default_transport_factory() {
    return [](runtime::AsioRuntime &runtime, DnsUpstreamConfig config) {
        return make_asio_dns_transport(runtime, std::move(config));
    };
}

} // namespace

class DnsQueryService::Operation final
    : public std::enable_shared_from_this<DnsQueryService::Operation> {
  public:
    struct Waiter {
        RequestId id;
        std::uint16_t response_id;
        Handler handler;
        CompletionScheduler completion_scheduler;
    };

    Operation(DnsQueryService &owner, std::string key, DnsPacket packet,
              std::shared_ptr<DnsUpstreamGroup> upstream)
        : owner_(owner), key_(std::move(key)), packet_(std::move(packet)),
          upstream_(std::move(upstream)) {}

    const std::string &key() const noexcept { return key_; }

    std::uint16_t packet_id() const noexcept { return packet_.id; }

    void add_waiter(RequestId id, std::uint16_t response_id, Handler handler,
                    CompletionScheduler completion_scheduler) {
        waiters_.push_back({id, response_id, std::move(handler), std::move(completion_scheduler)});
    }

    std::optional<Waiter> remove_waiter(RequestId id) {
        const auto found = std::find_if(waiters_.begin(), waiters_.end(),
                                        [id](const Waiter &waiter) { return waiter.id == id; });
        if (found == waiters_.end()) {
            return std::nullopt;
        }
        auto waiter = std::move(*found);
        waiters_.erase(found);
        return waiter;
    }

    bool has_waiters() const noexcept { return !waiters_.empty(); }

    std::vector<Waiter> take_waiters() { return std::move(waiters_); }

    void start() {
        auto self = shared_from_this();
        const auto deadline = std::chrono::steady_clock::now() + upstream_->timeout();
        exchange_id_ =
            upstream_->exchange(packet_, deadline, [self](core::Result<DnsPacket> result) {
                self->finish(std::move(result));
            });
        exchange_started_ = true;
        if (completed_) {
            upstream_->cancel(exchange_id_);
        }
    }

    void cancel_shared() {
        if (completed_) {
            return;
        }
        completed_ = true;
        if (upstream_ && exchange_started_) {
            upstream_->cancel(exchange_id_);
        }
        owner_.complete(shared_from_this(), core::fail(cancelled_error()));
    }

  private:
    void finish(core::Result<DnsPacket> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        owner_.complete(shared_from_this(), std::move(result));
    }

    DnsQueryService &owner_;
    std::string key_;
    DnsPacket packet_;
    std::shared_ptr<DnsUpstreamGroup> upstream_;
    DnsTransport::ExchangeId exchange_id_ = 0;
    std::vector<Waiter> waiters_;
    bool exchange_started_ = false;
    bool completed_ = false;
};

DnsQueryService::DnsQueryService(runtime::AsioRuntime &runtime, DnsResolverConfig config)
    : runtime_(runtime), config_(std::move(config)),
      callback_gate_(std::make_shared<std::atomic_bool>(true)) {
    if (!config_.transport_factory) {
        config_.transport_factory = default_transport_factory();
    }
    const auto install_named_outbound_dialer = [this](DnsUpstreamConfig &upstream) {
        if (upstream.dial_policy.kind == DnsDialPolicyKind::named_outbound && !upstream.dialer &&
            config_.outbound_registry && !upstream.dial_policy.outbound_id.empty()) {
            upstream.dialer = make_outbound_dns_upstream_dialer(runtime_, config_.outbound_registry,
                                                                upstream.dial_policy.outbound_id);
        }
    };
    install_named_outbound_dialer(config_.default_upstream);
    for (auto &[name, upstream] : config_.upstream_groups) {
        install_named_outbound_dialer(upstream);
    }
    for (auto &[name, group] : config_.group_configs) {
        for (auto &upstream : group.members) {
            install_named_outbound_dialer(upstream);
        }
    }
    default_group_ = std::make_shared<DnsUpstreamGroup>(
        runtime_, DnsUpstreamGroupConfig{{config_.default_upstream}}, config_.transport_factory);
    for (const auto &[name, upstream_config] : config_.upstream_groups) {
        upstream_groups_.emplace(name, std::make_shared<DnsUpstreamGroup>(
                                           runtime_, DnsUpstreamGroupConfig{{upstream_config}},
                                           config_.transport_factory));
    }
    for (const auto &[name, group_config] : config_.group_configs) {
        upstream_groups_[name] =
            std::make_shared<DnsUpstreamGroup>(runtime_, group_config, config_.transport_factory);
    }
}

DnsQueryService::~DnsQueryService() { stop(); }

core::Status DnsQueryService::validate() const {
    if (config_.dependency_graph) {
        if (const auto result = config_.dependency_graph->validate(); !result) {
            return result;
        }
    }

    const auto validate_upstream = [this](const DnsUpstreamConfig &upstream,
                                          std::string_view name) -> core::Status {
        if (upstream.endpoint.address().is_unspecified() || upstream.endpoint.port() == 0) {
            return core::fail({core::ErrorCode::configuration,
                               "DNS upstream has an invalid endpoint: " + std::string(name)});
        }
        if (upstream.timeout.count() <= 0) {
            return core::fail({core::ErrorCode::configuration,
                               "DNS upstream has a non-positive timeout: " + std::string(name)});
        }
        if (upstream.mode != DnsTransportMode::plain && upstream.mode != DnsTransportMode::dot &&
            upstream.mode != DnsTransportMode::doh2 && upstream.mode != DnsTransportMode::doq &&
            upstream.mode != DnsTransportMode::doh3) {
            return core::fail({core::ErrorCode::configuration,
                               "DNS upstream has an invalid transport mode: " + std::string(name)});
        }
        if (upstream.dial_policy.kind != DnsDialPolicyKind::direct &&
            upstream.dial_policy.kind != DnsDialPolicyKind::named_outbound &&
            upstream.dial_policy.kind != DnsDialPolicyKind::traffic_rules) {
            return core::fail({core::ErrorCode::configuration,
                               "DNS upstream has an invalid dial policy: " + std::string(name)});
        }
        if (upstream.dial_policy.kind == DnsDialPolicyKind::named_outbound &&
            upstream.dial_policy.outbound_id.empty()) {
            return core::fail({core::ErrorCode::configuration,
                               "named DNS outbound requires an outbound ID: " + std::string(name)});
        }
        if (upstream.dial_policy.kind == DnsDialPolicyKind::named_outbound &&
            config_.outbound_registry) {
            const auto ids = config_.outbound_registry->ids();
            if (std::find(ids.begin(), ids.end(), upstream.dial_policy.outbound_id) == ids.end()) {
                return core::fail({core::ErrorCode::configuration,
                                   "DNS upstream references an unknown outbound: " +
                                       upstream.dial_policy.outbound_id});
            }
        }
        if (upstream.tcp_endpoint && upstream.tcp_endpoint->port() == 0) {
            return core::fail({core::ErrorCode::configuration,
                               "DNS upstream has an invalid TCP endpoint: " + std::string(name)});
        }
        if (upstream.fallback_endpoint && (upstream.fallback_endpoint->address().is_unspecified() ||
                                           upstream.fallback_endpoint->port() == 0)) {
            return core::fail(
                {core::ErrorCode::configuration,
                 "DNS upstream has an invalid fallback endpoint: " + std::string(name)});
        }
        if (upstream.fallback_tcp_endpoint && upstream.fallback_tcp_endpoint->port() == 0) {
            return core::fail(
                {core::ErrorCode::configuration,
                 "DNS upstream has an invalid fallback TCP endpoint: " + std::string(name)});
        }
        if (upstream.mode == DnsTransportMode::doh2 &&
            (upstream.doh_path.empty() || upstream.doh_path.front() != '/')) {
            return core::fail({core::ErrorCode::configuration,
                               "DoH2 path must be an absolute path: " + std::string(name)});
        }
        if (upstream.mode == DnsTransportMode::doh3 &&
            (upstream.doh_path.empty() || upstream.doh_path.front() != '/')) {
            return core::fail({core::ErrorCode::configuration,
                               "DoH3 path must be an absolute path: " + std::string(name)});
        }
        if (upstream.dial_policy.kind != DnsDialPolicyKind::direct && !upstream.dialer) {
            return core::fail({core::ErrorCode::configuration,
                               "DNS upstream dial policy requires a dialer: " + std::string(name)});
        }
        return {};
    };

    if (const auto result = validate_upstream(config_.default_upstream, "$default"); !result) {
        return result;
    }
    for (const auto &[name, upstream] : config_.upstream_groups) {
        if (name.empty()) {
            return core::fail(
                {core::ErrorCode::configuration, "DNS upstream group name is required"});
        }
        if (const auto result = validate_upstream(upstream, name); !result) {
            return result;
        }
    }
    for (const auto &[name, group] : config_.group_configs) {
        if (name.empty()) {
            return core::fail(
                {core::ErrorCode::configuration, "DNS upstream group name is required"});
        }
        if (group.members.empty()) {
            return core::fail({core::ErrorCode::configuration,
                               "DNS upstream group has no configured members: " + name});
        }
        if (group.selection != DnsUpstreamSelection::sequential &&
            group.selection != DnsUpstreamSelection::round_robin) {
            return core::fail({core::ErrorCode::configuration,
                               "DNS upstream group has an invalid selection: " + name});
        }
        for (const auto &member : group.members) {
            if (const auto result = validate_upstream(member, name); !result) {
                return result;
            }
        }
    }

    if (!config_.policy_router) {
        return {};
    }
    const auto validate_group = [this](std::string_view group) -> core::Status {
        if (is_builtin_default_group(group) || upstream_groups_.contains(std::string(group))) {
            return {};
        }
        return core::fail({core::ErrorCode::configuration,
                           "DNS policy selects missing upstream group: " + std::string(group)});
    };
    if (const auto result = validate_group(config_.policy_router->default_upstream()); !result) {
        return result;
    }
    for (const auto &rule : config_.policy_router->rules()) {
        if (rule.value.empty()) {
            return core::fail(
                {core::ErrorCode::configuration, "DNS policy rule value is required: " + rule.id});
        }
        if (rule.kind != DnsPolicyRuleKind::exact && rule.kind != DnsPolicyRuleKind::suffix &&
            rule.kind != DnsPolicyRuleKind::keyword) {
            return core::fail({core::ErrorCode::configuration,
                               "DNS policy rule has an invalid match kind: " + rule.id});
        }
        if (rule.upstream_group.empty()) {
            return core::fail({core::ErrorCode::configuration,
                               "DNS policy rule selects an empty upstream group"});
        }
        if (const auto result = validate_group(rule.upstream_group); !result) {
            return result;
        }
    }
    return {};
}

namespace {

void post_completion(runtime::AsioRuntime &runtime, DnsQueryService::Handler handler,
                     DnsQueryService::CompletionScheduler completion_scheduler,
                     core::Result<DnsPacket> result) {
    if (completion_scheduler) {
        completion_scheduler->post(
            [handler = std::move(handler), result = std::move(result)]() mutable {
                handler(std::move(result));
            });
        return;
    }
    boost::asio::post(runtime.context(),
                      [handler = std::move(handler), result = std::move(result)]() mutable {
                          handler(std::move(result));
                      });
}

void post_packet(runtime::AsioRuntime &runtime, DnsQueryService::Handler handler,
                 DnsQueryService::CompletionScheduler completion_scheduler, DnsPacket packet,
                 std::uint16_t response_id) {
    const auto wire = DnsMessageCodec::rewrite_id(packet, response_id);
    if (!wire) {
        post_completion(runtime, std::move(handler), std::move(completion_scheduler),
                        core::fail(wire.error()));
        return;
    }
    packet.wire = wire.value();
    packet.id = response_id;
    post_completion(runtime, std::move(handler), std::move(completion_scheduler),
                    std::move(packet));
}

} // namespace

DnsQueryService::RequestId DnsQueryService::query(DnsPacket packet, Handler handler,
                                                  CompletionScheduler completion_scheduler) {
    const auto request_id = next_request_id_.fetch_add(1, std::memory_order_relaxed);
    if (!runtime_.running()) {
        query_on_owner(request_id, std::move(packet), std::move(handler),
                       std::move(completion_scheduler));
        return request_id;
    }

    const auto gate = callback_gate_;
    boost::asio::post(
        runtime_.context(),
        [this, gate, request_id, packet = std::move(packet), handler = std::move(handler),
         completion_scheduler = std::move(completion_scheduler)]() mutable {
            if (!gate->load(std::memory_order_acquire)) {
                post_completion(runtime_, std::move(handler), std::move(completion_scheduler),
                                core::fail(cancelled_error()));
                return;
            }
            query_on_owner(request_id, std::move(packet), std::move(handler),
                           std::move(completion_scheduler));
        });
    return request_id;
}

void DnsQueryService::query_on_owner(RequestId request_id, DnsPacket packet, Handler handler,
                                     CompletionScheduler completion_scheduler) {
    if (stopped_.load(std::memory_order_acquire)) {
        post_completion(runtime_, std::move(handler), std::move(completion_scheduler),
                        core::fail(cancelled_error()));
        return;
    }
    if (packet.response() || packet.questions.size() != 1 || packet.wire.size() < 12) {
        post_completion(runtime_, std::move(handler), std::move(completion_scheduler),
                        core::fail(invalid_query_error("DNS query must contain one question")));
        return;
    }

    auto question = packet.questions.front();
    question.name = normalize_name(question.name);
    packet.questions.front() = question;
    spdlog::debug("Querying DNS packet for {}", question.name);

    std::shared_ptr<DnsUpstreamGroup> upstream = default_group_;
    std::string upstream_group = "$default";
    if (config_.policy_router) {
        const auto decision = config_.policy_router->select(question.name);
        if (const auto selected = upstream_groups_.find(decision.upstream_group);
            selected != upstream_groups_.end()) {
            upstream = selected->second;
            upstream_group = decision.upstream_group;
        } else if (!is_builtin_default_group(decision.upstream_group)) {
            post_completion(runtime_, std::move(handler), std::move(completion_scheduler),
                            core::fail({core::ErrorCode::configuration,
                                        "DNS policy selected unknown upstream group: " +
                                            decision.upstream_group}));
            return;
        }
    }

    const auto key = cache_key(question, upstream_group, config_.cache_generation);
    const auto now = std::chrono::steady_clock::now();
    if (const auto cached = cache_.find(key); cached != cache_.end()) {
        if (cached->second.expires > now) {
            cache_lru_.splice(cache_lru_.begin(), cache_lru_, cached->second.lru_position);
            post_packet(runtime_, std::move(handler), std::move(completion_scheduler),
                        cached->second.packet, packet.id);
            return;
        }
        cache_lru_.erase(cached->second.lru_position);
        cache_.erase(cached);
        cache_size_.store(cache_.size(), std::memory_order_release);
    }

    if (const auto existing = in_flight_.find(key); existing != in_flight_.end()) {
        existing->second->add_waiter(request_id, packet.id, std::move(handler),
                                     std::move(completion_scheduler));
        requests_[request_id] = existing->second;
        return;
    }

    auto operation =
        std::make_shared<Operation>(*this, key, std::move(packet), std::move(upstream));
    operation->add_waiter(request_id, operation->packet_id(), std::move(handler),
                          std::move(completion_scheduler));
    in_flight_.emplace(key, operation);
    requests_[request_id] = operation;
    operation->start();
}

void DnsQueryService::cancel(RequestId request_id) noexcept {
    if (!runtime_.running()) {
        cancel_on_owner(request_id);
        return;
    }
    const auto gate = callback_gate_;
    boost::asio::post(runtime_.context(), [this, gate, request_id] {
        if (gate->load(std::memory_order_acquire)) {
            cancel_on_owner(request_id);
        }
    });
}

void DnsQueryService::cancel_on_owner(RequestId request_id) noexcept {
    const auto request = requests_.find(request_id);
    if (request == requests_.end()) {
        return;
    }
    auto operation = request->second.lock();
    requests_.erase(request);
    if (!operation) {
        return;
    }
    const auto waiter = operation->remove_waiter(request_id);
    if (!waiter) {
        return;
    }
    post_completion(runtime_, std::move(waiter->handler), std::move(waiter->completion_scheduler),
                    core::fail(cancelled_error()));
    if (!operation->has_waiters()) {
        operation->cancel_shared();
    }
}

void DnsQueryService::stop() noexcept {
    if (stopped_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    callback_gate_->store(false, std::memory_order_release);
    if (!runtime_.running()) {
        stop_on_owner();
        return;
    }

    std::binary_semaphore completed(0);
    boost::asio::dispatch(runtime_.context(), [this, &completed] {
        stop_on_owner();
        completed.release();
    });
    completed.acquire();
}

void DnsQueryService::stop_on_owner() noexcept {
    while (!in_flight_.empty()) {
        in_flight_.begin()->second->cancel_shared();
    }
    in_flight_.clear();
    requests_.clear();
    if (default_group_) {
        default_group_->stop();
    }
    for (const auto &[name, upstream] : upstream_groups_) {
        upstream->stop();
    }
}

void DnsQueryService::clear_cache() noexcept {
    if (!runtime_.running()) {
        cache_.clear();
        cache_lru_.clear();
        cache_size_.store(0, std::memory_order_release);
        return;
    }
    const auto gate = callback_gate_;
    boost::asio::post(runtime_.context(), [this, gate] {
        if (!gate->load(std::memory_order_acquire)) {
            return;
        }
        cache_.clear();
        cache_lru_.clear();
        cache_size_.store(0, std::memory_order_release);
    });
}

std::size_t DnsQueryService::cache_size() const noexcept {
    return cache_size_.load(std::memory_order_acquire);
}

void DnsQueryService::complete(const std::shared_ptr<Operation> &operation,
                               core::Result<DnsPacket> result) {
    const auto in_flight = in_flight_.find(operation->key());
    if (in_flight != in_flight_.end() && in_flight->second == operation) {
        in_flight_.erase(in_flight);
    }

    if (result) {
        if (const auto ttl = cache_ttl(result.value(), config_.negative_cache_ttl)) {
            if (config_.cache_capacity > 0) {
                if (const auto existing = cache_.find(operation->key()); existing != cache_.end()) {
                    cache_lru_.erase(existing->second.lru_position);
                    cache_.erase(existing);
                }
                while (cache_.size() >= config_.cache_capacity && !cache_lru_.empty()) {
                    cache_.erase(cache_lru_.back());
                    cache_lru_.pop_back();
                }
                cache_lru_.push_front(operation->key());
                cache_.emplace(operation->key(),
                               CacheEntry{result.value(), std::chrono::steady_clock::now() + *ttl,
                                          cache_lru_.begin()});
                cache_size_.store(cache_.size(), std::memory_order_release);
            }
        }
    }
    if (!result) {
        spdlog::warn("DNS query completed with an error: {}", result.error().context);
    }

    auto waiters = operation->take_waiters();
    for (const auto &waiter : waiters) {
        requests_.erase(waiter.id);
    }
    for (auto &waiter : waiters) {
        if (!result) {
            post_completion(runtime_, std::move(waiter.handler),
                            std::move(waiter.completion_scheduler), result);
            continue;
        }
        post_packet(runtime_, std::move(waiter.handler), std::move(waiter.completion_scheduler),
                    result.value(), waiter.response_id);
    }
}

} // namespace clash_native::dns
