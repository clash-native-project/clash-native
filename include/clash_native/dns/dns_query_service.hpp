#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_policy_router.hpp>
#include <clash_native/dns/dns_upstream.hpp>
#include <clash_native/dns/resolver_graph.hpp>
#include <clash_native/outbound/outbound_registry.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace clash_native::dns {

struct DnsResolverConfig {
    DnsResolverConfig(DnsUpstreamConfig default_upstream,
                      std::unordered_map<std::string, DnsUpstreamConfig> upstream_groups = {},
                      std::shared_ptr<const DnsPolicyRouter> policy_router = nullptr,
                      DnsTransportFactory transport_factory = {},
                      std::unordered_map<std::string, DnsUpstreamGroupConfig> group_configs = {},
                      std::size_t cache_capacity = 4096,
                      std::chrono::seconds negative_cache_ttl = std::chrono::seconds(5),
                      std::uint64_t cache_generation = 0,
                      std::shared_ptr<const ResolverDependencyGraph> dependency_graph = nullptr,
                      outbound::OutboundRegistry::Snapshot outbound_registry = nullptr)
        : default_upstream(std::move(default_upstream)),
          upstream_groups(std::move(upstream_groups)), policy_router(std::move(policy_router)),
          transport_factory(std::move(transport_factory)), group_configs(std::move(group_configs)),
          dependency_graph(std::move(dependency_graph)),
          outbound_registry(std::move(outbound_registry)) {
        this->cache_capacity = cache_capacity;
        this->negative_cache_ttl = negative_cache_ttl;
        this->cache_generation = cache_generation;
    }

    DnsUpstreamConfig default_upstream;
    std::unordered_map<std::string, DnsUpstreamConfig> upstream_groups;
    std::shared_ptr<const DnsPolicyRouter> policy_router;
    DnsTransportFactory transport_factory;
    std::unordered_map<std::string, DnsUpstreamGroupConfig> group_configs;
    std::size_t cache_capacity = 4096;
    std::chrono::seconds negative_cache_ttl = std::chrono::seconds(5);
    std::uint64_t cache_generation = 0;
    std::shared_ptr<const ResolverDependencyGraph> dependency_graph;
    outbound::OutboundRegistry::Snapshot outbound_registry;
};

class DnsQueryService final {
  public:
    using RequestId = std::uint64_t;
    using Handler = std::function<void(core::Result<DnsPacket>)>;
    using CompletionScheduler = std::optional<runtime::AsioScheduler>;

    DnsQueryService(runtime::AsioRuntime &runtime, DnsResolverConfig config);
    ~DnsQueryService();

    DnsQueryService(const DnsQueryService &) = delete;
    DnsQueryService &operator=(const DnsQueryService &) = delete;

    RequestId query(DnsPacket packet, Handler handler,
                    CompletionScheduler completion_scheduler = std::nullopt);
    void cancel(RequestId request_id) noexcept;
    void stop() noexcept;
    void clear_cache() noexcept;
    std::size_t cache_size() const noexcept;
    core::Status validate() const;

  private:
    class Operation;
    struct CacheEntry {
        DnsPacket packet;
        std::chrono::steady_clock::time_point expires;
        std::list<std::string>::iterator lru_position;
    };

    void query_on_owner(RequestId request_id, DnsPacket packet, Handler handler,
                        CompletionScheduler completion_scheduler);
    void cancel_on_owner(RequestId request_id) noexcept;
    void stop_on_owner() noexcept;
    void complete(const std::shared_ptr<Operation> &operation, core::Result<DnsPacket> result);

    runtime::AsioRuntime &runtime_;
    DnsResolverConfig config_;
    std::shared_ptr<DnsUpstreamGroup> default_group_;
    std::unordered_map<std::string, std::shared_ptr<DnsUpstreamGroup>> upstream_groups_;
    std::unordered_map<std::string, CacheEntry> cache_;
    std::list<std::string> cache_lru_;
    std::unordered_map<std::string, std::shared_ptr<Operation>> in_flight_;
    std::unordered_map<RequestId, std::weak_ptr<Operation>> requests_;
    std::shared_ptr<std::atomic_bool> callback_gate_;
    std::atomic<RequestId> next_request_id_{1};
    std::atomic_bool stopped_{false};
    std::atomic<std::size_t> cache_size_{0};
};

} // namespace clash_native::dns
