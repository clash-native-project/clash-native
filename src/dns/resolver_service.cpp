#include <clash_native/dns/resolver_service.hpp>

#include <utility>

namespace clash_native::dns {

ResolverService::ResolverService(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
    : ResolverService(runtime, DnsResolverConfig{std::move(config), {}, nullptr, {}}) {}

ResolverService::ResolverService(runtime::AsioRuntime &runtime, DnsResolverConfig config)
    : query_service_(runtime, std::move(config)), address_resolver_(query_service_) {}

ResolverService::~ResolverService() { stop(); }

ResolverService::RequestId ResolverService::resolve(DnsQuestion question, Handler handler,
                                                    CompletionScheduler completion_scheduler) {
    return address_resolver_.resolve(std::move(question), std::move(handler),
                                     std::move(completion_scheduler));
}

void ResolverService::cancel(RequestId request_id) noexcept {
    address_resolver_.cancel(request_id);
}

void ResolverService::stop() noexcept { query_service_.stop(); }

void ResolverService::clear_cache() noexcept { query_service_.clear_cache(); }

std::size_t ResolverService::cache_size() const noexcept { return query_service_.cache_size(); }

core::Status ResolverService::validate() const { return query_service_.validate(); }

DnsQueryService &ResolverService::query_service() noexcept { return query_service_; }

} // namespace clash_native::dns
