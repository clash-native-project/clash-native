#pragma once

#include <clash_native/dns/address_resolver.hpp>
#include <clash_native/dns/dns_query_service.hpp>

namespace clash_native::dns {

class ResolverService final {
  public:
    using RequestId = AddressResolver::RequestId;
    using Handler = AddressResolver::Handler;
    using CompletionScheduler = AddressResolver::CompletionScheduler;

    ResolverService(runtime::AsioRuntime &runtime, DnsUpstreamConfig config);
    ResolverService(runtime::AsioRuntime &runtime, DnsResolverConfig config);
    ~ResolverService();

    ResolverService(const ResolverService &) = delete;
    ResolverService &operator=(const ResolverService &) = delete;

    RequestId resolve(DnsQuestion question, Handler handler,
                      CompletionScheduler completion_scheduler = std::nullopt);
    void cancel(RequestId request_id) noexcept;
    void stop() noexcept;
    void clear_cache() noexcept;
    std::size_t cache_size() const noexcept;
    core::Status validate() const;
    DnsQueryService &query_service() noexcept;

  private:
    DnsQueryService query_service_;
    AddressResolver address_resolver_;
};

} // namespace clash_native::dns
