#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_types.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

namespace clash_native::dns {

struct DnsUpstreamConfig {
    boost::asio::ip::udp::endpoint endpoint;
    std::chrono::milliseconds timeout = std::chrono::seconds(2);
    std::optional<boost::asio::ip::tcp::endpoint> tcp_endpoint;
    bool prefer_tcp = false;
};

class ResolverService final {
  public:
    using RequestId = std::uint64_t;
    using Handler = std::function<void(core::Result<DnsAnswer>)>;

    ResolverService(runtime::AsioRuntime &runtime, DnsUpstreamConfig config);
    ~ResolverService();

    ResolverService(const ResolverService &) = delete;
    ResolverService &operator=(const ResolverService &) = delete;

    RequestId resolve(DnsQuestion question, Handler handler);
    void cancel(RequestId request_id) noexcept;
    void stop() noexcept;
    void clear_cache() noexcept;
    std::size_t cache_size() const noexcept;

  private:
    class Operation;
    struct CacheEntry {
        DnsAnswer answer;
        std::chrono::steady_clock::time_point expires;
    };

    void complete(const std::shared_ptr<Operation> &operation, core::Result<DnsAnswer> result);

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    std::unordered_map<std::string, CacheEntry> cache_;
    std::unordered_map<std::string, std::shared_ptr<Operation>> in_flight_;
    std::unordered_map<RequestId, std::weak_ptr<Operation>> requests_;
    RequestId next_request_id_ = 1;
    std::uint16_t next_query_id_ = 1;
    bool stopped_ = false;
};

} // namespace clash_native::dns
