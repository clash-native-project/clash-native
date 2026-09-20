#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clash_native::dns {

class BootstrapResolver {
  public:
    using RequestId = std::uint64_t;
    using Handler = std::function<void(core::Result<std::vector<boost::asio::ip::address>>)>;

    virtual RequestId resolve(std::string hostname, std::chrono::steady_clock::time_point deadline,
                              Handler handler) = 0;
    virtual void cancel(RequestId request_id) noexcept = 0;
    virtual void stop() noexcept = 0;
    virtual ~BootstrapResolver() = default;
};

std::shared_ptr<BootstrapResolver> make_system_bootstrap_resolver(runtime::AsioRuntime &runtime);

// Returns the built-in IPv4 DNS servers used to bootstrap hostname-based
// encrypted DNS upstreams. The order is part of the fallback policy.
std::vector<boost::asio::ip::udp::endpoint> default_bootstrap_dns_servers();

// Creates a bootstrap resolver that tries configured literal DNS servers,
// then the built-in servers, and finally the system resolver.
std::shared_ptr<BootstrapResolver>
make_bootstrap_resolver(runtime::AsioRuntime &runtime,
                        std::vector<boost::asio::ip::udp::endpoint> configured_servers = {},
                        std::shared_ptr<BootstrapResolver> system_resolver = nullptr);

} // namespace clash_native::dns
