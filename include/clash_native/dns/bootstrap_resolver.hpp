#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/address.hpp>

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

} // namespace clash_native::dns
