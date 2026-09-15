#include <clash_native/dns/system_resolver.hpp>

#include <algorithm>
#include <system_error>
#include <utility>

namespace clash_native::dns {

namespace {

core::Error resolution_error(const std::string &name, const boost::system::error_code &error) {
    return {core::ErrorCode::resolution, "system resolver failed for " + name,
            std::error_code(error.value(), std::system_category())};
}

} // namespace

SystemResolver::SystemResolver(boost::asio::io_context &context) : resolver_(context) {}

void SystemResolver::resolve(std::string name, Handler handler) {
    const auto query = name;
    resolver_.async_resolve(
        query, "0",
        [name = std::move(name), handler = std::move(handler)](
            const boost::system::error_code &error,
            const boost::asio::ip::tcp::resolver::results_type &results) mutable {
            if (error) {
                handler(core::fail(resolution_error(name, error)));
                return;
            }

            std::vector<boost::asio::ip::address> addresses;
            for (const auto &entry : results) {
                if (std::find(addresses.begin(), addresses.end(), entry.endpoint().address()) ==
                    addresses.end()) {
                    addresses.push_back(entry.endpoint().address());
                }
            }
            handler(std::move(addresses));
        });
}

void SystemResolver::cancel() noexcept { resolver_.cancel(); }

} // namespace clash_native::dns
