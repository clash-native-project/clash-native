#include <clash_native/dns/system_resolver.hpp>

#include <exec/asio/use_sender.hpp>
#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <algorithm>
#include <memory>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace clash_native::dns {

namespace {

core::Error resolution_error(const std::string &name, const boost::system::error_code &error) {
    return {core::ErrorCode::resolution, "system resolver failed for " + name,
            std::error_code(error.value(), std::system_category())};
}

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "system resolver was cancelled"};
}

using RequestId = std::uint64_t;

struct Request {
    SystemResolver::Handler handler;
};

} // namespace

struct SystemResolverState {
    std::unordered_map<RequestId, std::shared_ptr<Request>> requests;
    RequestId next_request_id = 1;
    exec::async_scope scope;
};

SystemResolver::SystemResolver(boost::asio::io_context &context)
    : resolver_(context), state_(std::make_shared<SystemResolverState>()) {}

// Straight-line resolve chain: the await races cancel() via first-wins map
// lookup in complete(). cancel() aborts the in-flight use_sender await
// (operation_aborted -> set_stopped), so the task ends promptly and its late
// terminal drops the same way. The task always ends with a value.
exec::task<void> run_system_lookup(std::shared_ptr<SystemResolverState> state,
                                   boost::asio::ip::tcp::resolver *resolver, RequestId request_id,
                                   std::string name) {
    try {
        auto results = co_await resolver->async_resolve(name, "0", exec::asio::use_sender);
        std::vector<boost::asio::ip::address> addresses;
        for (const auto &entry : results) {
            if (std::find(addresses.begin(), addresses.end(), entry.endpoint().address()) ==
                addresses.end()) {
                addresses.push_back(entry.endpoint().address());
            }
        }
        const auto found = state->requests.find(request_id);
        if (found == state->requests.end()) {
            co_return;
        }
        auto request = std::move(found->second);
        state->requests.erase(found);
        if (addresses.empty()) {
            request->handler(
                core::fail({core::ErrorCode::resolution, "system resolver returned no addresses"}));
        } else {
            request->handler(std::move(addresses));
        }
    } catch (const boost::system::system_error &failure) {
        const auto found = state->requests.find(request_id);
        if (found == state->requests.end()) {
            co_return;
        }
        auto request = std::move(found->second);
        state->requests.erase(found);
        request->handler(core::fail(resolution_error(name, failure.code())));
    } catch (...) {
        // Stop-cancelled awaits and late terminals land here after cancel()
        // already delivered the terminal; the map lookup above dropped them.
    }
    co_return;
}

void SystemResolver::resolve(std::string name, Handler handler) {
    const auto request_id = state_->next_request_id++;
    auto request = std::make_shared<Request>();
    request->handler = std::move(handler);
    state_->requests.emplace(request_id, std::move(request));
    // The scope only owns lookup tasks; teardown stays guard-driven
    // (cancel aborts the resolver), so no stop is ever requested.
    state_->scope.spawn(run_system_lookup(state_, &resolver_, request_id, std::move(name)));
}

void SystemResolver::cancel() noexcept {
    try {
        resolver_.cancel();
    } catch (...) {
    }
    std::vector<std::shared_ptr<Request>> pending;
    pending.reserve(state_->requests.size());
    for (auto &[request_id, request] : state_->requests) {
        (void)request_id;
        pending.push_back(std::move(request));
    }
    state_->requests.clear();
    for (auto &request : pending) {
        if (request->handler) {
            request->handler(core::fail(cancelled_error()));
        }
    }
}

} // namespace clash_native::dns
