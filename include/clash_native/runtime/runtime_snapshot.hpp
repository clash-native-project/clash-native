#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/dns/fake_ip_store.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/outbound/outbound_registry.hpp>
#include <clash_native/router/traffic_router.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>

namespace clash_native::runtime {

struct RuntimeSnapshot {
    std::uint64_t generation = 0;
    router::TrafficRouter::Snapshot router;
    outbound::OutboundRegistry::Snapshot outbounds;
    std::shared_ptr<dns::ResolverService> resolver;
    std::shared_ptr<dns::FakeIpStore> fake_ip_store;
    std::function<bool(std::string_view)> fake_ip_filter;

    core::Status validate() const {
        if (!router || !outbounds) {
            return core::fail({core::ErrorCode::configuration, "runtime snapshot is incomplete"});
        }
        if (const auto result = outbounds->validate(); !result) {
            return result;
        }
        if (resolver) {
            if (const auto result = resolver->validate(); !result) {
                return result;
            }
        }
        return router->validate(outbounds->ids());
    }
};

using RuntimeSnapshotPtr = std::shared_ptr<const RuntimeSnapshot>;

class RuntimeSnapshotStore final {
  public:
    RuntimeSnapshotPtr load() const noexcept { return current_.load(std::memory_order_acquire); }

    core::Status publish(RuntimeSnapshotPtr snapshot) {
        if (!snapshot) {
            return core::fail({core::ErrorCode::configuration, "runtime snapshot is required"});
        }
        if (const auto result = snapshot->validate(); !result) {
            return result;
        }

        auto current = current_.load(std::memory_order_acquire);
        while (true) {
            if (current && snapshot->generation <= current->generation) {
                return core::fail(
                    {core::ErrorCode::configuration, "runtime snapshot generation must increase"});
            }
            if (current_.compare_exchange_weak(current, snapshot, std::memory_order_release,
                                               std::memory_order_acquire)) {
                return {};
            }
        }
    }

  private:
    std::atomic<RuntimeSnapshotPtr> current_;
};

} // namespace clash_native::runtime
