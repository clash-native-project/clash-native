#pragma once

#include <clash_native/dns/dns_transport.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace clash_native::dns {

using DnsTransportFactory =
    std::function<std::shared_ptr<DnsTransport>(runtime::AsioRuntime &, DnsUpstreamConfig)>;

class DnsUpstream final : public std::enable_shared_from_this<DnsUpstream> {
  public:
    DnsUpstream(runtime::AsioRuntime &runtime, DnsUpstreamConfig config,
                DnsTransportFactory transport_factory);
    ~DnsUpstream();

    DnsUpstream(const DnsUpstream &) = delete;
    DnsUpstream &operator=(const DnsUpstream &) = delete;

    io::AnySender<DnsExchangeResult> exchange(DnsPacket query,
                                              std::chrono::steady_clock::time_point deadline);
    std::chrono::milliseconds timeout() const noexcept;
    void stop() noexcept;

  private:
    runtime::AsioRuntime &runtime_;
    std::chrono::milliseconds timeout_;
    std::shared_ptr<DnsTransport> transport_;
};

enum class DnsUpstreamSelection {
    sequential,
    round_robin,
};

struct DnsUpstreamGroupConfig {
    std::vector<DnsUpstreamConfig> members;
    DnsUpstreamSelection selection = DnsUpstreamSelection::sequential;
    std::chrono::milliseconds timeout{};
};

class DnsUpstreamGroup final : public std::enable_shared_from_this<DnsUpstreamGroup> {
  public:
    DnsUpstreamGroup(runtime::AsioRuntime &runtime, DnsUpstreamGroupConfig config,
                     DnsTransportFactory transport_factory);
    ~DnsUpstreamGroup();

    DnsUpstreamGroup(const DnsUpstreamGroup &) = delete;
    DnsUpstreamGroup &operator=(const DnsUpstreamGroup &) = delete;

    io::AnySender<DnsExchangeResult> exchange(DnsPacket query,
                                              std::chrono::steady_clock::time_point deadline);
    std::chrono::milliseconds timeout() const noexcept;
    void stop() noexcept;

  private:
    class Operation;

    void forget(Operation *operation) noexcept;
    std::size_t next_start_index() noexcept;
    std::optional<std::size_t> select_member(std::size_t start_index,
                                             const std::vector<bool> &attempted) const;
    void record_failure(std::size_t member_index, const core::Error &error);
    void record_success(std::size_t member_index) noexcept;

    struct MemberHealth {
        std::size_t consecutive_failures = 0;
        std::chrono::steady_clock::time_point unhealthy_until{};
    };

    runtime::AsioRuntime &runtime_;
    DnsUpstreamSelection selection_;
    std::chrono::milliseconds timeout_;
    std::vector<std::shared_ptr<DnsUpstream>> members_;
    std::vector<MemberHealth> member_health_;
    std::unordered_set<std::shared_ptr<Operation>> operations_;
    std::atomic<std::size_t> next_member_{0};
    bool stopped_ = false;

    friend class Operation;
};

} // namespace clash_native::dns
