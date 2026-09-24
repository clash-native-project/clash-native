#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_types.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/outbound/outbound_registry.hpp>
#include <clash_native/router/traffic_router.hpp>
#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/transport/endpoint_dialer.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace clash_native::dns {

class BootstrapResolver;

enum class DnsDialPolicyKind {
    direct,
    named_outbound,
    traffic_rules,
};

struct DnsDialPolicy {
    DnsDialPolicyKind kind = DnsDialPolicyKind::direct;
    std::string outbound_id;
};

class DnsUpstreamDialer {
  public:
    virtual io::AnySender<core::StreamOpenResult> connect_stream(core::StreamRequest request) = 0;
    virtual io::AnySender<core::DatagramOpenResult> open_datagram(core::DatagramRequest request) {
        return io::AnySender<core::DatagramOpenResult>{
            stdexec::just(core::DatagramOpenResult::unsupported())};
    }
    virtual ~DnsUpstreamDialer() = default;
};

class OutboundDnsUpstreamDialer final : public DnsUpstreamDialer {
  public:
    OutboundDnsUpstreamDialer(runtime::AsioRuntime &runtime,
                              outbound::OutboundRegistry::Snapshot registry,
                              std::string outbound_id,
                              transport::EndpointDialRequirements requirements = {});

    io::AnySender<core::StreamOpenResult> connect_stream(core::StreamRequest request) override;
    io::AnySender<core::DatagramOpenResult> open_datagram(core::DatagramRequest request) override;

  private:
    runtime::AsioRuntime &runtime_;
    std::shared_ptr<transport::EndpointDialer> endpoint_dialer_;
    std::optional<core::Error> plan_error_;
};

enum class DnsTransportMode {
    plain,
    dot,
    doh1,
    doh2,
    doq,
    doh3,
};

struct DnsUpstreamConfig {
    boost::asio::ip::udp::endpoint endpoint;
    std::chrono::milliseconds timeout = std::chrono::seconds(2);
    std::optional<boost::asio::ip::tcp::endpoint> tcp_endpoint;
    bool prefer_tcp = false;
    // These fields are retained for legacy construction and expanded by DnsUpstreamGroup.
    std::optional<boost::asio::ip::udp::endpoint> fallback_endpoint;
    std::optional<boost::asio::ip::tcp::endpoint> fallback_tcp_endpoint;
    DnsTransportMode mode = DnsTransportMode::plain;
    std::string server_name;
    bool verify_peer = true;
    std::string doh_path = "/dns-query";
    std::string doh_authority;
    DnsDialPolicy dial_policy;
    std::shared_ptr<DnsUpstreamDialer> dialer;
    // Retained for DNS egress routing when a bootstrap address is used.
    std::string egress_hostname;
    // When set, the endpoint address is resolved by the explicit bootstrap resolver.
    std::string hostname;
    // Literal DNS servers tried before the built-in bootstrap servers.
    std::vector<boost::asio::ip::udp::endpoint> bootstrap_dns_servers;
    std::shared_ptr<BootstrapResolver> bootstrap_resolver;
};

struct DnsExchangeRequest {
    DnsPacket query;
    std::chrono::steady_clock::time_point deadline;
};

// Internal exchange key for transports that multiplex queries over a
// shared carrier. Not part of the public contract: dropping the
// exchange sender aborts exactly that query.
using DnsExchangeId = std::uint64_t;

using DnsExchangeResult = core::Result<DnsPacket>;

class DnsTransport {
  public:
    virtual io::AnySender<DnsExchangeResult> exchange(DnsExchangeRequest request) = 0;
    virtual void stop() noexcept = 0;
    virtual ~DnsTransport() = default;
};

std::shared_ptr<DnsUpstreamDialer> make_direct_dns_upstream_dialer(runtime::AsioRuntime &runtime);
std::shared_ptr<DnsUpstreamDialer> make_outbound_dns_upstream_dialer(
    runtime::AsioRuntime &runtime, outbound::OutboundRegistry::Snapshot registry,
    std::string outbound_id, transport::EndpointDialRequirements requirements = {});
std::shared_ptr<DnsUpstreamDialer> make_traffic_rules_dns_upstream_dialer(
    runtime::AsioRuntime &runtime, outbound::OutboundRegistry::Snapshot registry,
    router::TrafficRouter::Snapshot traffic_router, std::string egress_hostname);

std::shared_ptr<DnsTransport> make_asio_dns_transport(runtime::AsioRuntime &runtime,
                                                      DnsUpstreamConfig config);

} // namespace clash_native::dns
