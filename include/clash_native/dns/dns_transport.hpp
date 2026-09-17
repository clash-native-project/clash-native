#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_types.hpp>
#include <clash_native/outbound/outbound_registry.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

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
    using Handler = core::StreamOpenHandler;

    virtual void connect_stream(core::StreamRequest request, Handler handler) = 0;
    virtual void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) {
        handler(core::DatagramOpenResult::unsupported());
    }
    virtual ~DnsUpstreamDialer() = default;
};

class OutboundDnsUpstreamDialer final : public DnsUpstreamDialer {
  public:
    OutboundDnsUpstreamDialer(runtime::AsioRuntime &runtime,
                              outbound::OutboundRegistry::Snapshot registry,
                              std::string outbound_id);

    void connect_stream(core::StreamRequest request, Handler handler) override;
    void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) override;

  private:
    runtime::AsioRuntime &runtime_;
    outbound::OutboundRegistry::Snapshot registry_;
    std::string outbound_id_;
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
    // When set, the endpoint address is resolved by the explicit bootstrap resolver.
    std::string hostname;
    std::shared_ptr<BootstrapResolver> bootstrap_resolver;
};

struct DnsExchangeRequest {
    DnsPacket query;
    std::chrono::steady_clock::time_point deadline;
};

class DnsTransport {
  public:
    using ExchangeId = std::uint64_t;
    using Handler = std::function<void(core::Result<DnsPacket>)>;

    virtual ExchangeId exchange(DnsExchangeRequest request, Handler handler) = 0;
    virtual void cancel(ExchangeId exchange_id) noexcept = 0;
    virtual void stop() noexcept = 0;
    virtual ~DnsTransport() = default;
};

std::shared_ptr<DnsUpstreamDialer> make_direct_dns_upstream_dialer(runtime::AsioRuntime &runtime);
std::shared_ptr<DnsUpstreamDialer>
make_outbound_dns_upstream_dialer(runtime::AsioRuntime &runtime,
                                  outbound::OutboundRegistry::Snapshot registry,
                                  std::string outbound_id);

std::shared_ptr<DnsTransport> make_asio_dns_transport(runtime::AsioRuntime &runtime,
                                                      DnsUpstreamConfig config);

} // namespace clash_native::dns
