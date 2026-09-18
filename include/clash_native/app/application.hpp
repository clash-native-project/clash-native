#pragma once

#include <clash_native/dns/dns_query_service.hpp>
#include <clash_native/dns/dns_server.hpp>
#include <clash_native/dns/fake_ip_store.hpp>
#include <clash_native/outbound/outbound_registry.hpp>
#include <clash_native/proxy/proxy_server.hpp>
#include <clash_native/router/traffic_router.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace clash_native::app {

struct ApplicationOptions {
    std::optional<boost::asio::ip::tcp::endpoint> listen_endpoint;
    std::optional<dns::DnsResolverConfig> dns_config;
    std::optional<boost::asio::ip::udp::endpoint> dns_udp_endpoint;
    std::optional<boost::asio::ip::tcp::endpoint> dns_tcp_endpoint;
    std::shared_ptr<dns::FakeIpStore> fake_ip_store;
    std::function<bool(std::string_view)> fake_ip_filter;
    router::RouteAction default_route_action = router::RouteAction::direct();
    std::vector<router::TrafficRule> route_rules;
    std::shared_ptr<outbound::OutboundRegistry> outbound_registry;
};

class Application {
  public:
    Application();

    int run(const ApplicationOptions &options = {});
    core::Status reload(runtime::RuntimeSnapshotPtr snapshot);

  private:
    runtime::AsioRuntime runtime_;
    proxy::ProxyServer proxy_server_;
    std::shared_ptr<dns::ResolverService> resolver_;
    std::unique_ptr<dns::DnsServer> dns_server_;
};

} // namespace clash_native::app
