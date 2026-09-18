#pragma once

#include <clash_native/core/metadata.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/dns/fake_ip_store.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/observability/connection_registry.hpp>
#include <clash_native/outbound/builtin_outbound.hpp>
#include <clash_native/outbound/outbound_registry.hpp>
#include <clash_native/router/traffic_router.hpp>
#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/runtime/runtime_snapshot.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <unordered_set>

namespace clash_native::proxy {

class ProxyServer {
  public:
    explicit ProxyServer(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint = {
                                                            boost::asio::ip::tcp::v4(), 1080});
    ~ProxyServer();

    ProxyServer(const ProxyServer &) = delete;
    ProxyServer &operator=(const ProxyServer &) = delete;

    void set_endpoint(boost::asio::ip::tcp::endpoint endpoint);
    void set_default_action(router::RouteAction action);
    void add_rule(router::TrafficRule rule);
    void set_resolver(std::shared_ptr<dns::ResolverService> resolver);
    void set_fake_ip_store(std::shared_ptr<dns::FakeIpStore> store);
    void set_outbound_registry(std::shared_ptr<outbound::OutboundRegistry> registry);
    void set_connection_registry(std::shared_ptr<observability::ConnectionRegistry> registry);
    core::Status reload(runtime::RuntimeSnapshotPtr snapshot);
    core::Status start();
    void stop() noexcept;
    bool running() const noexcept;
    boost::asio::ip::tcp::endpoint endpoint() const noexcept;

  private:
    class Session;
    using SessionPtr = std::shared_ptr<Session>;
    using DatagramRouteHandler =
        std::function<void(core::DatagramOpenResult, boost::asio::ip::udp::endpoint)>;

    void accept();
    void open_stream(core::ConnectionMetadata metadata,
                     std::optional<observability::ConnectionRegistry::ConnectionId> connection_id,
                     core::StreamOpenHandler handler);
    void route_stream(runtime::RuntimeSnapshotPtr snapshot, core::ConnectionMetadata metadata,
                      router::RoutingContext context, std::size_t start,
                      std::optional<observability::ConnectionRegistry::ConnectionId> connection_id,
                      core::StreamOpenHandler handler);
    void open_datagram(runtime::RuntimeSnapshotPtr snapshot, core::ConnectionMetadata metadata,
                       DatagramRouteHandler handler);
    void route_datagram(runtime::RuntimeSnapshotPtr snapshot, core::ConnectionMetadata metadata,
                        router::RoutingContext context, DatagramRouteHandler handler);
    void stop_on_owner() noexcept;
    void remove_session(const SessionPtr &session) noexcept;

    runtime::AsioRuntime &runtime_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ip::tcp::endpoint endpoint_;
    mutable std::mutex sessions_mutex_;
    std::set<SessionPtr> sessions_;
    std::atomic_bool running_{false};
    router::TrafficRouter router_;
    std::shared_ptr<outbound::DirectOutbound> direct_outbound_;
    std::shared_ptr<outbound::RejectOutbound> reject_outbound_;
    std::shared_ptr<outbound::OutboundRegistry> outbound_registry_;
    std::shared_ptr<observability::ConnectionRegistry> connection_registry_;
    runtime::RuntimeSnapshotStore snapshot_store_;
    std::uint64_t next_snapshot_generation_ = 1;
    std::shared_ptr<dns::ResolverService> resolver_;
    std::shared_ptr<dns::FakeIpStore> fake_ip_store_;
    std::shared_ptr<std::atomic_bool> callback_gate_;
    std::unordered_set<dns::ResolverService::RequestId> resolver_requests_;
};

} // namespace clash_native::proxy
