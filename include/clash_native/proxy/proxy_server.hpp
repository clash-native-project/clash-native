#pragma once

#include <clash_native/core/metadata.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/outbound/builtin_outbound.hpp>
#include <clash_native/router/traffic_router.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <set>

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
    core::Status start();
    void stop() noexcept;
    bool running() const noexcept;
    boost::asio::ip::tcp::endpoint endpoint() const noexcept;

  private:
    class Session;
    using SessionPtr = std::shared_ptr<Session>;

    void accept();
    void open_stream(core::ConnectionMetadata metadata, core::StreamOpenHandler handler);
    void route_stream(router::TrafficRouter::Snapshot snapshot, core::ConnectionMetadata metadata,
                      router::RoutingContext context, std::size_t start,
                      core::StreamOpenHandler handler);
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
    std::shared_ptr<dns::ResolverService> resolver_;
};

} // namespace clash_native::proxy
