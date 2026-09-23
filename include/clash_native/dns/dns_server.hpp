#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_query_service.hpp>
#include <clash_native/dns/fake_ip_store.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/net/udp_stream.hpp>
#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/runtime/runtime_snapshot.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace clash_native::dns {

class DnsServer final {
  public:
    DnsServer(
        runtime::AsioRuntime &runtime, ResolverService &resolver,
        boost::asio::ip::udp::endpoint udp_endpoint = {boost::asio::ip::address_v4::loopback(), 0},
        boost::asio::ip::tcp::endpoint tcp_endpoint = {boost::asio::ip::address_v4::loopback(), 0});
    DnsServer(
        runtime::AsioRuntime &runtime, DnsQueryService &query_service,
        boost::asio::ip::udp::endpoint udp_endpoint = {boost::asio::ip::address_v4::loopback(), 0},
        boost::asio::ip::tcp::endpoint tcp_endpoint = {boost::asio::ip::address_v4::loopback(), 0});
    DnsServer(
        runtime::AsioRuntime &runtime,
        std::shared_ptr<runtime::RuntimeSnapshotStore> snapshot_store,
        boost::asio::ip::udp::endpoint udp_endpoint = {boost::asio::ip::address_v4::loopback(), 0},
        boost::asio::ip::tcp::endpoint tcp_endpoint = {boost::asio::ip::address_v4::loopback(), 0});
    ~DnsServer();

    DnsServer(const DnsServer &) = delete;
    DnsServer &operator=(const DnsServer &) = delete;

    core::Status start();
    void stop() noexcept;
    void set_fake_ip_store(std::shared_ptr<FakeIpStore> store,
                           std::function<bool(std::string_view)> filter = {});
    bool running() const noexcept;
    boost::asio::ip::udp::endpoint udp_endpoint() const noexcept;
    boost::asio::ip::tcp::endpoint tcp_endpoint() const noexcept;

  private:
    void receive_udp();
    void send_udp_response(boost::asio::ip::udp::endpoint recipient,
                           std::shared_ptr<std::vector<std::uint8_t>> payload);
    void accept_tcp();
    void read_tcp_query(std::shared_ptr<boost::asio::ip::tcp::socket> socket);
    void close_tcp_socket(const std::shared_ptr<boost::asio::ip::tcp::socket> &socket) noexcept;
    void resolve_udp(DnsPacket query, boost::asio::ip::udp::endpoint sender);
    void resolve_tcp(std::shared_ptr<boost::asio::ip::tcp::socket> socket, DnsPacket query);
    runtime::RuntimeSnapshotPtr current_snapshot() const noexcept;
    struct PendingQuery {
        std::shared_ptr<ResolverService> resolver;
        DnsQueryService *query_service = nullptr;
        DnsQueryService::RequestId request_id = 0;
    };
    void stop_on_owner() noexcept;

    runtime::AsioRuntime &runtime_;
    DnsQueryService *query_service_ = nullptr;
    std::shared_ptr<ResolverService> resolver_owner_;
    std::shared_ptr<runtime::RuntimeSnapshotStore> snapshot_store_;
    net::UdpStream udp_socket_;
    boost::asio::ip::tcp::acceptor tcp_acceptor_;
    boost::asio::ip::udp::endpoint udp_endpoint_;
    boost::asio::ip::tcp::endpoint tcp_endpoint_;
    std::array<std::uint8_t, 65535> udp_buffer_{};
    std::atomic_bool running_{false};
    std::shared_ptr<std::atomic_bool> callback_gate_;
    std::unordered_map<std::uint64_t, PendingQuery> query_requests_;
    std::uint64_t next_query_request_id_ = 1;
    std::unordered_set<std::shared_ptr<boost::asio::ip::tcp::socket>> tcp_sockets_;
    std::shared_ptr<FakeIpStore> fake_ip_store_;
    std::function<bool(std::string_view)> fake_ip_filter_;
};

} // namespace clash_native::dns
