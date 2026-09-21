#include <clash_native/core/base64.hpp>
#include <clash_native/net/udp_stream.hpp>
#include <clash_native/proxy/proxy_server.hpp>
#include <clash_native/proxy/tcp_relay.hpp>
#include <clash_native/transport/exchange_session.hpp>

#include "outbound/outbound_utils.hpp"
#include "outbound/proxy_address.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <semaphore>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "http_proxy_utils.hpp"
#include "proxy_session.hpp"
#include "socks5_udp_listener.hpp"

namespace clash_native::proxy {

namespace {

core::Error listener_error(std::string_view operation, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, fmt::format("failed to {} proxy listener", operation),
            std::error_code(error.value(), std::system_category())};
}

} // namespace

ProxyServer::ProxyServer(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint)
    : runtime_(runtime), acceptor_(runtime.context()), endpoint_(endpoint), router_(),
      direct_outbound_(std::make_shared<outbound::DirectOutbound>(runtime)),
      reject_outbound_(std::make_shared<outbound::RejectOutbound>(runtime)),
      outbound_registry_(std::make_shared<outbound::OutboundRegistry>()),
      connection_registry_(std::make_shared<observability::ConnectionRegistry>()),
      snapshot_store_(std::make_shared<runtime::RuntimeSnapshotStore>()),
      callback_gate_(std::make_shared<std::atomic_bool>(false)) {
    if (!outbound_registry_->add_outbound("direct", direct_outbound_) ||
        !outbound_registry_->add_outbound("reject", reject_outbound_)) {
        throw std::logic_error("failed to initialize proxy built-in outbounds");
    }
}

ProxyServer::~ProxyServer() { stop(); }

void ProxyServer::set_endpoint(boost::asio::ip::tcp::endpoint endpoint) {
    if (running()) {
        throw std::logic_error("Cannot change a running proxy endpoint");
    }

    endpoint_ = endpoint;
}

void ProxyServer::set_inbound_mode(ProxyInboundMode mode) {
    if (running()) {
        throw std::logic_error("Cannot change the inbound mode on a running proxy");
    }
    inbound_mode_ = mode;
}

void ProxyServer::set_http_authentication(std::string username, std::string password) {
    if (running()) {
        throw std::logic_error("Cannot change HTTP authentication on a running proxy");
    }
    if (username.empty() != password.empty()) {
        throw std::invalid_argument("HTTP proxy username and password must be provided together");
    }
    if (!http_detail::has_valid_http_credentials(username, password)) {
        throw std::invalid_argument("HTTP proxy credentials contain invalid characters");
    }
    http_username_ = std::move(username);
    http_password_ = std::move(password);
}

void ProxyServer::set_socks5_users(std::vector<Socks5User> users) {
    if (running()) {
        throw std::logic_error("Cannot change SOCKS5 users on a running proxy");
    }
    std::unordered_set<std::string> names;
    for (const auto &user : users) {
        if (user.username.empty() || user.username.size() > 255 || user.password.size() > 255) {
            throw std::invalid_argument("SOCKS5 usernames and passwords must fit in one byte");
        }
        if (!http_detail::has_valid_http_credentials(user.username, user.password)) {
            throw std::invalid_argument("SOCKS5 credentials contain invalid characters");
        }
        if (!names.emplace(user.username).second) {
            throw std::invalid_argument("SOCKS5 usernames must be unique");
        }
    }
    socks5_users_ = std::move(users);
}

void ProxyServer::set_socks5_udp_endpoint(boost::asio::ip::udp::endpoint endpoint) {
    if (running()) {
        throw std::logic_error("Cannot change the SOCKS5 UDP endpoint on a running proxy");
    }
    socks5_udp_endpoint_ = endpoint;
}

void ProxyServer::clear_socks5_udp_endpoint() {
    if (running()) {
        throw std::logic_error("Cannot change the SOCKS5 UDP endpoint on a running proxy");
    }
    socks5_udp_endpoint_.reset();
}

void ProxyServer::set_tls_server_credentials(std::vector<std::uint8_t> certificate_pem,
                                             std::vector<std::uint8_t> private_key_pem) {
    if (running()) {
        throw std::logic_error("Cannot change TLS credentials on a running proxy");
    }
    if (certificate_pem.empty() != private_key_pem.empty()) {
        throw std::invalid_argument(
            "TLS server certificate and private key must be provided together");
    }
    tls_certificate_pem_ = std::move(certificate_pem);
    tls_private_key_pem_ = std::move(private_key_pem);
    tls_context_.reset();
}

void ProxyServer::clear_tls_server_credentials() {
    if (running()) {
        throw std::logic_error("Cannot change TLS credentials on a running proxy");
    }
    tls_certificate_pem_.clear();
    tls_private_key_pem_.clear();
    tls_context_.reset();
}

bool ProxyServer::tls_enabled() const noexcept {
    return !tls_certificate_pem_.empty() && !tls_private_key_pem_.empty();
}

void ProxyServer::set_default_action(router::RouteAction action) {
    if (running()) {
        throw std::logic_error("Cannot change routing on a running proxy");
    }
    router_.set_default_action(std::move(action));
}

void ProxyServer::add_rule(router::TrafficRule rule) {
    if (running()) {
        throw std::logic_error("Cannot change routing on a running proxy");
    }
    router_.add_rule(std::move(rule));
}

void ProxyServer::set_resolver(std::shared_ptr<dns::ResolverService> resolver) {
    if (running()) {
        throw std::logic_error("Cannot change the resolver on a running proxy");
    }
    resolver_ = std::move(resolver);
    direct_outbound_->set_resolver(resolver_);
}

void ProxyServer::set_fake_ip_store(std::shared_ptr<dns::FakeIpStore> store) {
    if (running()) {
        throw std::logic_error("Cannot change FakeIP configuration on a running proxy");
    }
    fake_ip_store_ = std::move(store);
}

void ProxyServer::set_fake_ip_filter(std::function<bool(std::string_view)> filter) {
    if (running()) {
        throw std::logic_error("Cannot change FakeIP configuration on a running proxy");
    }
    fake_ip_filter_ = std::move(filter);
}

void ProxyServer::set_outbound_registry(std::shared_ptr<outbound::OutboundRegistry> registry) {
    if (running()) {
        throw std::logic_error("Cannot change outbound registry on a running proxy");
    }
    outbound_registry_ = std::move(registry);
}

void ProxyServer::set_connection_registry(
    std::shared_ptr<observability::ConnectionRegistry> registry) {
    if (running()) {
        throw std::logic_error("Cannot change the connection registry on a running proxy");
    }
    connection_registry_ = std::move(registry);
}

core::Status ProxyServer::start() {
    if (running_.exchange(true)) {
        spdlog::debug("Proxy server start requested while already running");
        return {};
    }

    if (!outbound_registry_) {
        spdlog::error("Proxy server cannot start without an outbound registry");
        running_ = false;
        return core::fail({core::ErrorCode::configuration, "proxy outbound registry is missing"});
    }
    if (const auto result = outbound_registry_->validate(); !result) {
        spdlog::error("Proxy server outbound registry validation failed: {}",
                      result.error().context);
        running_ = false;
        return result;
    }
    const auto outbound_ids = outbound_registry_->ids();
    if (const auto result = router_.validate(outbound_ids); !result) {
        spdlog::error("Proxy server routing validation failed: {}", result.error().context);
        running_ = false;
        return result;
    }

    auto snapshot = std::make_shared<const runtime::RuntimeSnapshot>(runtime::RuntimeSnapshot{
        next_snapshot_generation_++, router_.snapshot(), outbound_registry_->snapshot(), resolver_,
        fake_ip_store_, fake_ip_filter_});
    if (const auto result = snapshot_store_->publish(snapshot); !result) {
        spdlog::error("Proxy server runtime snapshot validation failed: {}",
                      result.error().context);
        running_ = false;
        return result;
    }

    if (tls_enabled()) {
        auto context =
            std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tls_server);
        context->set_options(boost::asio::ssl::context::default_workarounds |
                             boost::asio::ssl::context::no_sslv2 |
                             boost::asio::ssl::context::no_sslv3);
        boost::system::error_code tls_error;
        context->use_certificate_chain(boost::asio::buffer(tls_certificate_pem_), tls_error);
        if (!tls_error) {
            context->use_private_key(boost::asio::buffer(tls_private_key_pem_),
                                     boost::asio::ssl::context::pem, tls_error);
        }
        if (tls_error) {
            spdlog::error("Proxy server TLS credentials are invalid: {}", tls_error.message());
            running_ = false;
            return core::fail({core::ErrorCode::configuration,
                               "invalid proxy TLS certificate or private key",
                               std::error_code(tls_error.value(), std::system_category())});
        }
        tls_context_ = std::move(context);
    } else {
        tls_context_.reset();
    }

    boost::system::error_code error;
    acceptor_.open(endpoint_.protocol(), error);
    if (!error) {
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true), error);
    }
    if (!error) {
        acceptor_.bind(endpoint_, error);
    }
    if (!error) {
        acceptor_.listen(boost::asio::socket_base::max_listen_connections, error);
    }

    if (error) {
        spdlog::error("Proxy server failed to open listener: {}", error.message());
        running_ = false;
        acceptor_.close();
        return core::fail(listener_error("open, bind, or listen", error));
    }

    endpoint_ = acceptor_.local_endpoint(error);
    if (error) {
        spdlog::error("Proxy server failed to query listener endpoint: {}", error.message());
        running_ = false;
        acceptor_.close();
        return core::fail(listener_error("query", error));
    }

    callback_gate_ = std::make_shared<std::atomic_bool>(true);
    if (socks5_udp_endpoint_ && inbound_mode_ == ProxyInboundMode::http) {
        spdlog::error("Proxy server cannot enable a SOCKS5 UDP listener in HTTP-only mode");
        callback_gate_->store(false, std::memory_order_release);
        acceptor_.close();
        running_ = false;
        return core::fail(
            {core::ErrorCode::configuration, "SOCKS5 UDP listener requires a SOCKS-capable mode"});
    }
    if (socks5_udp_endpoint_) {
        if (const auto result = start_socks5_udp_listener(); !result) {
            callback_gate_->store(false, std::memory_order_release);
            acceptor_.close();
            running_ = false;
            return result;
        }
    }
    spdlog::info("Proxy server listening on {}:{}{}", endpoint_.address().to_string(),
                 endpoint_.port(), tls_enabled() ? " (TLS)" : "");
    accept();
    return {};
}

void ProxyServer::stop() noexcept {
    if (!running_.exchange(false)) {
        spdlog::debug("Proxy server stop requested while already stopped");
        return;
    }

    spdlog::debug("Stopping proxy server");
    callback_gate_->store(false, std::memory_order_release);
    if (!runtime_.running()) {
        stop_on_owner();
        return;
    }

    std::binary_semaphore completed(0);
    boost::asio::dispatch(runtime_.context(), [this, &completed] {
        stop_on_owner();
        completed.release();
    });
    completed.acquire();
}

void ProxyServer::stop_on_owner() noexcept {
    if (resolver_) {
        for (const auto request_id : resolver_requests_) {
            resolver_->cancel(request_id);
        }
    }
    resolver_requests_.clear();

    boost::system::error_code ignored;
    acceptor_.cancel(ignored);
    acceptor_.close(ignored);
    if (socks5_udp_listener_) {
        socks5_udp_listener_->stop();
        socks5_udp_listener_.reset();
    }

    std::vector<SessionPtr> sessions;
    {
        std::lock_guard lock(sessions_mutex_);
        sessions.reserve(sessions_.size());
        for (const auto &session : sessions_) {
            sessions.push_back(session);
        }
        sessions_.clear();
    }

    for (const auto &session : sessions) {
        session->stop();
    }
    spdlog::debug("Proxy server stopped");
}

core::Status ProxyServer::reload(runtime::RuntimeSnapshotPtr snapshot) {
    if (!snapshot) {
        return core::fail({core::ErrorCode::configuration, "proxy runtime snapshot is required"});
    }
    if (snapshot->generation == 0) {
        auto replacement = std::make_shared<runtime::RuntimeSnapshot>(*snapshot);
        replacement->generation = next_snapshot_generation_++;
        snapshot = std::move(replacement);
    }
    if (const auto result = snapshot_store_->publish(std::move(snapshot)); !result) {
        return result;
    }
    spdlog::info("Proxy server published runtime snapshot generation {}",
                 snapshot_store_->load()->generation);
    return {};
}

std::shared_ptr<runtime::RuntimeSnapshotStore>
ProxyServer::runtime_snapshot_store() const noexcept {
    return snapshot_store_;
}

bool ProxyServer::running() const noexcept { return running_.load(); }

boost::asio::ip::tcp::endpoint ProxyServer::endpoint() const noexcept { return endpoint_; }

std::optional<boost::asio::ip::udp::endpoint> ProxyServer::socks5_udp_endpoint() const noexcept {
    if (socks5_udp_listener_) {
        return socks5_udp_listener_->endpoint();
    }
    return socks5_udp_endpoint_;
}

core::Status ProxyServer::start_socks5_udp_listener() {
    if (!socks5_udp_endpoint_) {
        return {};
    }
    socks5_udp_listener_ = std::make_shared<Socks5UdpListener>(*this);
    if (const auto result = socks5_udp_listener_->start(*socks5_udp_endpoint_); !result) {
        socks5_udp_listener_.reset();
        return result;
    }
    socks5_udp_endpoint_ = socks5_udp_listener_->endpoint();
    return {};
}

void ProxyServer::accept() {
    if (!running()) {
        return;
    }

    auto client = std::make_shared<boost::asio::ip::tcp::socket>(runtime_.context());
    const auto gate = callback_gate_;
    acceptor_.async_accept(*client, [this, gate, client](const boost::system::error_code &error) {
        if (!gate->load(std::memory_order_acquire)) {
            return;
        }
        if (!error && running()) {
            auto session = std::make_shared<ProxySession>(
                *this, std::move(*client), [this, gate](const SessionPtr &closed_session) {
                    if (gate->load(std::memory_order_acquire)) {
                        remove_session(closed_session);
                    }
                });
            bool accepted_session = false;
            {
                std::lock_guard lock(sessions_mutex_);
                if (running()) {
                    sessions_.insert(session);
                    accepted_session = true;
                }
            }
            if (accepted_session) {
                session->start();
            } else {
                session->stop();
            }
        }

        if (gate->load(std::memory_order_acquire)) {
            accept();
        }
    });
}

void ProxyServer::open_stream(
    core::ConnectionMetadata metadata,
    std::optional<observability::ConnectionRegistry::ConnectionId> connection_id,
    core::StreamOpenHandler handler) {
    const auto snapshot = snapshot_store_->load();
    if (!snapshot) {
        handler(core::StreamOpenResult::failed(
            {core::ErrorCode::configuration, "proxy runtime snapshot is not published"}));
        return;
    }
    if (snapshot->fake_ip_store && metadata.destination.is_address() &&
        metadata.destination.address().is_v4()) {
        if (const auto domain =
                snapshot->fake_ip_store->reverse(metadata.destination.address().to_v4())) {
            metadata.destination = core::Destination::domain(*domain, metadata.destination.port());
        }
    }
    route_stream(snapshot, std::move(metadata), {}, 0, connection_id, std::move(handler));
}

void ProxyServer::route_stream(
    runtime::RuntimeSnapshotPtr snapshot, core::ConnectionMetadata metadata,
    router::RoutingContext context, std::size_t start,
    std::optional<observability::ConnectionRegistry::ConnectionId> connection_id,
    core::StreamOpenHandler handler) {
    const auto evaluation = snapshot->router->evaluate(metadata, context, start);
    if (const auto *need = std::get_if<router::NeedMetadata>(&evaluation)) {
        if (need->need != router::MetadataNeed::destination_ip ||
            !metadata.destination.is_domain() || !snapshot->resolver) {
            handler(core::StreamOpenResult::failed(
                {core::ErrorCode::resolution, "destination IP enrichment is not configured"}));
            return;
        }

        context.destination_lookup = router::LookupState::in_progress;
        const auto resolver = snapshot->resolver;
        const auto gate = callback_gate_;
        auto self = this;
        const auto request_id = std::make_shared<dns::ResolverService::RequestId>();
        *request_id = resolver->resolve(
            {metadata.destination.domain(), dns::DnsRecordType::a, 1},
            [self, gate, resolver, request_id, snapshot, connection_id,
             metadata = std::move(metadata), context = std::move(context), start = need->rule_index,
             handler = std::move(handler)](core::Result<dns::DnsAnswer> result) mutable {
                if (!gate->load(std::memory_order_acquire)) {
                    return;
                }
                self->resolver_requests_.erase(*request_id);
                auto addresses = std::make_shared<std::vector<boost::asio::ip::address>>();
                if (result) {
                    addresses->insert(addresses->end(), result.value().addresses.begin(),
                                      result.value().addresses.end());
                }
                const auto ipv6_request_id = std::make_shared<dns::ResolverService::RequestId>();
                *ipv6_request_id = resolver->resolve(
                    {metadata.destination.domain(), dns::DnsRecordType::aaaa, 1},
                    [self, gate, snapshot, ipv6_request_id, metadata = std::move(metadata),
                     context = std::move(context), start, connection_id,
                     handler = std::move(handler),
                     addresses](core::Result<dns::DnsAnswer> ipv6_result) mutable {
                        if (!gate->load(std::memory_order_acquire)) {
                            return;
                        }
                        self->resolver_requests_.erase(*ipv6_request_id);
                        if (ipv6_result) {
                            addresses->insert(addresses->end(),
                                              ipv6_result.value().addresses.begin(),
                                              ipv6_result.value().addresses.end());
                        }
                        if (!addresses->empty()) {
                            context.destination_lookup = router::LookupState::resolved;
                            context.destination_addresses = std::move(*addresses);
                            context.destination_address = context.destination_addresses.front();
                        } else {
                            context.destination_lookup = router::LookupState::failed;
                            context.destination_addresses.clear();
                            context.destination_address.reset();
                        }
                        self->route_stream(snapshot, std::move(metadata), std::move(context), start,
                                           connection_id, std::move(handler));
                    },
                    self->runtime_.scheduler());
                self->resolver_requests_.insert(*ipv6_request_id);
            },
            runtime_.scheduler());
        resolver_requests_.insert(*request_id);
        return;
    }

    const auto *matched = std::get_if<router::Matched>(&evaluation);
    if (!matched) {
        handler(core::StreamOpenResult::failed(
            {core::ErrorCode::resolution, "routing requires destination IP enrichment"}));
        return;
    }

    switch (matched->decision.action.kind) {
    case router::RouteActionKind::direct:
        if (connection_id && connection_registry_) {
            connection_registry_->update_outbound(*connection_id, "direct");
        }
        if (metadata.destination.is_domain() && !context.destination_address &&
            snapshot->resolver) {
            const auto gate = callback_gate_;
            auto destination = metadata.destination;
            const auto domain = destination.domain();
            outbound::detail::resolve_host(
                runtime_, snapshot->resolver, domain,
                [this, gate, destination = std::move(destination), handler = std::move(handler)](
                    core::Result<outbound::detail::AddressList> result) mutable {
                    if (!gate->load(std::memory_order_acquire)) {
                        return;
                    }
                    if (!result || result.value().empty()) {
                        handler(core::StreamOpenResult::failed(
                            result ? core::Error{core::ErrorCode::resolution,
                                                 "direct destination resolved to no addresses"}
                                   : result.error()));
                        return;
                    }
                    direct_outbound_->connect_stream(
                        {std::move(destination), result.value().front()}, std::move(handler));
                });
            return;
        }
        direct_outbound_->connect_stream(
            {std::move(metadata.destination), context.destination_address}, std::move(handler));
        return;
    case router::RouteActionKind::reject:
        if (connection_id && connection_registry_) {
            connection_registry_->update_outbound(*connection_id, "reject");
        }
        reject_outbound_->connect_stream(
            {std::move(metadata.destination), context.destination_address}, std::move(handler));
        return;
    case router::RouteActionKind::named:
        if (!snapshot->outbounds) {
            handler(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration, "proxy outbound registry is missing"}));
            return;
        }
        {
            const auto selected = snapshot->outbounds->select(matched->decision.action.target);
            if (!selected) {
                handler(core::StreamOpenResult::failed(selected.error()));
                return;
            }
            if (connection_id && connection_registry_) {
                connection_registry_->update_outbound(*connection_id,
                                                      selected.value()->descriptor().id);
            }
            selected.value()->connect_stream(
                {std::move(metadata.destination), context.destination_address}, std::move(handler));
        }
        return;
    }
}

void ProxyServer::open_datagram(runtime::RuntimeSnapshotPtr snapshot,
                                core::ConnectionMetadata metadata, DatagramRouteHandler handler) {
    if (!snapshot) {
        handler(core::DatagramOpenResult::failed(
                    {core::ErrorCode::configuration, "proxy runtime snapshot is not published"}),
                {});
        return;
    }
    if (snapshot->fake_ip_store && metadata.destination.is_address() &&
        metadata.destination.address().is_v4()) {
        if (const auto domain =
                snapshot->fake_ip_store->reverse(metadata.destination.address().to_v4())) {
            metadata.destination = core::Destination::domain(*domain, metadata.destination.port());
        }
    }

    router::RoutingContext context;
    if (metadata.destination.is_address()) {
        context.destination_lookup = router::LookupState::resolved;
        context.destination_address = metadata.destination.address();
        context.destination_addresses.push_back(metadata.destination.address());
        route_datagram(std::move(snapshot), std::move(metadata), std::move(context),
                       std::move(handler));
        return;
    }

    const auto gate = callback_gate_;
    const auto domain = metadata.destination.domain();
    auto resolver = snapshot->resolver;
    outbound::detail::resolve_host(
        runtime_, std::move(resolver), domain,
        [this, gate, snapshot = std::move(snapshot), metadata = std::move(metadata),
         handler = std::move(handler)](core::Result<outbound::detail::AddressList> result) mutable {
            if (!gate->load(std::memory_order_acquire)) {
                return;
            }
            if (!result || result.value().empty()) {
                handler(core::DatagramOpenResult::failed(
                            result ? core::Error{core::ErrorCode::resolution,
                                                 "UDP destination resolved to no addresses"}
                                   : result.error()),
                        {});
                return;
            }
            router::RoutingContext context;
            context.destination_lookup = router::LookupState::resolved;
            context.destination_addresses = std::move(result.value());
            context.destination_address = context.destination_addresses.front();
            route_datagram(std::move(snapshot), std::move(metadata), std::move(context),
                           std::move(handler));
        });
}

void ProxyServer::route_datagram(runtime::RuntimeSnapshotPtr snapshot,
                                 core::ConnectionMetadata metadata, router::RoutingContext context,
                                 DatagramRouteHandler handler) {
    const auto evaluation = snapshot->router->evaluate(metadata, context);
    const auto *matched = std::get_if<router::Matched>(&evaluation);
    if (!matched) {
        handler(
            core::DatagramOpenResult::failed(
                {core::ErrorCode::resolution, "UDP routing requires destination IP enrichment"}),
            {});
        return;
    }

    const auto destination_address =
        context.destination_address
            ? context.destination_address
            : (metadata.destination.is_address()
                   ? std::optional<boost::asio::ip::address>(metadata.destination.address())
                   : std::nullopt);
    if (!destination_address) {
        handler(core::DatagramOpenResult::failed(
                    {core::ErrorCode::resolution, "UDP destination has no resolved address"}),
                {});
        return;
    }
    const boost::asio::ip::udp::endpoint target(*destination_address, metadata.destination.port());
    const core::DatagramRequest request{
        core::Destination::address(target.address(), target.port())};
    std::shared_ptr<core::Outbound> outbound;
    switch (matched->decision.action.kind) {
    case router::RouteActionKind::direct:
        outbound = direct_outbound_;
        break;
    case router::RouteActionKind::reject:
        outbound = reject_outbound_;
        break;
    case router::RouteActionKind::named:
        if (!snapshot->outbounds) {
            handler(core::DatagramOpenResult::failed(
                        {core::ErrorCode::configuration, "proxy outbound registry is missing"}),
                    target);
            return;
        }
        {
            const auto selected = snapshot->outbounds->select(matched->decision.action.target);
            if (!selected) {
                handler(core::DatagramOpenResult::failed(selected.error()), target);
                return;
            }
            outbound = selected.value();
        }
        break;
    }
    outbound->open_datagram(
        request, [handler = std::move(handler), target](core::DatagramOpenResult result) mutable {
            handler(std::move(result), target);
        });
}

void ProxyServer::remove_session(const SessionPtr &session) noexcept {
    std::lock_guard lock(sessions_mutex_);
    sessions_.erase(session);
}

} // namespace clash_native::proxy
