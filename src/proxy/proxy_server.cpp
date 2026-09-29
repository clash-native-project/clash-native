#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/net/udp_stream.hpp>
#include <clash_native/proxy/proxy_server.hpp>
#include <clash_native/proxy/tcp_relay.hpp>

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
#include <exec/asio/use_sender.hpp>
#include <exec/when_any.hpp>
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

// Detached drain receiver: releases the stop semaphore; errors are
// impossible here (on_empty only fails on misuse, and the loop swallows
// its own failures), so terminate rather than hang the stop path.
struct DetachedRelease {
    using receiver_concept = stdexec::receiver_tag;
    std::binary_semaphore *completed;
    void set_value() && noexcept { completed->release(); }
    void set_error(std::exception_ptr) && noexcept { std::terminate(); }
    void set_stopped() && noexcept { completed->release(); }
};

} // namespace

ProxyServer::ProxyServer(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint)
    : runtime_(runtime), acceptor_(runtime.serialized_executor()), endpoint_(endpoint), router_(),
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

void ProxyServer::set_http_exchange_deadline(std::chrono::steady_clock::duration deadline) {
    if (running()) {
        throw std::logic_error("Cannot change the HTTP exchange deadline on a running proxy");
    }
    http_exchange_deadline_ = deadline;
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
    boost::asio::dispatch(runtime_.serialized_executor(), [this, &completed] {
        stop_on_owner();
        // The accept loop only exits after its in-flight accept completes
        // stopped; draining the scope here keeps the spawn's __active_
        // count alive until the task (and its use_sender op) is destroyed,
        // instead of racing the ProxyServer destructor at teardown. The
        // drain runs on the owner strand, and the accept completion posts
        // back here, so stop only returns once the loop is gone.
        auto drained =
            accept_scope_.on_empty() | stdexec::then([&completed] { completed.release(); });
        async::start_with_receiver(std::move(drained), DetachedRelease{&completed});
    });
    completed.acquire();
}

void ProxyServer::stop_on_owner() noexcept {
    // Destroy the pending accept before requesting scope stop: the
    // use_sender accept op completes through the IO thread, which can
    // otherwise race process teardown (io_context shutdown completing the
    // accept into a dying scope). Closing first turns the in-flight accept
    // into an immediate error on the owner strand.
    boost::system::error_code ignored;
    acceptor_.cancel(ignored);
    acceptor_.close(ignored);
    try {
        accept_scope_.request_stop();
    } catch (...) {
    }
    if (resolver_) {
        for (const auto request_id : resolver_requests_) {
            resolver_->cancel(request_id);
        }
    }
    resolver_requests_.clear();

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
    // Accept loop runs as a task: stop requests scope stop, which completes
    // the in-flight accept as stopped and exits without re-arming.
    accept_scope_.spawn(run_accept_loop(this));
}

exec::task<void> ProxyServer::run_accept_loop(ProxyServer *server) {
    while (server->running_.load()) {
        auto client =
            std::make_shared<boost::asio::ip::tcp::socket>(server->runtime_.serialized_executor());
        try {
            co_await server->acceptor_.async_accept(*client, exec::asio::use_sender);
        } catch (...) {
            // Stopped (shutdown cancel/close) or accept failure: stop owns
            // teardown, so just exit the loop without re-arming.
            co_return;
        }
        if (!server->running_.load() || !server->callback_gate_->load(std::memory_order_acquire)) {
            co_return;
        }
        const auto gate = server->callback_gate_;
        auto session = std::make_shared<ProxySession>(
            *server, std::move(*client), [server, gate](const SessionPtr &closed_session) {
                if (gate->load(std::memory_order_acquire)) {
                    server->remove_session(closed_session);
                }
            });
        bool accepted_session = false;
        {
            std::lock_guard lock(server->sessions_mutex_);
            if (server->running_.load()) {
                server->sessions_.insert(session);
                accepted_session = true;
            }
        }
        if (accepted_session) {
            session->start();
        } else {
            session->stop();
        }
    }
}

exec::task<core::StreamOpenResult> ProxyServer::open_stream(
    core::ConnectionMetadata metadata,
    std::optional<observability::ConnectionRegistry::ConnectionId> connection_id) {
    const auto snapshot = snapshot_store_->load();
    if (!snapshot) {
        co_return core::StreamOpenResult::failed(
            {core::ErrorCode::configuration, "proxy runtime snapshot is not published"});
    }
    if (snapshot->fake_ip_store && metadata.destination.is_address() &&
        metadata.destination.address().is_v4()) {
        if (const auto domain =
                snapshot->fake_ip_store->reverse(metadata.destination.address().to_v4())) {
            metadata.destination = core::Destination::domain(*domain, metadata.destination.port());
        }
    }
    co_return co_await route_stream(*this, snapshot, std::move(metadata), {}, 0, connection_id);
}

exec::task<core::StreamOpenResult> ProxyServer::route_stream(
    ProxyServer &server, runtime::RuntimeSnapshotPtr snapshot, core::ConnectionMetadata metadata,
    router::RoutingContext context, std::size_t start,
    std::optional<observability::ConnectionRegistry::ConnectionId> connection_id) {
    const auto failed = [](core::Error error) {
        return core::StreamOpenResult::failed(std::move(error));
    };
    const auto cancelled = [] {
        return core::StreamOpenResult::failed(
            {core::ErrorCode::cancelled, "proxy route was cancelled", {}});
    };
    const auto stopped = [&server] {
        return !server.callback_gate_->load(std::memory_order_acquire);
    };
    // Resolve leaf: registers the registry request for server stop and
    // unregisters on terminal; the aborter cancels late. callback_sender
    // (not bridge_sender) because the result must cross as an in-band
    // value while stop maps to set_stopped.
    const auto resolve_addresses =
        [&server, snapshot](std::string host,
                            dns::DnsRecordType type) -> exec::task<core::Result<dns::DnsAnswer>> {
        core::Result<dns::DnsAnswer> answer;
        try {
            answer = co_await async::callback_sender<
                async::BridgeSignatures<core::Result<dns::DnsAnswer>>>(
                [&server, snapshot, host = std::move(host),
                 type](auto terminal) mutable -> async::CallbackAbortFn {
                    auto resolver = snapshot->resolver;
                    auto id = std::make_shared<dns::ResolverService::RequestId>();
                    *id = resolver->resolve(
                        {std::move(host), type, 1},
                        [&server, id, terminal = std::move(terminal)](
                            core::Result<dns::DnsAnswer> result) mutable {
                            server.resolver_requests_.erase(*id);
                            terminal(std::move(result));
                        },
                        server.runtime_.scheduler());
                    server.resolver_requests_.insert(*id);
                    return async::CallbackAbortFn{[&server, snapshot, id] {
                        if (snapshot->resolver) {
                            snapshot->resolver->cancel(*id);
                        }
                        server.resolver_requests_.erase(*id);
                    }};
                },
                async::BridgeTranslate<core::Result<dns::DnsAnswer>>{});
        } catch (...) {
            co_return core::fail(
                core::Error{core::ErrorCode::resolution, "proxy route DNS enrichment failed", {}});
        }
        co_return answer;
    };
    for (;;) {
        const auto evaluation = snapshot->router->evaluate(metadata, context, start);
        if (const auto *need = std::get_if<router::NeedMetadata>(&evaluation)) {
            if (need->need != router::MetadataNeed::destination_ip ||
                !metadata.destination.is_domain() || !snapshot->resolver) {
                co_return failed(
                    {core::ErrorCode::resolution, "destination IP enrichment is not configured"});
            }
            context.destination_lookup = router::LookupState::in_progress;
            std::vector<boost::asio::ip::address> addresses;
            for (const auto type : {dns::DnsRecordType::a, dns::DnsRecordType::aaaa}) {
                auto answer = co_await resolve_addresses(metadata.destination.domain(), type);
                if (stopped()) {
                    co_return cancelled();
                }
                if (answer) {
                    addresses.insert(addresses.end(), answer.value().addresses.begin(),
                                     answer.value().addresses.end());
                }
            }
            if (!addresses.empty()) {
                context.destination_lookup = router::LookupState::resolved;
                context.destination_addresses = std::move(addresses);
                context.destination_address = context.destination_addresses.front();
            } else {
                context.destination_lookup = router::LookupState::failed;
                context.destination_addresses.clear();
                context.destination_address.reset();
            }
            start = need->rule_index;
            continue;
        }
        const auto *matched = std::get_if<router::Matched>(&evaluation);
        if (!matched) {
            co_return failed(
                {core::ErrorCode::resolution, "routing requires destination IP enrichment"});
        }
        const auto dial =
            [&server](std::shared_ptr<core::Outbound> outbound,
                      core::StreamRequest request) -> exec::task<core::StreamOpenResult> {
            try {
                co_return co_await outbound->connect_stream(std::move(request));
            } catch (const core::Error &failure) {
                co_return core::StreamOpenResult::failed(failure);
            } catch (...) {
                co_return core::StreamOpenResult::failed(core::Error{
                    core::ErrorCode::endpoint_connection, "proxy outbound open failed"});
            }
        };
        switch (matched->decision.action.kind) {
        case router::RouteActionKind::direct: {
            if (connection_id && server.connection_registry_) {
                server.connection_registry_->update_outbound(*connection_id, "direct");
            }
            if (metadata.destination.is_domain() && !context.destination_address &&
                snapshot->resolver) {
                const auto domain = metadata.destination.domain();
                core::Result<outbound::detail::AddressList> resolved;
                try {
                    resolved = co_await outbound::detail::resolve_host_sender(
                        server.runtime_, server.snapshot_store_->load()->resolver, domain);
                } catch (...) {
                    co_return failed(
                        {core::ErrorCode::resolution, "direct destination resolution failed"});
                }
                if (stopped()) {
                    co_return cancelled();
                }
                if (!resolved || resolved.value().empty()) {
                    co_return failed(
                        resolved ? core::Error{core::ErrorCode::resolution,
                                               "direct destination resolved to no addresses"}
                                 : resolved.error());
                }
                auto destination = metadata.destination;
                co_return co_await dial(server.direct_outbound_,
                                        {std::move(destination), resolved.value().front()});
            }
            co_return co_await dial(server.direct_outbound_,
                                    {std::move(metadata.destination), context.destination_address});
        }
        case router::RouteActionKind::reject: {
            if (connection_id && server.connection_registry_) {
                server.connection_registry_->update_outbound(*connection_id, "reject");
            }
            co_return co_await dial(server.reject_outbound_,
                                    {std::move(metadata.destination), context.destination_address});
        }
        case router::RouteActionKind::named: {
            if (!snapshot->outbounds) {
                co_return failed(
                    {core::ErrorCode::configuration, "proxy outbound registry is missing"});
            }
            const auto selected = snapshot->outbounds->select(matched->decision.action.target);
            if (!selected) {
                co_return failed(selected.error());
            }
            if (connection_id && server.connection_registry_) {
                server.connection_registry_->update_outbound(*connection_id,
                                                             selected.value()->descriptor().id);
            }
            co_return co_await dial(selected.value(),
                                    {std::move(metadata.destination), context.destination_address});
        }
        }
    }
}
exec::task<ProxyServer::RoutedDatagram>
ProxyServer::open_datagram(runtime::RuntimeSnapshotPtr snapshot,
                           core::ConnectionMetadata metadata) {
    if (!snapshot) {
        co_return RoutedDatagram{
            core::DatagramOpenResult::failed(
                {core::ErrorCode::configuration, "proxy runtime snapshot is not published"}),
            {}};
    }
    if (snapshot->fake_ip_store && metadata.destination.is_address() &&
        metadata.destination.address().is_v4()) {
        if (const auto domain =
                snapshot->fake_ip_store->reverse(metadata.destination.address().to_v4())) {
            metadata.destination = core::Destination::domain(*domain, metadata.destination.port());
        }
    }
    if (metadata.destination.is_address()) {
        router::RoutingContext context;
        context.destination_lookup = router::LookupState::resolved;
        context.destination_address = metadata.destination.address();
        context.destination_addresses.push_back(metadata.destination.address());
        co_return co_await route_datagram(*this, std::move(snapshot), std::move(metadata),
                                          std::move(context));
    }
    co_return co_await open_datagram_resolved(*this, std::move(snapshot), std::move(metadata));
}

exec::task<ProxyServer::RoutedDatagram>
ProxyServer::open_datagram_resolved(ProxyServer &server, runtime::RuntimeSnapshotPtr snapshot,
                                    core::ConnectionMetadata metadata) {
    const auto domain = metadata.destination.domain();
    core::Result<outbound::detail::AddressList> resolved;
    try {
        resolved = co_await outbound::detail::resolve_host_sender(
            server.runtime_, server.snapshot_store_->load()->resolver, domain);
    } catch (...) {
        co_return RoutedDatagram{core::DatagramOpenResult::failed(
                                     {core::ErrorCode::resolution, "UDP resolution failed", {}}),
                                 {}};
    }
    if (!server.callback_gate_->load(std::memory_order_acquire)) {
        co_return RoutedDatagram{core::DatagramOpenResult::failed(
                                     {core::ErrorCode::cancelled, "proxy route was cancelled", {}}),
                                 {}};
    }
    if (!resolved || resolved.value().empty()) {
        co_return RoutedDatagram{core::DatagramOpenResult::failed(
                                     resolved
                                         ? core::Error{core::ErrorCode::resolution,
                                                       "UDP destination resolved to no addresses"}
                                         : resolved.error()),
                                 {}};
    }
    router::RoutingContext context;
    context.destination_lookup = router::LookupState::resolved;
    context.destination_addresses = std::move(resolved.value());
    context.destination_address = context.destination_addresses.front();
    co_return co_await route_datagram(server, std::move(snapshot), std::move(metadata),
                                      std::move(context));
}

exec::task<ProxyServer::RoutedDatagram>
ProxyServer::route_datagram(ProxyServer &server, runtime::RuntimeSnapshotPtr snapshot,
                            core::ConnectionMetadata metadata, router::RoutingContext context) {
    const auto failed = [](core::Error error, boost::asio::ip::udp::endpoint target) {
        return RoutedDatagram{core::DatagramOpenResult::failed(std::move(error)), target};
    };
    const auto evaluation = snapshot->router->evaluate(metadata, context);
    const auto *matched = std::get_if<router::Matched>(&evaluation);
    if (!matched) {
        co_return failed(
            {core::ErrorCode::resolution, "UDP routing requires destination IP enrichment"}, {});
    }
    const auto destination_address =
        context.destination_address
            ? context.destination_address
            : (metadata.destination.is_address()
                   ? std::optional<boost::asio::ip::address>(metadata.destination.address())
                   : std::nullopt);
    if (!destination_address) {
        co_return failed({core::ErrorCode::resolution, "UDP destination has no resolved address"},
                         {});
    }
    const boost::asio::ip::udp::endpoint target(*destination_address, metadata.destination.port());
    const core::DatagramRequest request{
        core::Destination::address(target.address(), target.port())};
    std::shared_ptr<core::Outbound> outbound;
    switch (matched->decision.action.kind) {
    case router::RouteActionKind::direct:
        outbound = server.direct_outbound_;
        break;
    case router::RouteActionKind::reject:
        outbound = server.reject_outbound_;
        break;
    case router::RouteActionKind::named:
        if (!snapshot->outbounds) {
            co_return failed({core::ErrorCode::configuration, "proxy outbound registry is missing"},
                             target);
        }
        {
            const auto selected = snapshot->outbounds->select(matched->decision.action.target);
            if (!selected) {
                co_return failed(selected.error(), target);
            }
            outbound = selected.value();
        }
        break;
    }
    // Mihomo's tunnel skips adapters without UDP support before dialing.
    // Our router picks a single outbound without fallback iteration, so a
    // disabled outbound fails the relay here instead of moving on.
    if (outbound->capabilities().datagram == core::DatagramSemantics::unsupported) {
        co_return failed(
            {core::ErrorCode::configuration, "the selected outbound does not support UDP"}, target);
    }
    try {
        co_return RoutedDatagram{co_await outbound->open_datagram(std::move(request)), target};
    } catch (const core::Error &failure) {
        co_return failed(failure, target);
    } catch (...) {
        co_return failed(
            core::Error{core::ErrorCode::endpoint_connection, "proxy datagram open failed"},
            target);
    }
}
void ProxyServer::remove_session(const SessionPtr &session) noexcept {
    std::lock_guard lock(sessions_mutex_);
    sessions_.erase(session);
}

bool ProxyServer::close_connection(observability::ConnectionRegistry::ConnectionId id) noexcept {
    SessionPtr target;
    {
        std::lock_guard lock(sessions_mutex_);
        for (const auto &session : sessions_) {
            if (session->connection_id() == id) {
                target = session;
                break;
            }
        }
    }
    // Outside the lock: stop() closes the session, which removes itself
    // from the set through the close handler.
    if (!target) {
        return false;
    }
    target->stop();
    return true;
}

} // namespace clash_native::proxy
