#include <clash_native/app/application.hpp>

#include <clash_native/platform/platform_adapter.hpp>

#include <boost/asio/signal_set.hpp>

#include <csignal>
#include <future>
#include <stdexcept>
#include <system_error>

#include <spdlog/spdlog.h>

namespace clash_native::app {

Application::Application() : runtime_(), proxy_server_(runtime_) {}

int Application::run(const ApplicationOptions &options) {
    if (!options.listen_endpoint) {
        spdlog::info("clash-native is an experimental native proxy core on {}.", platform::name());
        runtime_.start();
        runtime_.stop();
        return 0;
    }

    proxy_server_.set_endpoint(*options.listen_endpoint);
    proxy_server_.set_inbound_mode(options.inbound_mode);
    proxy_server_.set_http_authentication(options.http_username, options.http_password);
    proxy_server_.set_tls_server_credentials(options.tls_certificate_pem,
                                             options.tls_private_key_pem);
    proxy_server_.set_default_action(options.default_route_action);
    for (const auto &rule : options.route_rules) {
        proxy_server_.add_rule(rule);
    }
    if (options.outbound_registry) {
        proxy_server_.set_outbound_registry(options.outbound_registry);
    }
    if (options.dns_config) {
        resolver_ = std::make_shared<dns::ResolverService>(runtime_, *options.dns_config);
        if (const auto result = resolver_->validate(); !result) {
            throw std::runtime_error(result.error().context);
        }
        proxy_server_.set_resolver(resolver_);
        if (options.fake_ip_store) {
            proxy_server_.set_fake_ip_store(options.fake_ip_store);
        }
        proxy_server_.set_fake_ip_filter(options.fake_ip_filter);
        dns_server_ = std::make_unique<dns::DnsServer>(
            runtime_, proxy_server_.runtime_snapshot_store(),
            options.dns_udp_endpoint.value_or(
                boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 0)),
            options.dns_tcp_endpoint.value_or(
                boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0)));
    }

    boost::asio::signal_set signals(runtime_.context(), SIGINT, SIGTERM);
    std::promise<void> stopped;
    auto stopped_future = stopped.get_future();
    signals.async_wait([this, &stopped](const boost::system::error_code &, int) {
        if (dns_server_) {
            dns_server_->stop();
        }
        proxy_server_.stop();
        stopped.set_value();
    });

    runtime_.start();
    const auto start_result = proxy_server_.start();
    if (!start_result) {
        signals.cancel();
        if (dns_server_) {
            dns_server_->stop();
        }
        runtime_.stop();
        const auto &error = start_result.error();
        if (error.cause) {
            throw std::system_error(error.cause, error.context);
        }
        throw std::runtime_error(error.context);
    }

    if (dns_server_) {
        const auto dns_start_result = dns_server_->start();
        if (!dns_start_result) {
            signals.cancel();
            dns_server_->stop();
            proxy_server_.stop();
            runtime_.stop();
            throw std::runtime_error(dns_start_result.error().context);
        }
    }

    const auto endpoint = proxy_server_.endpoint();
    const auto listener_name = options.inbound_mode == proxy::ProxyInboundMode::http
                                   ? "HTTP"
                                   : "HTTP/SOCKS5 mixed";
    const auto authentication_name = options.http_username.empty() ? "no HTTP authentication"
                                                                    : "HTTP Basic authentication";
    spdlog::info("{} proxy listening on {}:{} ({}). Press Ctrl+C to stop.", listener_name,
                 endpoint.address().to_string(), endpoint.port(), authentication_name);

    stopped_future.wait();
    signals.cancel();
    if (dns_server_) {
        dns_server_->stop();
    }
    proxy_server_.stop();
    runtime_.stop();
    return 0;
}

core::Status Application::reload(runtime::RuntimeSnapshotPtr snapshot) {
    return proxy_server_.reload(std::move(snapshot));
}

} // namespace clash_native::app
