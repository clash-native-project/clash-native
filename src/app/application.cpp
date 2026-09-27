#include <clash_native/app/application.hpp>

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/platform/platform_adapter.hpp>

#include <boost/asio/signal_set.hpp>
#include <exec/task.hpp>

#include <stdexec/execution.hpp>

#include <csignal>
#include <exception>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <spdlog/spdlog.h>

namespace clash_native::app {
namespace {

// Awaits one shutdown signal as a task instead of a signal_set.async_wait
// callback leaf, so the wait composes with stop/when_any/timeout instead
// of firing a handler into the run() frame. Abortion cancels the set;
// cancellation or set destruction completes stopped.
exec::task<void> await_shutdown_signal(std::shared_ptr<boost::asio::signal_set> signals) {
    using Signatures = stdexec::completion_signatures<stdexec::set_value_t(int),
                                                      stdexec::set_error_t(std::exception_ptr),
                                                      stdexec::set_stopped_t()>;
    co_await async::callback_sender<Signatures>(
        [signals](auto terminal) mutable -> async::CallbackAbortFn {
            signals->async_wait([terminal = std::move(terminal),
                                 signals](const boost::system::error_code &error,
                                          int signo) mutable { terminal(error, signo); });
            return async::CallbackAbortFn{[signals = std::move(signals)] { signals->cancel(); }};
        },
        [](stdexec::receiver auto &&receiver, const boost::system::error_code &error, int signo) {
            if (!error) {
                stdexec::set_value(std::forward<decltype(receiver)>(receiver), signo);
            } else if (error == boost::asio::error::operation_aborted) {
                stdexec::set_stopped(std::forward<decltype(receiver)>(receiver));
            } else {
                stdexec::set_error(std::forward<decltype(receiver)>(receiver),
                                   std::make_exception_ptr(boost::system::system_error(error)));
            }
        });
    co_return;
}

} // namespace

Application::Application() : runtime_(runtime::AsioRuntime::instance()), proxy_server_(runtime_) {}

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
    proxy_server_.set_socks5_users(options.socks5_users);
    if (options.socks5_udp_endpoint) {
        proxy_server_.set_socks5_udp_endpoint(*options.socks5_udp_endpoint);
    } else {
        proxy_server_.clear_socks5_udp_endpoint();
    }
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

    // The signal set outlives the await below; queued signals deliver to the
    // wait armed after startup, so no handler needs to be parked across
    // server startup.
    auto signals =
        std::make_shared<boost::asio::signal_set>(runtime_.serialized_executor(), SIGINT, SIGTERM);

    runtime_.start();
    const auto start_result = proxy_server_.start();
    if (!start_result) {
        signals->cancel();
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
            signals->cancel();
            dns_server_->stop();
            proxy_server_.stop();
            runtime_.stop();
            throw std::runtime_error(dns_start_result.error().context);
        }
    }

    const auto endpoint = proxy_server_.endpoint();
    const auto listener_name = options.inbound_mode == proxy::ProxyInboundMode::http ? "HTTP"
                               : options.inbound_mode == proxy::ProxyInboundMode::socks
                                   ? "SOCKS4/5"
                                   : "HTTP/SOCKS4/5 mixed";
    const auto authentication_name =
        options.http_username.empty() ? "no HTTP authentication" : "HTTP Basic authentication";
    spdlog::info("{} proxy listening on {}:{} ({}). Press Ctrl+C to stop.", listener_name,
                 endpoint.address().to_string(), endpoint.port(), authentication_name);

    // Single awaitable signal wait: composable with stop/timeout via the
    // sender (its aborter cancels the set). The sync_wait below blocks the
    // calling thread only; Asio work still runs on runtime threads.
    (void)stdexec::sync_wait(await_shutdown_signal(signals));
    signals->cancel();
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
