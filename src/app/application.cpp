#include <clash_native/app/application.hpp>

#include <clash_native/platform/platform_adapter.hpp>

#include <boost/asio/signal_set.hpp>

#include <csignal>
#include <future>
#include <iostream>
#include <stdexcept>
#include <system_error>

#include <spdlog/spdlog.h>

namespace clash_native::app {

Application::Application() : runtime_(), proxy_server_(runtime_) {}

int Application::run(const ApplicationOptions &options) {
    spdlog::set_level(spdlog::level::off);

    if (!options.listen_endpoint) {
        std::cout << "clash-native is an experimental native proxy core on " << platform::name()
                  << ".\n";
        runtime_.start();
        runtime_.stop();
        return 0;
    }

    proxy_server_.set_endpoint(*options.listen_endpoint);

    boost::asio::signal_set signals(runtime_.context(), SIGINT, SIGTERM);
    std::promise<void> stopped;
    auto stopped_future = stopped.get_future();
    signals.async_wait([this, &stopped](const boost::system::error_code &, int) {
        proxy_server_.stop();
        stopped.set_value();
    });

    runtime_.start();
    const auto start_result = proxy_server_.start();
    if (!start_result) {
        signals.cancel();
        runtime_.stop();
        const auto &error = start_result.error();
        if (error.cause) {
            throw std::system_error(error.cause, error.context);
        }
        throw std::runtime_error(error.context);
    }

    const auto endpoint = proxy_server_.endpoint();
    std::cout << "SOCKS5 proxy listening on " << endpoint.address().to_string() << ":"
              << endpoint.port() << " (no authentication). Press Ctrl+C to stop.\n";

    stopped_future.wait();
    signals.cancel();
    proxy_server_.stop();
    runtime_.stop();
    return 0;
}

} // namespace clash_native::app
