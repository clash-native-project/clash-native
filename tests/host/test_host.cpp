#include <clash_native/proxy/proxy_server.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/signal_set.hpp>

#include <csignal>
#include <exception>
#include <future>
#include <iostream>

int main(int argc, char **) {
    if (argc != 1) {
        std::cerr << "clash-native-test-host does not accept command-line arguments.\n";
        return 2;
    }

    try {
        clash_native::runtime::AsioRuntime runtime;
        clash_native::proxy::ProxyServer proxy(runtime,
                                               {boost::asio::ip::address_v4::loopback(), 0});
        boost::asio::signal_set signals(runtime.context(), SIGINT, SIGTERM);
        std::promise<void> stopped;
        auto stopped_future = stopped.get_future();

        signals.async_wait([&proxy, &stopped](const boost::system::error_code &, int) {
            proxy.stop();
            stopped.set_value();
        });

        runtime.start();
        proxy.start();

        const auto endpoint = proxy.endpoint();
        std::cout << "clash-native-test-host ready " << endpoint.address().to_string() << ":"
                  << endpoint.port() << std::endl;

        stopped_future.wait();
        signals.cancel();
        proxy.stop();
        runtime.stop();
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "clash-native-test-host error: " << error.what() << "\n";
        return 1;
    }
}
