#pragma once

#include <clash_native/proxy/proxy_server.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <optional>

namespace clash_native::app {

struct ApplicationOptions {
    std::optional<boost::asio::ip::tcp::endpoint> listen_endpoint;
};

class Application {
  public:
    Application();

    int run(const ApplicationOptions &options = {});

  private:
    runtime::AsioRuntime runtime_;
    proxy::ProxyServer proxy_server_;
};

} // namespace clash_native::app
