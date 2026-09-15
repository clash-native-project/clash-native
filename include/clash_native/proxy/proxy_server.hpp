#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <atomic>
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
    core::Status start();
    void stop() noexcept;
    bool running() const noexcept;
    boost::asio::ip::tcp::endpoint endpoint() const noexcept;

  private:
    class Session;
    using SessionPtr = std::shared_ptr<Session>;

    void accept();
    void remove_session(const SessionPtr &session) noexcept;

    runtime::AsioRuntime &runtime_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ip::tcp::endpoint endpoint_;
    mutable std::mutex sessions_mutex_;
    std::set<SessionPtr> sessions_;
    std::atomic_bool running_{false};
};

} // namespace clash_native::proxy
