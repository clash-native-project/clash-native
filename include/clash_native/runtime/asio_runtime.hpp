#pragma once

#include <clash_native/runtime/asio_scheduler.hpp>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include <atomic>
#include <thread>

namespace clash_native::runtime {

class AsioRuntime {
  public:
    AsioRuntime();
    ~AsioRuntime();

    AsioRuntime(const AsioRuntime &) = delete;
    AsioRuntime &operator=(const AsioRuntime &) = delete;
    AsioRuntime(AsioRuntime &&) = delete;
    AsioRuntime &operator=(AsioRuntime &&) = delete;

    boost::asio::io_context &context() noexcept;
    AsioScheduler scheduler() noexcept;
    bool running() const noexcept;

    void start();
    void stop();

  private:
    using WorkGuard = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;

    boost::asio::io_context io_context_;
    WorkGuard work_guard_;
    std::thread thread_;
    std::atomic_bool started_{false};
    std::atomic_bool stopped_{false};
    std::atomic_bool running_{false};
};

} // namespace clash_native::runtime
