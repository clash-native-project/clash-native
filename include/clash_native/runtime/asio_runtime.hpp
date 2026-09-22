#pragma once

#include <clash_native/runtime/asio_scheduler.hpp>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace clash_native::runtime {

class AsioRuntime {
  public:
    static constexpr std::size_t kDefaultWorkerCount = 4;
    using SerializedExecutor = AsioScheduler::SerializedExecutor;

    static AsioRuntime &instance();

    AsioRuntime(const AsioRuntime &) = delete;
    AsioRuntime &operator=(const AsioRuntime &) = delete;
    AsioRuntime(AsioRuntime &&) = delete;
    AsioRuntime &operator=(AsioRuntime &&) = delete;

    boost::asio::io_context &context() noexcept;
    SerializedExecutor serialized_executor() const noexcept;
    AsioScheduler scheduler() noexcept;
    bool running() const noexcept;
    std::size_t worker_count() const noexcept;

    // The worker count may only be changed while the singleton is stopped. Changing it
    // rebuilds the io_context so Asio receives the matching concurrency hint.
    void set_worker_count(std::size_t worker_count);

    void start();
    void stop();

  private:
    AsioRuntime();
    ~AsioRuntime();

    using WorkGuard = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;

    std::size_t worker_count_ = kDefaultWorkerCount;
    std::unique_ptr<boost::asio::io_context> io_context_;
    std::optional<SerializedExecutor> serialized_executor_;
    std::unique_ptr<WorkGuard> work_guard_;
    std::vector<std::thread> threads_;
    mutable std::mutex lifecycle_mutex_;
    std::atomic_bool started_{false};
    std::atomic_bool running_{false};
    bool stopping_ = false;
};

} // namespace clash_native::runtime
