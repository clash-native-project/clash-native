#pragma once

#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/runtime/asio_scheduler.hpp>

#include <cstddef>
#include <memory>
#include <vector>

namespace clash_native::runtime {

class RuntimeSet {
  public:
    static constexpr std::size_t kDefaultWorkerCount = 4;

    explicit RuntimeSet(std::size_t worker_count = kDefaultWorkerCount);
    ~RuntimeSet();

    RuntimeSet(const RuntimeSet &) = delete;
    RuntimeSet &operator=(const RuntimeSet &) = delete;
    RuntimeSet(RuntimeSet &&) = delete;
    RuntimeSet &operator=(RuntimeSet &&) = delete;

    std::size_t size() const noexcept;
    AsioRuntime &runtime(std::size_t index);
    AsioScheduler scheduler(std::size_t index);

    void start();
    void stop() noexcept;

  private:
    std::vector<std::unique_ptr<AsioRuntime>> runtimes_;
};

} // namespace clash_native::runtime
