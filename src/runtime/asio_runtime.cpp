#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/executor_work_guard.hpp>

#include <spdlog/spdlog.h>

#include <stdexcept>

namespace clash_native::runtime {

AsioRuntime::AsioRuntime()
    : io_context_(), work_guard_(boost::asio::make_work_guard(io_context_)) {}

AsioRuntime::~AsioRuntime() { stop(); }

boost::asio::io_context &AsioRuntime::context() noexcept { return io_context_; }

AsioScheduler AsioRuntime::scheduler() noexcept {
    return AsioScheduler(io_context_.get_executor());
}

bool AsioRuntime::running() const noexcept { return running_.load(); }

void AsioRuntime::start() {
    if (stopped_.load()) {
        throw std::logic_error("Cannot start a stopped AsioRuntime");
    }

    if (started_.exchange(true)) {
        spdlog::debug("Asio runtime start requested more than once");
        return;
    }

    spdlog::debug("Starting Asio runtime");
    running_ = true;
    try {
        thread_ = std::thread([this] {
            io_context_.run();
            running_ = false;
        });
    } catch (...) {
        running_ = false;
        started_ = false;
        throw;
    }
}

void AsioRuntime::stop() {
    if (stopped_.exchange(true)) {
        spdlog::debug("Asio runtime stop requested more than once");
        return;
    }

    spdlog::debug("Stopping Asio runtime");
    work_guard_.reset();

    if (thread_.joinable()) {
        thread_.join();
    }

    running_ = false;
    spdlog::debug("Asio runtime stopped");
}

} // namespace clash_native::runtime
