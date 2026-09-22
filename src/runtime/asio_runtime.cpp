#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/executor_work_guard.hpp>

#include <spdlog/spdlog.h>

#include <limits>
#include <stdexcept>
#include <utility>

namespace clash_native::runtime {

AsioRuntime::AsioRuntime()
    : io_context_(std::make_unique<boost::asio::io_context>(static_cast<int>(worker_count_))),
      serialized_executor_(std::in_place, boost::asio::make_strand(io_context_->get_executor())),
      work_guard_(std::make_unique<WorkGuard>(io_context_->get_executor())) {}

AsioRuntime::~AsioRuntime() { stop(); }

AsioRuntime &AsioRuntime::instance() {
    static AsioRuntime runtime;
    return runtime;
}

boost::asio::io_context &AsioRuntime::context() noexcept { return *io_context_; }

AsioRuntime::SerializedExecutor AsioRuntime::serialized_executor() const noexcept {
    return *serialized_executor_;
}

AsioScheduler AsioRuntime::scheduler() noexcept { return AsioScheduler(*serialized_executor_); }

bool AsioRuntime::running() const noexcept { return running_.load(); }

std::size_t AsioRuntime::worker_count() const noexcept {
    std::lock_guard lock(lifecycle_mutex_);
    return worker_count_;
}

void AsioRuntime::set_worker_count(std::size_t worker_count) {
    if (worker_count == 0) {
        throw std::invalid_argument("AsioRuntime requires at least one worker");
    }
    if (worker_count > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument("AsioRuntime worker count exceeds the Asio limit");
    }

    std::lock_guard lock(lifecycle_mutex_);
    if (started_.load() || stopping_) {
        throw std::logic_error("Cannot change AsioRuntime worker count while running");
    }

    if (worker_count == worker_count_) {
        return;
    }

    // The Asio concurrency hint is fixed when io_context is constructed. Build the
    // replacement objects before releasing the old ones so an allocation failure
    // leaves the stopped runtime usable with its previous configuration.
    auto new_io_context = std::make_unique<boost::asio::io_context>(static_cast<int>(worker_count));
    auto new_serialized_executor = std::optional<SerializedExecutor>(
        std::in_place, boost::asio::make_strand(new_io_context->get_executor()));
    auto new_work_guard = std::make_unique<WorkGuard>(new_io_context->get_executor());

    work_guard_.reset();
    serialized_executor_.reset();
    io_context_.reset();
    worker_count_ = worker_count;
    io_context_ = std::move(new_io_context);
    serialized_executor_ = std::move(new_serialized_executor);
    work_guard_ = std::move(new_work_guard);
}

void AsioRuntime::start() {
    std::lock_guard lock(lifecycle_mutex_);
    if (started_.load()) {
        spdlog::debug("Asio runtime start requested more than once");
        return;
    }
    if (stopping_) {
        throw std::logic_error("Cannot start AsioRuntime while it is stopping");
    }

    spdlog::debug("Starting Asio runtime with {} worker threads", worker_count_);
    io_context_->restart();
    if (!work_guard_) {
        work_guard_ = std::make_unique<WorkGuard>(io_context_->get_executor());
    }
    started_ = true;
    running_ = true;

    try {
        threads_.reserve(worker_count_);
        for (std::size_t index = 0; index < worker_count_; ++index) {
            threads_.emplace_back([this] { io_context_->run(); });
        }
    } catch (...) {
        work_guard_->reset();
        work_guard_.reset();
        for (auto &thread : threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        threads_.clear();
        started_ = false;
        running_ = false;
        throw;
    }
}

void AsioRuntime::stop() {
    std::vector<std::thread> threads;
    {
        std::lock_guard lock(lifecycle_mutex_);
        if (!started_.load()) {
            spdlog::debug("Asio runtime stop requested while already stopped");
            return;
        }

        spdlog::debug("Stopping Asio runtime");
        stopping_ = true;
        work_guard_->reset();
        work_guard_.reset();
        threads.swap(threads_);
    }

    for (auto &thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    {
        std::lock_guard lock(lifecycle_mutex_);
        started_ = false;
        running_ = false;
        stopping_ = false;
        io_context_->restart();
    }
    spdlog::debug("Asio runtime stopped");
}

} // namespace clash_native::runtime
