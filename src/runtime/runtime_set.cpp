#include <clash_native/runtime/runtime_set.hpp>

#include <stdexcept>

namespace clash_native::runtime {

RuntimeSet::RuntimeSet(std::size_t worker_count) {
    if (worker_count == 0) {
        throw std::invalid_argument("RuntimeSet requires at least one worker");
    }

    runtimes_.reserve(worker_count);
    for (std::size_t index = 0; index < worker_count; ++index) {
        runtimes_.push_back(std::make_unique<AsioRuntime>());
    }
}

RuntimeSet::~RuntimeSet() { stop(); }

std::size_t RuntimeSet::size() const noexcept { return runtimes_.size(); }

AsioRuntime &RuntimeSet::runtime(std::size_t index) { return *runtimes_.at(index); }

AsioScheduler RuntimeSet::scheduler(std::size_t index) { return runtimes_.at(index)->scheduler(); }

void RuntimeSet::start() {
    for (const auto &runtime : runtimes_) {
        runtime->start();
    }
}

void RuntimeSet::stop() noexcept {
    for (const auto &runtime : runtimes_) {
        runtime->stop();
    }
}

} // namespace clash_native::runtime
