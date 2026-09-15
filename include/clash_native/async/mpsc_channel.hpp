#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <utility>

namespace clash_native::async {

template <typename T> class MpscChannel {
  public:
    static constexpr std::size_t kUnbounded = std::numeric_limits<std::size_t>::max();

  private:
    struct State {
        explicit State(std::size_t capacity_value) : capacity(capacity_value) {}

        std::mutex mutex;
        std::condition_variable_any changed;
        std::deque<T> queue;
        std::optional<T> rendezvous_value;
        std::size_t capacity;
        std::size_t waiting_receivers = 0;
        std::size_t producer_count = 0;
        bool receiver_alive = true;
        bool closed = false;
    };

  public:
    class Sender {
      public:
        Sender() = default;

        explicit Sender(std::shared_ptr<State> state) : state_(std::move(state)) {
            if (state_) {
                std::lock_guard lock(state_->mutex);
                ++state_->producer_count;
            }
        }

        ~Sender() { release(); }

        Sender(const Sender &other) : Sender(other.state_) {}

        Sender &operator=(const Sender &other) {
            if (this != &other) {
                release();
                state_ = other.state_;
                if (state_) {
                    std::lock_guard lock(state_->mutex);
                    ++state_->producer_count;
                }
            }
            return *this;
        }

        Sender(Sender &&other) noexcept : state_(std::move(other.state_)) {}

        Sender &operator=(Sender &&other) noexcept {
            if (this != &other) {
                release();
                state_ = std::move(other.state_);
            }
            return *this;
        }

        bool send(T value, std::stop_token stop_token = {}) {
            if (!state_) {
                return false;
            }

            std::unique_lock lock(state_->mutex);
            if (state_->capacity == 0) {
                return send_rendezvous(std::move(value), stop_token, lock);
            }

            const auto has_space = [this] {
                return state_->capacity == kUnbounded || state_->queue.size() < state_->capacity;
            };
            const bool ready = state_->changed.wait(lock, stop_token, [this, &has_space] {
                return state_->closed || !state_->receiver_alive || has_space();
            });
            if (!ready || state_->closed || !state_->receiver_alive) {
                return false;
            }

            state_->queue.push_back(std::move(value));
            state_->changed.notify_all();
            return true;
        }

        void close() noexcept {
            auto state = state_;
            if (!state) {
                return;
            }

            std::lock_guard lock(state->mutex);
            state->closed = true;
            state->changed.notify_all();
        }

      private:
        void release() noexcept {
            auto state = std::move(state_);
            if (!state) {
                return;
            }

            {
                std::lock_guard lock(state->mutex);
                if (state->producer_count > 0) {
                    --state->producer_count;
                }
                if (state->producer_count == 0) {
                    state->closed = true;
                }
                state->changed.notify_all();
            }
        }

        bool send_rendezvous(T value, std::stop_token stop_token,
                             std::unique_lock<std::mutex> &lock) {
            const bool receiver_waiting = state_->changed.wait(lock, stop_token, [this] {
                return state_->closed || !state_->receiver_alive ||
                       (state_->waiting_receivers > 0 && !state_->rendezvous_value.has_value());
            });
            if (!receiver_waiting || state_->closed || !state_->receiver_alive) {
                return false;
            }

            state_->rendezvous_value.emplace(std::move(value));
            state_->changed.notify_all();

            const bool delivered = state_->changed.wait(lock, stop_token, [this] {
                return !state_->rendezvous_value.has_value() || !state_->receiver_alive;
            });
            if (!delivered && state_->rendezvous_value.has_value()) {
                state_->rendezvous_value.reset();
                state_->changed.notify_all();
                return false;
            }

            if (state_->rendezvous_value.has_value()) {
                state_->rendezvous_value.reset();
                state_->changed.notify_all();
                return false;
            }
            return true;
        }

        std::shared_ptr<State> state_;

        friend class MpscChannel;
    };

    class Receiver {
      public:
        Receiver() = default;

        explicit Receiver(std::shared_ptr<State> state) : state_(std::move(state)) {}

        ~Receiver() { close(); }

        Receiver(const Receiver &) = delete;
        Receiver &operator=(const Receiver &) = delete;

        Receiver(Receiver &&other) noexcept : state_(std::move(other.state_)) {}

        Receiver &operator=(Receiver &&other) noexcept {
            if (this != &other) {
                close();
                state_ = std::move(other.state_);
            }
            return *this;
        }

        std::optional<T> receive(std::stop_token stop_token = {}) {
            if (!state_) {
                return std::nullopt;
            }

            std::unique_lock lock(state_->mutex);
            if (state_->capacity == 0) {
                return receive_rendezvous(stop_token, lock);
            }

            const bool ready = state_->changed.wait(lock, stop_token, [this] {
                return !state_->queue.empty() || state_->closed || state_->producer_count == 0;
            });
            if (!ready || state_->queue.empty()) {
                return std::nullopt;
            }

            T value = std::move(state_->queue.front());
            state_->queue.pop_front();
            state_->changed.notify_all();
            return value;
        }

        void close() noexcept {
            auto state = std::move(state_);
            if (!state) {
                return;
            }

            {
                std::lock_guard lock(state->mutex);
                state->receiver_alive = false;
                state->closed = true;
                state->changed.notify_all();
            }
        }

      private:
        std::optional<T> receive_rendezvous(std::stop_token stop_token,
                                            std::unique_lock<std::mutex> &lock) {
            ++state_->waiting_receivers;
            state_->changed.notify_all();

            const bool ready = state_->changed.wait(lock, stop_token, [this] {
                return state_->rendezvous_value.has_value() || state_->closed ||
                       state_->producer_count == 0;
            });
            if (!ready || !state_->rendezvous_value.has_value()) {
                --state_->waiting_receivers;
                state_->changed.notify_all();
                return std::nullopt;
            }

            T value = std::move(*state_->rendezvous_value);
            state_->rendezvous_value.reset();
            --state_->waiting_receivers;
            state_->changed.notify_all();
            return value;
        }

        std::shared_ptr<State> state_;

        friend class MpscChannel;
    };

    static std::pair<Sender, Receiver> create(std::size_t capacity) {
        auto state = std::make_shared<State>(capacity);
        return {Sender(state), Receiver(std::move(state))};
    }
};

} // namespace clash_native::async
