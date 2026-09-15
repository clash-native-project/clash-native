#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <utility>

namespace clash_native::async {

template <typename T> class OneshotChannel {
  private:
    struct State {
        std::mutex mutex;
        std::condition_variable_any changed;
        std::optional<T> value;
        bool closed = false;
    };

  public:
    class Sender {
      public:
        Sender() = default;

        ~Sender() { close(); }

        Sender(const Sender &) = delete;
        Sender &operator=(const Sender &) = delete;

        Sender(Sender &&other) noexcept : state_(std::move(other.state_)) {}

        Sender &operator=(Sender &&other) noexcept {
            if (this != &other) {
                close();
                state_ = std::move(other.state_);
            }
            return *this;
        }

        bool send(T value) {
            if (!state_) {
                return false;
            }

            std::lock_guard lock(state_->mutex);
            if (state_->closed || state_->value.has_value()) {
                return false;
            }

            state_->value.emplace(std::move(value));
            state_->changed.notify_all();
            return true;
        }

        void close() noexcept {
            auto state = std::move(state_);
            if (!state) {
                return;
            }

            {
                std::lock_guard lock(state->mutex);
                state->closed = true;
                state->changed.notify_all();
            }
        }

      private:
        explicit Sender(std::shared_ptr<State> state) : state_(std::move(state)) {}

        std::shared_ptr<State> state_;

        friend class OneshotChannel;
    };

    class Receiver {
      public:
        Receiver() = default;

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
            const bool ready = state_->changed.wait(
                lock, stop_token, [this] { return state_->value.has_value() || state_->closed; });
            if (!ready || !state_->value.has_value()) {
                return std::nullopt;
            }

            auto value = std::move(state_->value);
            state_->closed = true;
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
                state->closed = true;
                state->changed.notify_all();
            }
        }

      private:
        explicit Receiver(std::shared_ptr<State> state) : state_(std::move(state)) {}

        std::shared_ptr<State> state_;

        friend class OneshotChannel;
    };

    static std::pair<Sender, Receiver> create() {
        auto state = std::make_shared<State>();
        return {Sender(state), Receiver(std::move(state))};
    }
};

} // namespace clash_native::async
