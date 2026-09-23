#include <clash_native/proxy/tcp_relay.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>

#include <chrono>
#include <exception>
#include <utility>

namespace clash_native::proxy {

namespace {

constexpr auto kRelayIdleTimeout = std::chrono::minutes(5);
constexpr std::size_t kRelayBufferSize = 8192;

} // namespace

std::shared_ptr<TcpRelay> TcpRelay::start(std::unique_ptr<io::StreamHandle> left,
                                          std::unique_ptr<io::StreamHandle> right,
                                          CompletionHandler handler,
                                          std::vector<std::uint8_t> initial_left_data) {
    auto relay = std::shared_ptr<TcpRelay>(
        new TcpRelay(std::move(left), std::move(right), std::move(handler)));
    relay->launch(std::move(initial_left_data));
    return relay;
}

TcpRelay::TcpRelay(std::unique_ptr<io::StreamHandle> left, std::unique_ptr<io::StreamHandle> right,
                   CompletionHandler handler)
    : left_(std::move(left)), right_(std::move(right)), idle_timer_(left_->executor()),
      completion_handler_(std::move(handler)) {}

void TcpRelay::stop() noexcept {
    // Teardown is close-driven (like the old relay): finish() closes both
    // handles, which aborts outstanding pulls, and joining delivers
    // completion. No stop source is used anywhere: requesting stop while
    // pull completions unwind synchronously destroys state the iteration
    // still needs, so the token stays permanently unrequested and the scope
    // only owns the spawned pumps.
    finish();
}

void TcpRelay::launch(std::vector<std::uint8_t> initial_left_data) {
    auto self = shared_from_this();
    outstanding_.store(2, std::memory_order_relaxed);
    poke();
    // The scope only owns the spawned pumps (merge-shaped usage); joining
    // is an atomic count below, and teardown is close-driven, so no join
    // state ever outlives the scope or touches it after completion.
    // Do not "simplify" this back to scope.on_empty() or request_stop():
    // an earlier revision did both, and ASan caught a heap-use-after-free
    // where request_stop()'s synchronous callback iteration raced spawn
    // opstate self-deletion (and the join opstate could outlive the scope
    // member being joined on). Closing handles to abort pulls is prompt
    // enough here and keeps every teardown on refcounted state.
    scope_.spawn(pump(self, true, std::move(initial_left_data)));
    scope_.spawn(pump(self, false, {}));
}

exec::task<void> TcpRelay::pump(std::shared_ptr<TcpRelay> self, bool left_to_right,
                                std::vector<std::uint8_t> first_payload) {
    struct Guard {
        std::shared_ptr<TcpRelay> owner;
        ~Guard() { owner->note_done(); }
    };
    // Runs on every exit path, including cancellation unwinding past the
    // catch below, so joining never depends on which terminal fired.
    Guard guard{self};
    io::StreamHandle *from = left_to_right ? self->left_.get() : self->right_.get();
    io::StreamHandle *to = left_to_right ? self->right_.get() : self->left_.get();
    std::uint64_t *counter =
        left_to_right ? &self->stats_.left_to_right_bytes : &self->stats_.right_to_left_bytes;
    try {
        if (!first_payload.empty()) {
            co_await to->async_write(boost::asio::buffer(first_payload));
            if (self->finished_.load(std::memory_order_acquire)) {
                co_return;
            }
            *counter += first_payload.size();
            self->poke();
        }
        std::vector<std::uint8_t> buffer(kRelayBufferSize);
        while (true) {
            auto chunk = co_await from->async_read_some(boost::asio::buffer(buffer));
            if (!chunk) {
                boost::system::error_code ignored;
                to->shutdown_send(ignored);
                co_return;
            }
            co_await to->async_write(boost::asio::buffer(buffer.data(), *chunk));
            if (self->finished_.load(std::memory_order_acquire)) {
                co_return;
            }
            *counter += *chunk;
            self->poke();
        }
    } catch (...) {
        // Abort the peer direction promptly by closing (finish is
        // idempotent); joining still delivers completion exactly once.
        // Never let failures escape: a spawned sender completing with
        // error would terminate.
        self->finish();
    }
    co_return;
}

void TcpRelay::note_done() noexcept {
    if (outstanding_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        finish();
    }
}

void TcpRelay::poke() {
    if (finished_.load(std::memory_order_acquire)) {
        return;
    }
    std::lock_guard lock(timer_mutex_);
    if (finished_.load(std::memory_order_acquire)) {
        return;
    }
    idle_timer_.expires_after(kRelayIdleTimeout);
    // Kept callback-style like every other timer leaf in the tree: expiry
    // aborts the relay through the scope, re-arming cancels the wait.
    idle_timer_.async_wait([self = shared_from_this()](const boost::system::error_code &error) {
        if (!error) {
            self->finish();
        }
    });
}

void TcpRelay::finish() noexcept {
    if (finished_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    {
        std::lock_guard lock(timer_mutex_);
        idle_timer_.cancel();
    }

    if (left_) {
        left_->close();
    }
    if (right_) {
        right_->close();
    }

    if (completion_handler_) {
        auto handler = std::move(completion_handler_);
        handler(stats_);
    }
}

} // namespace clash_native::proxy
