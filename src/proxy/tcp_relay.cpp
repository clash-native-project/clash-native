#include <clash_native/proxy/tcp_relay.hpp>

#include <clash_native/async/async.hpp>
#include <clash_native/async/timer.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>

#include <exec/when_any.hpp>
#include <stdexec/execution.hpp>

#include <chrono>
#include <exception>
#include <utility>

namespace clash_native::proxy {

namespace {

constexpr auto kRelayIdleTimeout = std::chrono::minutes(5);
// Watchdog granularity: recheck the deadline without busy-looping.
constexpr auto kIdlePollInterval = std::chrono::seconds(30);
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
    : left_(std::move(left)), right_(std::move(right)), completion_handler_(std::move(handler)) {}

void TcpRelay::stop() noexcept {
    // Teardown is close-driven: finish() closes both handles, which aborts
    // outstanding pulls, and the scope is joined implicitly by refcount --
    // run() holds `self` until the race drains. No stop source is used:
    // requesting stop while pull completions unwind synchronously destroys
    // state the iteration still needs, so close-driven teardown keeps every
    // path on refcounted state.
    finish();
}

void TcpRelay::launch(std::vector<std::uint8_t> initial_left_data) {
    auto self = shared_from_this();
    touch();
    // The scope owns only the supervisor (merge-shaped usage); the pumps
    // and watchdog are children of the supervisor's when_any race, so no
    // join state outlives the scope or touches it after completion. Do not
    // "simplify" this back to scope.on_empty() or request_stop(): an
    // earlier revision did both, and ASan caught a heap-use-after-free
    // where request_stop()'s synchronous callback iteration raced spawn
    // opstate self-deletion (and the join opstate could outlive the scope
    // member being joined on). Closing handles to abort pulls is prompt
    // enough here and keeps every teardown on refcounted state.
    //
    // The supervisor task must NOT run on the member scope_: run() holds
    // the last TcpRelay reference, so its completion would free the scope
    // before __complete touches scope->__active_ (ASan #194, same shape as
    // ProxySession::run_udp_control and Socks5UdpListener::run_response_loop
    // -- heap-use-after-free at async_scope.hpp:162). Detached launch keeps
    // the task's scope on the immortal heap scope instead.
    async::spawn_detached([self, data = std::move(initial_left_data)](
                              std::shared_ptr<async::DetachedScope> scope) mutable {
        (void)scope;
        return run(std::move(self), std::move(data));
    });
}
exec::task<void> TcpRelay::join_pumps(std::shared_ptr<TcpRelay> self,
                                      std::vector<std::uint8_t> initial) {
    auto peer = self;
    co_await stdexec::when_all(pump(std::move(self), true, std::move(initial)),
                               pump(std::move(peer), false, {}));
    co_return;
}

exec::task<void> TcpRelay::run(std::shared_ptr<TcpRelay> self,
                               std::vector<std::uint8_t> initial_left_data) {
    try {
        co_await exec::when_any(join_pumps(self, std::move(initial_left_data)) |
                                    stdexec::then([] { return 0; }),
                                idle_watchdog(self) | stdexec::then([] { return 1; }));
    } catch (...) {
        // Pumps never let failures escape (they close and return), so this
        // is unreachable in practice; a spawned sender completing with
        // error would terminate, hence the belt-and-suspenders swallow.
        self->finish();
    }
    self->finish();
    co_return;
}

exec::task<void> TcpRelay::pump(std::shared_ptr<TcpRelay> self, bool left_to_right,
                                std::vector<std::uint8_t> first_payload) {
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
            self->touch();
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
            self->touch();
        }
    } catch (...) {
        // Abort the peer direction promptly by closing (finish is
        // idempotent); the supervisor still delivers completion exactly
        // once below. Never let failures escape: a spawned sender
        // completing with error would terminate.
        self->finish();
    }
    co_return;
}

exec::task<void> TcpRelay::idle_watchdog(std::shared_ptr<TcpRelay> self) {
    auto executor = self->left_->executor();
    while (true) {
        std::chrono::steady_clock::time_point last;
        {
            std::lock_guard lock(self->activity_mutex_);
            last = self->last_activity_;
        }
        const auto deadline = last + kRelayIdleTimeout;
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            self->finish();
            co_return;
        }
        // Sleep in bounded slices so a fresh transfer pushes the deadline
        // out without needing a cancellable timer re-arm.
        const auto remaining = deadline - now;
        const auto slice = remaining < kIdlePollInterval ? remaining : kIdlePollInterval;
        try {
            co_await async::sleep_after(executor, slice);
        } catch (...) {
            co_return;
        }
        if (self->finished_.load(std::memory_order_acquire)) {
            co_return;
        }
    }
}

void TcpRelay::touch() {
    if (finished_.load(std::memory_order_acquire)) {
        return;
    }
    std::lock_guard lock(activity_mutex_);
    last_activity_ = std::chrono::steady_clock::now();
}

void TcpRelay::finish() noexcept {
    if (finished_.exchange(true, std::memory_order_acq_rel)) {
        return;
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
