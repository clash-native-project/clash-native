#pragma once

#include <clash_native/io/stream_handle.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include <boost/asio/steady_timer.hpp>
#include <exec/async_scope.hpp>
#include <exec/task.hpp>

namespace clash_native::proxy {

struct RelayStats {
    std::uint64_t left_to_right_bytes = 0;
    std::uint64_t right_to_left_bytes = 0;
};

class TcpRelay final : public std::enable_shared_from_this<TcpRelay> {
  public:
    using CompletionHandler = std::function<void(RelayStats)>;

    static std::shared_ptr<TcpRelay> start(std::unique_ptr<io::StreamHandle> left,
                                           std::unique_ptr<io::StreamHandle> right,
                                           CompletionHandler handler,
                                           std::vector<std::uint8_t> initial_left_data = {});

    void stop() noexcept;

  private:
    TcpRelay(std::unique_ptr<io::StreamHandle> left, std::unique_ptr<io::StreamHandle> right,
             CompletionHandler handler);

    void launch(std::vector<std::uint8_t> initial_left_data);
    // One direction of the relay. Always terminates with a value: clean EOF
    // shuts down the peer send side and returns, failures request scope
    // stop (aborting the peer promptly) and return. Never lets failures
    // escape: a spawned sender completing with error would terminate.
    // Cancellation unwinds past the catch and completes stopped.
    exec::task<void> pump(std::shared_ptr<TcpRelay> self, bool left_to_right,
                          std::vector<std::uint8_t> first_payload);
    void note_done() noexcept;
    void poke();
    void finish() noexcept;

    std::unique_ptr<io::StreamHandle> left_;
    std::unique_ptr<io::StreamHandle> right_;
    boost::asio::steady_timer idle_timer_;
    // Asio timers are not thread-safe: pumps poke from whatever thread
    // completes each transfer while finish() cancels from the stop path.
    std::mutex timer_mutex_;
    exec::async_scope scope_;
    CompletionHandler completion_handler_;
    RelayStats stats_;
    std::atomic<int> outstanding_{0};
    std::atomic_bool finished_{false};
};

} // namespace clash_native::proxy
