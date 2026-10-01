#pragma once

#include <clash_native/io/stream_handle.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include <stdexec/execution.hpp>

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
    // Supervises the relay: races the joined pump pair against the idle
    // watchdog and delivers the final stats through the completion handler,
    // which stays a plain value callback (not a pump). Always terminates
    // with a value so the scope spawn is safe; pump failures surface as
    // early termination and still deliver stats below.
    static stdexec::task<void> run(std::shared_ptr<TcpRelay> self,
                                   std::vector<std::uint8_t> initial_left_data);
    static stdexec::task<void> join_pumps(std::shared_ptr<TcpRelay> self,
                                          std::vector<std::uint8_t> initial_left_data);
    // One direction of the relay. Always terminates with a value: clean EOF
    // shuts down the peer send side and returns (the sibling keeps going
    // until its own EOF), failures close the relay to abort the peer
    // promptly and return. Never lets failures escape: an error-terminated
    // branch would unwind the whole race. Cancellation unwinds past the
    // catch and completes stopped.
    static stdexec::task<void> pump(std::shared_ptr<TcpRelay> self, bool left_to_right,
                                    std::vector<std::uint8_t> first_payload);
    // Completes once no bytes have flowed for the idle timeout. Recomputes
    // the deadline from the pumps' activity stamps instead of re-arming a
    // callback timer, so the whole relay composes with stop/when_any.
    static stdexec::task<void> idle_watchdog(std::shared_ptr<TcpRelay> self);
    void touch();
    void finish() noexcept;

    std::unique_ptr<io::StreamHandle> left_;
    std::unique_ptr<io::StreamHandle> right_;
    // Written by the pumps on every successful transfer, read by the
    // watchdog. Plain mutex: only touched around transfers, never held
    // across an await.
    std::mutex activity_mutex_;
    std::chrono::steady_clock::time_point last_activity_{std::chrono::steady_clock::now()};
    // No member scope: the supervisor runs detached (immortal heap scope)
    // so its completion cannot free the scope it completes into (#194).
    CompletionHandler completion_handler_;
    RelayStats stats_;
    std::atomic_bool finished_{false};
};

} // namespace clash_native::proxy
