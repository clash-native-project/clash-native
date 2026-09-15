#pragma once

#include <clash_native/core/outbound.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include <boost/asio/steady_timer.hpp>

namespace clash_native::proxy {

struct RelayStats {
    std::uint64_t left_to_right_bytes = 0;
    std::uint64_t right_to_left_bytes = 0;
};

class TcpRelay final : public std::enable_shared_from_this<TcpRelay> {
  public:
    using CompletionHandler = std::function<void(RelayStats)>;

    static std::shared_ptr<TcpRelay> start(std::unique_ptr<core::StreamHandle> left,
                                           std::unique_ptr<core::StreamHandle> right,
                                           CompletionHandler handler,
                                           std::vector<std::uint8_t> initial_left_data = {});

    void stop() noexcept;

  private:
    TcpRelay(std::unique_ptr<core::StreamHandle> left, std::unique_ptr<core::StreamHandle> right,
             CompletionHandler handler);

    void start_impl(std::vector<std::uint8_t> initial_left_data);
    void reset_idle_timer();
    void read_left();
    void read_right();
    void write_initial_left_data();
    void finish() noexcept;
    void maybe_finish() noexcept;

    std::unique_ptr<core::StreamHandle> left_;
    std::unique_ptr<core::StreamHandle> right_;
    boost::asio::steady_timer idle_timer_;
    CompletionHandler completion_handler_;
    std::vector<std::uint8_t> initial_left_data_;
    std::vector<std::uint8_t> left_buffer_ = std::vector<std::uint8_t>(8192);
    std::vector<std::uint8_t> right_buffer_ = std::vector<std::uint8_t>(8192);
    RelayStats stats_;
    bool left_read_closed_ = false;
    bool right_read_closed_ = false;
    bool finished_ = false;
};

} // namespace clash_native::proxy
