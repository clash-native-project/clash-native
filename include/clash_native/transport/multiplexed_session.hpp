#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace clash_native::transport {

// Options for opening one logical bidirectional stream on an already
// established multiplexed carrier. Protocols that expose unidirectional
// streams must provide a protocol-specific API because StreamHandle represents
// a read/write stream.
struct MultiplexedStreamRequest {
    bool bidirectional = true;
};

class MultiplexedSession {
  public:
    using StreamId = std::uint64_t;
    using StreamHandler = std::function<void(core::Result<std::unique_ptr<core::StreamHandle>>)>;

    // The callback is invoked exactly once. A failed result means that the
    // logical stream was not opened and the session remains usable unless it
    // has also become retired.
    virtual StreamId open_stream(MultiplexedStreamRequest request,
                                 std::chrono::steady_clock::time_point deadline,
                                 StreamHandler handler) = 0;
    virtual void cancel(StreamId stream_id) noexcept = 0;
    virtual std::size_t active_streams() const noexcept = 0;
    virtual std::optional<std::size_t> max_concurrent_streams() const noexcept = 0;
    virtual void stop() noexcept = 0;
    virtual bool retired() const noexcept = 0;
    virtual ~MultiplexedSession() = default;
};

} // namespace clash_native::transport
