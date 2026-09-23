#pragma once

#include <clash_native/io/sender.hpp>
#include <clash_native/io/stream_handle.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace clash_native::io {

// Options for opening one logical bidirectional stream on an already
// established multiplexed carrier. Protocols that expose unidirectional
// streams must provide a protocol-specific API because StreamHandle represents
// a read/write stream.
struct MultiplexedStreamRequest {
    bool bidirectional = true;
};

// Opens logical bidirectional streams on an established carrier. open_stream completes
// set_value(unique_ptr<StreamHandle>) with the new stream, or set_error on
// failure (a failed open leaves the session usable unless it has also become
// retired). Cancellation travels through the stop token; cancel(id) remains
// for session-side aborts of opens the caller no longer tracks.
class MultiplexedSession {
  public:
    using StreamId = std::uint64_t;

    virtual AnySender<std::unique_ptr<StreamHandle>>
    open_stream(MultiplexedStreamRequest request,
                std::chrono::steady_clock::time_point deadline) = 0;
    virtual void cancel(StreamId stream_id) noexcept = 0;
    virtual std::size_t active_streams() const noexcept = 0;
    virtual std::optional<std::size_t> max_concurrent_streams() const noexcept = 0;
    virtual void stop() noexcept = 0;
    virtual bool retired() const noexcept = 0;
    virtual ~MultiplexedSession() = default;
};

} // namespace clash_native::io
