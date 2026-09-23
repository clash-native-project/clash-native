#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/io/stream_handle.hpp>

#include <memory>

namespace clash_native::transport::shadowsocks {

// Wraps a byte stream in the framed Snappy format emitted by Go's
// snappy.NewBufferedWriter/NewReader pair used by Mihomo kcptun.
core::Result<std::unique_ptr<io::StreamHandle>>
make_kcptun_snappy_stream(std::unique_ptr<io::StreamHandle> transport);

} // namespace clash_native::transport::shadowsocks
