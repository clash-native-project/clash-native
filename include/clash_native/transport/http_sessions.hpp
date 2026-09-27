#pragma once

// Factories for the sender-native HTTP exchange sessions. Each session takes
// ownership of its carrier; calls must use the carrier's executor.

#include <clash_native/async/oneshot.hpp>
#include <clash_native/core/error.hpp>
#include <clash_native/io/exchange_session.hpp>

#include <boost/asio/post.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <utility>

namespace clash_native::transport {

class QuicClientConnection;

struct Http2SessionOptions {
    // PING keepalive interval, zero disables (Mihomo PingInterval
    // semantics). Two unacknowledged intervals fail the connection.
    std::chrono::milliseconds ping_interval{0};
};

std::shared_ptr<io::ExchangeSession>
make_http1_exchange_session(std::unique_ptr<io::StreamHandle> stream);
std::shared_ptr<io::ExchangeSession>
make_http2_exchange_session(std::unique_ptr<io::StreamHandle> stream,
                            Http2SessionOptions options = {});
std::shared_ptr<io::ExchangeSession>
make_http3_exchange_session(std::shared_ptr<QuicClientConnection> connection,
                            std::function<void(core::Error)> failure_handler = {});

// Completes a oneshot exchange terminal on the session executor. The send
// itself is thread-safe; the hop only routes the receiver's continuation
// back onto the owning strand.
template <typename Executor, typename Terminal>
void post_terminal(Executor &&executor, async::oneshot::Sender<Terminal> sender, Terminal result) {
    boost::asio::post(std::forward<Executor>(executor),
                      [sender = std::move(sender), result = std::move(result)]() mutable {
                          sender.send(std::move(result));
                      });
}

} // namespace clash_native::transport
