#pragma once

// Factories for the sender-native HTTP exchange sessions. Each session takes
// ownership of its carrier; calls must use the carrier's executor.

#include <clash_native/core/error.hpp>
#include <clash_native/io/exchange_session.hpp>

#include <functional>
#include <memory>

namespace clash_native::transport {

class QuicClientConnection;

std::shared_ptr<io::ExchangeSession>
make_http1_exchange_session(std::unique_ptr<io::StreamHandle> stream);
std::shared_ptr<io::ExchangeSession>
make_http2_exchange_session(std::unique_ptr<io::StreamHandle> stream);
std::shared_ptr<io::ExchangeSession>
make_http3_exchange_session(std::shared_ptr<QuicClientConnection> connection,
                            std::function<void(core::Error)> failure_handler = {});

} // namespace clash_native::transport
