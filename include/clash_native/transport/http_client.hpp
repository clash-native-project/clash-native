#pragma once

// Compatibility include for clients of the pre-ExchangeSession API. New code
// should include exchange_session.hpp and use its generic exchange vocabulary.
#include <clash_native/transport/exchange_session.hpp>

#include <utility>

namespace clash_native::transport {

using HttpHeader = ExchangeField;
using HttpRequest = ExchangeRequest;
using HttpResponse = ExchangeResponse;
using HttpBodyStream = ExchangeBodyStream;
using HttpStreamingRequest = StreamingExchangeRequest;
using HttpStreamingResponse = StreamingExchangeResponse;
using HttpTunnelMode = StreamUpgradeMode;
using HttpTunnelRequest = StreamUpgradeRequest;
using HttpTunnelResponse = StreamUpgradeResponse;
using HttpClientSession = ExchangeSession;

inline std::shared_ptr<ExchangeSession>
make_http1_client_session(std::unique_ptr<core::StreamHandle> stream) {
    return make_http1_exchange_session(std::move(stream));
}

inline std::shared_ptr<ExchangeSession>
make_http2_client_session(std::unique_ptr<core::StreamHandle> stream) {
    return make_http2_exchange_session(std::move(stream));
}

inline std::shared_ptr<ExchangeSession>
make_http3_client_session(std::shared_ptr<QuicClientConnection> connection,
                          std::function<void(core::Error)> failure_handler = {}) {
    return make_http3_exchange_session(std::move(connection), std::move(failure_handler));
}

} // namespace clash_native::transport
