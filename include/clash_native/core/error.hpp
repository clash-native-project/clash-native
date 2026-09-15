#pragma once

#include <string>
#include <string_view>
#include <system_error>

namespace clash_native::core {

enum class ErrorCode {
    cancelled,
    resolution,
    endpoint_connection,
    carrier_handshake,
    authentication,
    protocol_framing,
    timeout,
    rejected,
    unsupported,
    transport_io,
};

constexpr std::string_view to_string(ErrorCode code) noexcept {
    switch (code) {
    case ErrorCode::cancelled:
        return "cancelled";
    case ErrorCode::resolution:
        return "resolution";
    case ErrorCode::endpoint_connection:
        return "endpoint_connection";
    case ErrorCode::carrier_handshake:
        return "carrier_handshake";
    case ErrorCode::authentication:
        return "authentication";
    case ErrorCode::protocol_framing:
        return "protocol_framing";
    case ErrorCode::timeout:
        return "timeout";
    case ErrorCode::rejected:
        return "rejected";
    case ErrorCode::unsupported:
        return "unsupported";
    case ErrorCode::transport_io:
        return "transport_io";
    }

    return "unknown";
}

struct Error {
    ErrorCode code;
    std::string context;
    std::error_code cause;
};

} // namespace clash_native::core
