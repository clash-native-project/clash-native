#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_query_service.hpp>
#include <clash_native/io/sender.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace clash_native::dns {

// Queries the HTTPS record for a name and returns the first ech SvcParam
// value (RFC 9460, key 5) as opaque ECHConfigList bytes for ECH. Only direct
// answers are considered; CNAME chasing is the caller's job. Completes
// set_value(Result<vector<uint8_t>>) with the config bytes, or
// set_error(exception_ptr) carrying a core::Error when none is published.
io::AnySender<core::Result<std::vector<std::uint8_t>>>
async_query_ech_config(DnsQueryService &query_service, std::string name,
                       std::optional<std::string> query_server_name = std::nullopt);

} // namespace clash_native::dns
