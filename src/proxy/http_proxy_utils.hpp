#pragma once

#include <clash_native/core/base64.hpp>
#include <clash_native/core/outbound.hpp>

#include <boost/beast/http.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace clash_native::proxy::http_detail {

namespace http = boost::beast::http;

template <class StringView> std::string_view as_std_view(const StringView &value) {
    return {value.data(), value.size()};
}

template <class StringView> std::string copy_view(const StringView &value) {
    return std::string(value.data(), value.size());
}

struct ParsedHttpTarget {
    core::Destination destination;
    std::string authority;
    std::string origin_target;
    bool empty_path_and_query = false;
};

std::optional<std::uint16_t> parse_port(std::string_view value);
std::optional<core::Destination> parse_http_authority(std::string_view authority);
bool is_http_token(std::string_view value);
std::string lowercase_ascii(std::string_view value);
bool is_http_header(std::string_view name, std::string_view expected);
std::string_view trim_http_whitespace(std::string_view value);
bool has_valid_http_credentials(std::string_view username, std::string_view password);
bool basic_authorization_matches(std::string_view header, std::string_view username,
                                 std::string_view password);
bool collect_connection_options(const http::fields &fields,
                                std::unordered_set<std::string> &options);
bool collect_upgrade_protocol(const http::fields &fields, std::string &protocol, bool &present);
bool is_hop_by_hop_or_proxy_header(std::string_view name,
                                   const std::unordered_set<std::string> &connection_options);
bool is_forbidden_trailer_field(std::string_view name);
bool collect_declared_trailers(const http::fields &fields,
                               const std::unordered_set<std::string> &connection_options,
                               std::unordered_set<std::string> &declared_trailers,
                               std::vector<std::string> &trailer_names);
std::optional<ParsedHttpTarget> parse_http_absolute_target(std::string_view target);

} // namespace clash_native::proxy::http_detail
