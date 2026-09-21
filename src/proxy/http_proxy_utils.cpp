#include "http_proxy_utils.hpp"

#include <boost/asio/ip/address.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>

namespace clash_native::proxy::http_detail {

namespace http = boost::beast::http;

std::optional<std::uint16_t> parse_port(std::string_view value) {
    if (value.empty()) {
        return std::nullopt;
    }

    unsigned int parsed = 0;
    const auto *begin = value.data();
    const auto *end = begin + value.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end || parsed == 0 || parsed > 65535) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(parsed);
}

std::optional<core::Destination> parse_http_authority(std::string_view authority) {
    std::string_view host;
    std::string_view port_text;

    if (!authority.empty() && authority.front() == '[') {
        const auto closing_bracket = authority.find(']');
        if (closing_bracket == std::string_view::npos || closing_bracket + 1 >= authority.size() ||
            authority[closing_bracket + 1] != ':') {
            return std::nullopt;
        }
        host = authority.substr(1, closing_bracket - 1);
        port_text = authority.substr(closing_bracket + 2);
    } else {
        const auto separator = authority.rfind(':');
        if (separator == std::string_view::npos || authority.find(':') != separator) {
            return std::nullopt;
        }
        host = authority.substr(0, separator);
        port_text = authority.substr(separator + 1);
    }

    const auto port = parse_port(port_text);
    if (!port || host.empty()) {
        return std::nullopt;
    }

    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(host, error);
    if (!error) {
        return core::Destination::address(address, *port);
    }
    return core::Destination::domain(std::string(host), *port);
}

bool is_http_token_character(unsigned char character) {
    constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
    return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9') ||
           punctuation.find(static_cast<char>(character)) != std::string_view::npos;
}

bool is_http_token(std::string_view value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return is_http_token_character(character);
    });
}

std::string lowercase_ascii(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

bool is_http_header(std::string_view name, std::string_view expected) {
    return name.size() == expected.size() &&
           std::equal(name.begin(), name.end(), expected.begin(),
                      [](unsigned char actual, unsigned char wanted) {
                          return static_cast<unsigned char>(std::tolower(actual)) == wanted;
                      });
}

std::string_view trim_http_whitespace(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

bool has_valid_http_credentials(std::string_view username, std::string_view password) {
    return username.find_first_of("\r\n") == std::string_view::npos &&
           password.find_first_of("\r\n") == std::string_view::npos;
}

bool basic_authorization_matches(std::string_view header, std::string_view username,
                                 std::string_view password) {
    header = trim_http_whitespace(header);
    const auto separator = header.find_first_of(" \t");
    if (separator == std::string_view::npos ||
        lowercase_ascii(header.substr(0, separator)) != "basic") {
        return false;
    }

    const auto encoded = trim_http_whitespace(header.substr(separator + 1));
    const auto decoded = core::base64_decode(encoded);
    if (!decoded) {
        return false;
    }
    return *decoded == std::string(username) + ':' + std::string(password);
}

bool collect_connection_options(const http::fields &fields,
                                std::unordered_set<std::string> &options) {
    for (const auto &field : fields) {
        if (!is_http_header(as_std_view(field.name_string()), "connection")) {
            continue;
        }
        auto value = as_std_view(field.value());
        while (true) {
            const auto comma = value.find(',');
            const auto option = trim_http_whitespace(value.substr(0, comma));
            if (!is_http_token(option)) {
                return false;
            }
            options.emplace(lowercase_ascii(option));
            if (comma == std::string_view::npos) {
                break;
            }
            value.remove_prefix(comma + 1);
        }
    }
    return true;
}

bool collect_upgrade_protocol(const http::fields &fields, std::string &protocol, bool &present) {
    for (const auto &field : fields) {
        if (!is_http_header(as_std_view(field.name_string()), "upgrade")) {
            continue;
        }
        present = true;
        auto value = as_std_view(field.value());
        while (true) {
            const auto comma = value.find(',');
            const auto token = trim_http_whitespace(value.substr(0, comma));
            if (!is_http_token(token) || !protocol.empty()) {
                return false;
            }
            protocol.assign(token);
            if (comma == std::string_view::npos) {
                break;
            }
            value.remove_prefix(comma + 1);
        }
    }
    return present && !protocol.empty();
}

bool is_hop_by_hop_or_proxy_header(std::string_view name,
                                   const std::unordered_set<std::string> &connection_options) {
    if (connection_options.contains(lowercase_ascii(name))) {
        return true;
    }
    constexpr std::array<std::string_view, 8> names{
        "connection",          "keep-alive", "proxy-connection",  "proxy-authenticate",
        "proxy-authorization", "te",         "transfer-encoding", "upgrade"};
    return std::any_of(names.begin(), names.end(), [name](std::string_view expected) {
        return is_http_header(name, expected);
    });
}

bool is_forbidden_trailer_field(std::string_view name) {
    constexpr std::array<std::string_view, 17> names{"authorization",
                                                     "connection",
                                                     "content-encoding",
                                                     "content-length",
                                                     "content-range",
                                                     "content-type",
                                                     "host",
                                                     "keep-alive",
                                                     "proxy-authenticate",
                                                     "proxy-authorization",
                                                     "te",
                                                     "trailer",
                                                     "transfer-encoding",
                                                     "upgrade",
                                                     "www-authenticate",
                                                     "cache-control",
                                                     "expect"};
    return std::any_of(names.begin(), names.end(), [name](std::string_view expected) {
        return is_http_header(name, expected);
    });
}

bool collect_declared_trailers(const http::fields &fields,
                               const std::unordered_set<std::string> &connection_options,
                               std::unordered_set<std::string> &declared_trailers,
                               std::vector<std::string> &trailer_names) {
    for (const auto &field : fields) {
        if (!is_http_header(as_std_view(field.name_string()), "trailer")) {
            continue;
        }
        auto value = as_std_view(field.value());
        while (true) {
            const auto comma = value.find(',');
            const auto name = trim_http_whitespace(value.substr(0, comma));
            if (!is_http_token(name)) {
                return false;
            }
            const auto normalized = lowercase_ascii(name);
            if (is_forbidden_trailer_field(normalized) || connection_options.contains(normalized)) {
                return false;
            }
            if (declared_trailers.emplace(normalized).second) {
                trailer_names.push_back(normalized);
            }
            if (comma == std::string_view::npos) {
                break;
            }
            value.remove_prefix(comma + 1);
        }
    }
    return true;
}

std::optional<ParsedHttpTarget> parse_http_absolute_target(std::string_view target) {
    if (target.size() < 7 || target.find_first_of("\\\r\n\t ") != std::string_view::npos ||
        target.find('#') != std::string_view::npos) {
        return std::nullopt;
    }

    const auto scheme_end = target.find("://");
    if (scheme_end == std::string_view::npos ||
        lowercase_ascii(target.substr(0, scheme_end)) != "http") {
        return std::nullopt;
    }
    target.remove_prefix(scheme_end + 3);
    const auto target_end = target.find_first_of("/?");
    const auto authority = target.substr(0, target_end);
    if (authority.empty() || authority.find('@') != std::string_view::npos ||
        authority.find_first_of("\\\r\n\t ") != std::string_view::npos) {
        return std::nullopt;
    }

    std::string_view host;
    std::string_view port_text;
    bool explicit_port = false;
    if (authority.front() == '[') {
        const auto closing = authority.find(']');
        if (closing == std::string_view::npos || closing == 1) {
            return std::nullopt;
        }
        host = authority.substr(1, closing - 1);
        if (closing + 1 < authority.size()) {
            if (authority[closing + 1] != ':') {
                return std::nullopt;
            }
            explicit_port = true;
            port_text = authority.substr(closing + 2);
        }
    } else {
        const auto colon = authority.find(':');
        if (colon != std::string_view::npos) {
            if (authority.find(':', colon + 1) != std::string_view::npos) {
                return std::nullopt;
            }
            host = authority.substr(0, colon);
            explicit_port = true;
            port_text = authority.substr(colon + 1);
        } else {
            host = authority;
        }
    }
    if (host.empty() || host.find_first_of("[]@%") != std::string_view::npos) {
        return std::nullopt;
    }

    std::uint16_t port = 80;
    if (explicit_port) {
        const auto parsed_port = parse_port(port_text);
        if (!parsed_port) {
            return std::nullopt;
        }
        port = *parsed_port;
    }

    boost::system::error_code address_error;
    const auto address = boost::asio::ip::make_address(host, address_error);
    auto destination = address_error ? core::Destination::domain(std::string(host), port)
                                     : core::Destination::address(address, port);

    std::string origin_target;
    if (target_end == std::string_view::npos) {
        origin_target = "/";
    } else {
        const auto suffix = target.substr(target_end);
        if (suffix.front() == '?') {
            origin_target.reserve(suffix.size() + 1);
            origin_target.push_back('/');
            origin_target.append(suffix);
        } else {
            origin_target.assign(suffix);
        }
    }
    if (origin_target.empty() || origin_target.front() != '/') {
        return std::nullopt;
    }
    for (std::size_t index = 0; index < origin_target.size(); ++index) {
        if (origin_target[index] == '%' &&
            (index + 2 >= origin_target.size() ||
             !std::isxdigit(static_cast<unsigned char>(origin_target[index + 1])) ||
             !std::isxdigit(static_cast<unsigned char>(origin_target[index + 2])))) {
            return std::nullopt;
        }
    }
    return ParsedHttpTarget{std::move(destination), std::string(authority),
                            std::move(origin_target), target_end == std::string_view::npos};
}

} // namespace clash_native::proxy::http_detail
