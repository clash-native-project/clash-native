#include <clash_native/dns/dns_server.hpp>
#include <clash_native/proxy/proxy_server.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/signal_set.hpp>

#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <functional>
#include <future>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace {

std::optional<std::string> environment_value(const char *name) {
#ifdef _WIN32
    char *value = nullptr;
    std::size_t value_size = 0;
    if (_dupenv_s(&value, &value_size, name) != 0 || value == nullptr) {
        return std::nullopt;
    }
    std::string result(value);
    std::free(value);
    return result;
#else
    const auto *value = std::getenv(name);
    return value == nullptr ? std::nullopt : std::optional<std::string>(value);
#endif
}

std::optional<clash_native::dns::DnsUpstreamConfig> parse_upstream_config(const char *value) {
    if (value == nullptr) {
        return std::nullopt;
    }

    std::string_view text(value);
    auto mode = clash_native::dns::DnsTransportMode::plain;
    const auto scheme_separator = text.find("://");
    if (scheme_separator != std::string_view::npos) {
        const auto scheme = text.substr(0, scheme_separator);
        if (scheme == "doh1") {
            mode = clash_native::dns::DnsTransportMode::doh1;
        } else if (scheme == "doq") {
            mode = clash_native::dns::DnsTransportMode::doq;
        } else if (scheme == "doh3") {
            mode = clash_native::dns::DnsTransportMode::doh3;
        } else {
            return std::nullopt;
        }
        text.remove_prefix(scheme_separator + 3);
    }

    std::string doh_path = "/dns-query";
    if (mode == clash_native::dns::DnsTransportMode::doh1 ||
        mode == clash_native::dns::DnsTransportMode::doh3) {
        const auto path_separator = text.find('/');
        if (path_separator != std::string_view::npos) {
            doh_path = std::string(text.substr(path_separator));
            text = text.substr(0, path_separator);
        }
    }

    std::string_view host;
    std::string_view port_text;
    if (!text.empty() && text.front() == '[') {
        const auto closing_bracket = text.find(']');
        if (closing_bracket == std::string_view::npos || closing_bracket + 2 > text.size() ||
            text[closing_bracket + 1] != ':') {
            return std::nullopt;
        }
        host = text.substr(1, closing_bracket - 1);
        port_text = text.substr(closing_bracket + 2);
    } else {
        const auto separator = text.rfind(':');
        if (separator == std::string_view::npos || separator == 0 || separator + 1 == text.size()) {
            return std::nullopt;
        }
        host = text.substr(0, separator);
        port_text = text.substr(separator + 1);
    }
    if (host.empty() || port_text.empty()) {
        return std::nullopt;
    }

    std::uint16_t port = 0;
    const auto parse_result =
        std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (parse_result.ec != std::errc{} || parse_result.ptr != port_text.data() + port_text.size() ||
        port == 0) {
        return std::nullopt;
    }

    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(host, error);
    const auto endpoint_address =
        error ? boost::asio::ip::address(boost::asio::ip::address_v4::any()) : address;
    clash_native::dns::DnsUpstreamConfig config{
        boost::asio::ip::udp::endpoint(endpoint_address, port), std::chrono::seconds(2),
        boost::asio::ip::tcp::endpoint(endpoint_address, port)};
    config.mode = mode;
    config.server_name = std::string(host);
    config.doh_path = std::move(doh_path);
    if (mode == clash_native::dns::DnsTransportMode::doh1 ||
        mode == clash_native::dns::DnsTransportMode::doh3) {
        config.doh_authority = std::string(host);
        if (port != 443) {
            config.doh_authority += ':' + std::to_string(port);
        }
    }
    if (error) {
        config.hostname = std::string(host);
    }
    return config;
}

} // namespace

int main(int argc, char **) {
    if (argc != 1) {
        std::cerr << "clash-native-test-host does not accept command-line arguments.\n";
        return 2;
    }

    try {
        clash_native::runtime::AsioRuntime runtime;
        std::shared_ptr<clash_native::dns::ResolverService> resolver;
        std::unique_ptr<clash_native::dns::DnsServer> dns_server;
        std::shared_ptr<clash_native::dns::FakeIpStore> fake_ip_store;
        std::function<bool(std::string_view)> fake_ip_filter;
        if (const auto upstream_text = environment_value("CLASH_NATIVE_DNS_UPSTREAM");
            upstream_text) {
            auto upstream = parse_upstream_config(upstream_text->c_str());
            if (!upstream) {
                throw std::runtime_error("CLASH_NATIVE_DNS_UPSTREAM must be address:port or a "
                                         "supported doh1://, doq://, or doh3:// endpoint");
            }
            if (const auto verify_peer = environment_value("CLASH_NATIVE_DNS_VERIFY_PEER");
                verify_peer &&
                (*verify_peer == "0" || *verify_peer == "false" || *verify_peer == "FALSE")) {
                upstream->verify_peer = false;
            }

            resolver =
                std::make_shared<clash_native::dns::ResolverService>(runtime, std::move(*upstream));
            dns_server = std::make_unique<clash_native::dns::DnsServer>(
                runtime, *resolver,
                boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 0),
                boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
        }
        if (const auto fake_ip_domain = environment_value("CLASH_NATIVE_FAKE_IP_DOMAIN");
            fake_ip_domain) {
            if (fake_ip_domain->empty()) {
                throw std::runtime_error("CLASH_NATIVE_FAKE_IP_DOMAIN must not be empty");
            }
            fake_ip_store = std::make_shared<clash_native::dns::FakeIpStore>(
                boost::asio::ip::make_address_v4("198.18.0.0"), 24, 254);
            const auto domain = clash_native::dns::normalize_name(*fake_ip_domain);
            fake_ip_filter = [domain](std::string_view name) {
                return clash_native::dns::normalize_name(name) == domain;
            };
        }
        if (dns_server) {
            dns_server->set_fake_ip_store(fake_ip_store, fake_ip_filter);
        }

        clash_native::proxy::ProxyServer proxy(runtime,
                                               {boost::asio::ip::address_v4::loopback(), 0});
        if (resolver) {
            proxy.set_resolver(resolver);
        }
        if (fake_ip_store) {
            proxy.set_fake_ip_store(fake_ip_store);
        }
        boost::asio::signal_set signals(runtime.context(), SIGINT, SIGTERM);
        std::promise<void> stopped;
        auto stopped_future = stopped.get_future();

        signals.async_wait([&proxy, &dns_server, &stopped](const boost::system::error_code &, int) {
            if (dns_server) {
                dns_server->stop();
            }
            proxy.stop();
            stopped.set_value();
        });

        runtime.start();
        if (dns_server) {
            const auto dns_start_result = dns_server->start();
            if (!dns_start_result) {
                runtime.stop();
                const auto &error = dns_start_result.error();
                if (error.cause) {
                    throw std::system_error(error.cause, error.context);
                }
                throw std::runtime_error(error.context);
            }
        }
        const auto start_result = proxy.start();
        if (!start_result) {
            if (dns_server) {
                dns_server->stop();
            }
            runtime.stop();
            const auto &error = start_result.error();
            if (error.cause) {
                throw std::system_error(error.cause, error.context);
            }
            throw std::runtime_error(error.context);
        }

        const auto endpoint = proxy.endpoint();
        std::cout << "clash-native-test-host ready " << endpoint.address().to_string() << ":"
                  << endpoint.port() << std::endl;
        if (dns_server) {
            const auto udp_endpoint = dns_server->udp_endpoint();
            const auto tcp_endpoint = dns_server->tcp_endpoint();
            std::cout << "clash-native-test-host dns-ready udp="
                      << udp_endpoint.address().to_string() << ":" << udp_endpoint.port()
                      << " tcp=" << tcp_endpoint.address().to_string() << ":" << tcp_endpoint.port()
                      << std::endl;
        }

        stopped_future.wait();
        signals.cancel();
        if (dns_server) {
            dns_server->stop();
        }
        proxy.stop();
        runtime.stop();
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "clash-native-test-host error: " << error.what() << "\n";
        return 1;
    }
}
