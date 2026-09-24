#include <clash_native/dns/dns_policy_router.hpp>
#include <clash_native/dns/dns_server.hpp>
#include <clash_native/outbound/http_proxy_outbound.hpp>
#include <clash_native/outbound/outbound_registry.hpp>
#include <clash_native/outbound/shadowsocks_outbound.hpp>
#include <clash_native/outbound/trojan_outbound.hpp>
#include <clash_native/proxy/proxy_server.hpp>
#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/transport/shadowsocks/ss2022_packet.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/errc.hpp>

#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <functional>
#include <future>
#include <istream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

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

struct HostPort {
    std::string host;
    std::uint16_t port = 0;
};

HostPort parse_host_port(std::string_view text) {
    std::string_view host;
    std::string_view port_text;
    if (!text.empty() && text.front() == '[') {
        const auto closing = text.find(']');
        if (closing == std::string_view::npos || closing + 1 >= text.size() ||
            text[closing + 1] != ':') {
            throw std::runtime_error("outbound server must be formatted as host:port");
        }
        host = text.substr(1, closing - 1);
        port_text = text.substr(closing + 2);
    } else {
        const auto separator = text.rfind(':');
        if (separator == std::string_view::npos || separator == 0 || separator + 1 == text.size()) {
            throw std::runtime_error("outbound server must be formatted as host:port");
        }
        host = text.substr(0, separator);
        port_text = text.substr(separator + 1);
    }
    unsigned int port = 0;
    const auto parsed =
        std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (host.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != port_text.data() + port_text.size() || port == 0 || port > 65535) {
        throw std::runtime_error("outbound server must be formatted as host:port");
    }
    return {std::string(host), static_cast<std::uint16_t>(port)};
}

std::shared_ptr<clash_native::outbound::OutboundRegistry>
test_outbound_registry(clash_native::runtime::AsioRuntime &runtime,
                       std::shared_ptr<clash_native::dns::ResolverService> resolver,
                       const std::string &kind, const std::string &server_text,
                       const std::string &password) {
    const auto server = parse_host_port(server_text);
    auto registry = std::make_shared<clash_native::outbound::OutboundRegistry>();
    if (kind == "shadowsocks") {
        const auto method = environment_value("CLASH_NATIVE_TEST_OUTBOUND_METHOD");
        if (!method) {
            throw std::runtime_error("CLASH_NATIVE_TEST_OUTBOUND_METHOD is required");
        }
        clash_native::outbound::ShadowsocksOutboundConfig config{"test-proxy", server.host,
                                                                 server.port, *method, password};
        if (const auto plugin = environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN"); plugin) {
            config.plugin = *plugin;
            config.plugin_mode =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_MODE").value_or("");
            config.plugin_host =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST").value_or("");
            config.plugin_path =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_PATH").value_or("");
            config.plugin_tls =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_TLS").value_or("") == "1";
            config.plugin_skip_cert_verify =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_SKIP_CERT_VERIFY")
                    .value_or("") == "1";
            config.plugin_mux =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_MUX").value_or("") == "1";
            if (const auto smux_version =
                    environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_SMUX_VERSION");
                smux_version && !smux_version->empty()) {
                unsigned int parsed_version = 0;
                const auto parsed =
                    std::from_chars(smux_version->data(),
                                    smux_version->data() + smux_version->size(), parsed_version);
                if (parsed.ec != std::errc{} ||
                    parsed.ptr != smux_version->data() + smux_version->size() ||
                    parsed_version > std::numeric_limits<std::uint8_t>::max()) {
                    throw std::runtime_error(
                        "invalid CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_SMUX_VERSION");
                }
                config.plugin_smux_version = static_cast<std::uint8_t>(parsed_version);
            }
            config.plugin_password =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_PASSWORD").value_or("");
            config.plugin_username =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_USERNAME").value_or("");
            if (const auto version = environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_VERSION");
                version && !version->empty()) {
                const auto parsed = std::from_chars(
                    version->data(), version->data() + version->size(), config.plugin_version);
                if (parsed.ec != std::errc{} || parsed.ptr != version->data() + version->size()) {
                    throw std::runtime_error("invalid CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_VERSION");
                }
            }
            config.plugin_version_hint =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_VERSION_HINT")
                    .value_or(config.plugin_version_hint);
            config.plugin_restls_script =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_RESTLS_SCRIPT").value_or("");
            if (const auto alpn = environment_value("CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_ALPN");
                alpn && !alpn->empty()) {
                std::size_t offset = 0;
                while (offset <= alpn->size()) {
                    const auto separator = alpn->find(',', offset);
                    const auto length =
                        separator == std::string::npos ? alpn->size() - offset : separator - offset;
                    if (length == 0) {
                        throw std::runtime_error("invalid CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_ALPN");
                    }
                    config.plugin_alpn.emplace_back(alpn->substr(offset, length));
                    if (separator == std::string::npos) {
                        break;
                    }
                    offset = separator + 1;
                }
            }
            if (config.plugin == "kcptun") {
                auto options = clash_native::transport::shadowsocks::KcptunClientOptions{};
                options.key = environment_value("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_KEY")
                                  .value_or(options.key);
                options.crypt = environment_value("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_CRYPT")
                                    .value_or(options.crypt);
                const auto parse_option = [](const char *name, int &target) {
                    const auto value = environment_value(name);
                    if (!value || value->empty()) {
                        return;
                    }
                    const auto parsed =
                        std::from_chars(value->data(), value->data() + value->size(), target);
                    if (parsed.ec != std::errc{} || parsed.ptr != value->data() + value->size()) {
                        throw std::runtime_error(std::string("invalid ") + name);
                    }
                };
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_MTU", options.mtu);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_CONN", options.connection_count);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_AUTOEXPIRE",
                             options.auto_expire_seconds);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_SCAVENGETTL",
                             options.scavenge_ttl_seconds);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_RATELIMIT", options.rate_limit);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_SNDWND", options.send_window);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_RCVWND", options.receive_window);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_DSCP", options.dscp);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_NODELAY", options.nodelay);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_INTERVAL", options.interval_ms);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_RESEND", options.fast_resend);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_NC",
                             options.disable_congestion_control);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_SOCKBUF", options.socket_buffer);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_DATASHARD", options.data_shard);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_PARITYSHARD", options.parity_shard);
                if (const auto mode = environment_value("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_MODE");
                    mode && !mode->empty()) {
                    options.mode = *mode;
                }
                options.ack_nodelay =
                    environment_value("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_ACKNODELAY")
                        .value_or(options.ack_nodelay ? "1" : "0") != "0";
                if (options.data_shard < 0) {
                    options.data_shard = 0;
                }
                if (options.parity_shard < 0) {
                    options.parity_shard = 0;
                }
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_SMUXVER", options.smux_version);
                parse_option("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_FRAMESIZE", options.frame_size);
                options.no_compression =
                    environment_value("CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_NOCOMP")
                        .value_or(options.no_compression ? "1" : "0") != "0";
                config.kcptun = std::move(options);
            }
        }
        config.udp_over_tcp =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_UDP_OVER_TCP").value_or("") == "1";
        if (const auto version =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_UDP_OVER_TCP_VERSION");
            version && !version->empty()) {
            const auto parsed = std::from_chars(version->data(), version->data() + version->size(),
                                                config.udp_over_tcp_version);
            if (parsed.ec != std::errc{} || parsed.ptr != version->data() + version->size()) {
                throw std::runtime_error("invalid CLASH_NATIVE_TEST_OUTBOUND_UDP_OVER_TCP_VERSION");
            }
        }
        auto outbound = std::make_shared<clash_native::outbound::ShadowsocksOutbound>(
            runtime, std::move(config), std::move(resolver));
        if (const auto result = outbound->validate(); !result) {
            throw std::runtime_error(result.error().context);
        }
        if (const auto result = registry->add_outbound("test-proxy", std::move(outbound));
            !result) {
            throw std::runtime_error(result.error().context);
        }
    } else if (kind == "trojan") {
        std::string ca_pem;
        if (const auto ca_path = environment_value("CLASH_NATIVE_TEST_OUTBOUND_CA_FILE"); ca_path) {
            std::ifstream file(*ca_path, std::ios::binary);
            if (!file) {
                throw std::runtime_error("failed to read Trojan test CA file");
            }
            ca_pem.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        }
        const auto server_name = environment_value("CLASH_NATIVE_TEST_OUTBOUND_SERVER_NAME");
        auto trojan_config =
            clash_native::outbound::TrojanOutboundConfig{"test-proxy",
                                                         server.host,
                                                         server.port,
                                                         password,
                                                         server_name.value_or(server.host),
                                                         std::move(ca_pem),
                                                         true};
        trojan_config.network =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_NETWORK").value_or("tcp");
        trojan_config.websocket_host =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_WS_HOST").value_or("");
        trojan_config.websocket_path =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_WS_PATH").value_or("/");
        trojan_config.websocket_tls =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_WS_TLS").value_or("0") != "0";
        if (const auto early_data =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_WS_MAX_EARLY_DATA")) {
            trojan_config.websocket_max_early_data = std::stoul(*early_data);
        }
        trojan_config.websocket_early_data_header =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_WS_EARLY_DATA_HEADER")
                .value_or("");
        trojan_config.websocket_v2ray_http_upgrade =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_WS_UPGRADE").value_or("0") != "0";
        trojan_config.ss_enabled =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_SS_ENABLED").value_or("0") != "0";
        trojan_config.ss_method = environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_SS_METHOD")
                                      .value_or("AES-128-GCM");
        trojan_config.ss_password =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_SS_PASSWORD").value_or("");
        trojan_config.security_mode =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_SECURITY_MODE").value_or("");
        trojan_config.shadow_tls_options.password =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_SHADOWTLS_PASSWORD").value_or("");
        trojan_config.shadow_tls_options.host =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_SHADOWTLS_HOST").value_or("");
        trojan_config.shadow_tls_options.skip_cert_verify =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_SHADOWTLS_SKIP_VERIFY")
                .value_or("0") != "0";
        if (const auto version =
                environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_SHADOWTLS_VERSION")) {
            trojan_config.shadow_tls_options.version = std::stoi(*version);
        }
        trojan_config.restls_options.server_name =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_RESTLS_SERVER_NAME").value_or("");
        trojan_config.restls_options.password =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_RESTLS_PASSWORD").value_or("");
        trojan_config.restls_options.restls_script =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_RESTLS_SCRIPT").value_or("");
        trojan_config.restls_options.version_hint =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_RESTLS_VERSION").value_or("tls12");
        trojan_config.restls_options.skip_cert_verify =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_RESTLS_SKIP_VERIFY")
                .value_or("0") != "0";
        trojan_config.jls_options.server_name =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_JLS_SERVER_NAME").value_or("");
        trojan_config.jls_options.username =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_JLS_USERNAME").value_or("");
        trojan_config.jls_options.password =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_JLS_PASSWORD").value_or("");
        trojan_config.jls_options.skip_cert_verify =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_JLS_SKIP_VERIFY").value_or("0") !=
            "0";
        trojan_config.grpc_service_name =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_GRPC_SERVICE").value_or("");
        trojan_config.grpc_user_agent =
            environment_value("CLASH_NATIVE_TEST_OUTBOUND_TROJAN_GRPC_USER_AGENT").value_or("");
        auto outbound = std::make_shared<clash_native::outbound::TrojanOutbound>(
            runtime, std::move(trojan_config), std::move(resolver));
        if (const auto result = outbound->validate(); !result) {
            throw std::runtime_error(result.error().context);
        }
        if (const auto result = registry->add_outbound("test-proxy", std::move(outbound));
            !result) {
            throw std::runtime_error(result.error().context);
        }
    } else if (kind == "http") {
        std::string ca_pem;
        if (const auto ca_path = environment_value("CLASH_NATIVE_TEST_OUTBOUND_CA_FILE"); ca_path) {
            std::ifstream file(*ca_path, std::ios::binary);
            if (!file) {
                throw std::runtime_error("failed to read HTTP proxy test CA file");
            }
            ca_pem.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        }
        const auto server_name = environment_value("CLASH_NATIVE_TEST_OUTBOUND_SERVER_NAME");
        const auto username = environment_value("CLASH_NATIVE_TEST_OUTBOUND_USERNAME");
        const auto tls = environment_value("CLASH_NATIVE_TEST_OUTBOUND_TLS");
        auto outbound = std::make_shared<clash_native::outbound::HttpProxyOutbound>(
            runtime,
            clash_native::outbound::HttpProxyOutboundConfig{
                "test-proxy", server.host, server.port, tls && *tls == "1",
                server_name.value_or(server.host), std::move(ca_pem), true,
                username.value_or(std::string{}), password},
            std::move(resolver));
        if (const auto result = outbound->validate(); !result) {
            throw std::runtime_error(result.error().context);
        }
        if (const auto result = registry->add_outbound("test-proxy", std::move(outbound));
            !result) {
            throw std::runtime_error(result.error().context);
        }
    } else {
        throw std::runtime_error("unsupported CLASH_NATIVE_TEST_OUTBOUND protocol");
    }
    return registry;
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
        if (scheme == "dot") {
            mode = clash_native::dns::DnsTransportMode::dot;
        } else if (scheme == "doh1") {
            mode = clash_native::dns::DnsTransportMode::doh1;
        } else if (scheme == "doh2") {
            mode = clash_native::dns::DnsTransportMode::doh2;
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
        mode == clash_native::dns::DnsTransportMode::doh2 ||
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
        mode == clash_native::dns::DnsTransportMode::doh2 ||
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

class Stage2ReloadControl final : public std::enable_shared_from_this<Stage2ReloadControl> {
  public:
    Stage2ReloadControl(clash_native::runtime::AsioRuntime &runtime,
                        clash_native::proxy::ProxyServer &proxy,
                        std::shared_ptr<clash_native::dns::ResolverService> resolver)
        : runtime_(runtime), proxy_(proxy), resolver_(std::move(resolver)),
          acceptor_(runtime.context()) {
        boost::system::error_code error;
        acceptor_.open(boost::asio::ip::tcp::v4(), error);
        if (!error) {
            acceptor_.set_option(boost::asio::socket_base::reuse_address(true), error);
        }
        if (!error) {
            acceptor_.bind({boost::asio::ip::address_v4::loopback(), 0}, error);
        }
        if (!error) {
            acceptor_.listen(boost::asio::socket_base::max_listen_connections, error);
        }
        if (error) {
            throw std::system_error(error, "failed to start test reload control listener");
        }
        endpoint_ = acceptor_.local_endpoint(error);
        if (error) {
            throw std::system_error(error, "failed to query test reload control endpoint");
        }
    }

    boost::asio::ip::tcp::endpoint endpoint() const noexcept { return endpoint_; }

    void start() { accept(); }

    void stop() noexcept {
        boost::system::error_code ignored;
        acceptor_.cancel(ignored);
        acceptor_.close(ignored);
    }

  private:
    void accept() {
        if (!acceptor_.is_open()) {
            return;
        }
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(runtime_.context());
        const auto self = shared_from_this();
        acceptor_.async_accept(*socket, [self, socket](const boost::system::error_code &error) {
            if (!error) {
                self->read_command(socket);
            }
            self->accept();
        });
    }

    void read_command(const std::shared_ptr<boost::asio::ip::tcp::socket> &socket) {
        auto buffer = std::make_shared<boost::asio::streambuf>();
        const auto self = shared_from_this();
        boost::asio::async_read_until(
            *socket, *buffer, '\n',
            [self, socket, buffer](const boost::system::error_code &error, std::size_t) {
                std::string response = "ERR invalid command\n";
                if (!error) {
                    std::istream input(buffer.get());
                    std::string command;
                    std::getline(input, command);
                    if (command == "reload") {
                        response = self->reload_snapshot();
                    }
                }
                auto payload = std::make_shared<std::string>(std::move(response));
                boost::asio::async_write(
                    *socket, boost::asio::buffer(*payload),
                    [socket, payload](const boost::system::error_code &, std::size_t) {
                        boost::system::error_code ignored;
                        socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
                        socket->close(ignored);
                    });
            });
    }

    std::string reload_snapshot() {
        const auto current = proxy_.runtime_snapshot_store()->load();
        if (!current) {
            return "ERR runtime snapshot is not published\n";
        }
        auto router = std::make_shared<clash_native::router::TrafficRouter>(
            clash_native::router::RouteAction::reject());
        auto fake_ip_store = std::make_shared<clash_native::dns::FakeIpStore>(
            boost::asio::ip::make_address_v4("198.19.0.0"), 24, 254);
        auto replacement = std::make_shared<const clash_native::runtime::RuntimeSnapshot>(
            clash_native::runtime::RuntimeSnapshot{
                current->generation + 1, router->snapshot(), current->outbounds, resolver_,
                std::move(fake_ip_store), current->fake_ip_filter});
        if (const auto result = proxy_.reload(std::move(replacement)); !result) {
            return "ERR " + result.error().context + "\n";
        }
        return "OK " + std::to_string(current->generation + 1) + "\n";
    }

    clash_native::runtime::AsioRuntime &runtime_;
    clash_native::proxy::ProxyServer &proxy_;
    std::shared_ptr<clash_native::dns::ResolverService> resolver_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ip::tcp::endpoint endpoint_;
};

int run_raw_shadowsocks2022_udp_test() {
    const auto server_text = environment_value("CLASH_NATIVE_TEST_OUTBOUND_SERVER");
    const auto method = environment_value("CLASH_NATIVE_TEST_OUTBOUND_METHOD");
    const auto password = environment_value("CLASH_NATIVE_TEST_OUTBOUND_PASSWORD");
    const auto target_text = environment_value("CLASH_NATIVE_TEST_RAW_SS2022_TARGET");
    if (!server_text || !method || !password || !target_text) {
        throw std::runtime_error("raw Shadowsocks 2022 UDP test variables are incomplete");
    }
    const auto server = parse_host_port(*server_text);
    const auto target = parse_host_port(*target_text);
    boost::system::error_code error;
    const auto server_address = boost::asio::ip::make_address(server.host, error);
    if (error || !server_address.is_v4()) {
        throw std::runtime_error("raw Shadowsocks 2022 UDP test requires an IPv4 server");
    }
    const auto target_address = boost::asio::ip::make_address(target.host, error);
    if (error || !target_address.is_v4()) {
        throw std::runtime_error("raw Shadowsocks 2022 UDP test requires an IPv4 target");
    }

    clash_native::transport::shadowsocks::Shadowsocks2022DatagramCodec codec(*method, *password);
    const auto target_bytes = target_address.to_v4().to_bytes();
    std::vector<std::uint8_t> destination{1,
                                          target_bytes[0],
                                          target_bytes[1],
                                          target_bytes[2],
                                          target_bytes[3],
                                          static_cast<std::uint8_t>(target.port >> 8),
                                          static_cast<std::uint8_t>(target.port)};
    const std::vector<std::uint8_t> payload{'c', 'l', 'a', 's', 'h', '-', 'n', 'a',
                                            't', 'i', 'v', 'e', '-', 's', 's', '2',
                                            '0', '2', '2', '-', 'u', 'd', 'p'};
    const auto wire = codec.encrypt(destination, payload);
    if (!wire) {
        throw std::runtime_error(wire.error().context);
    }

    boost::asio::io_context context;
    boost::asio::ip::udp::socket socket(context, boost::asio::ip::udp::v4());
    socket.bind({boost::asio::ip::udp::v4(), 0}, error);
    if (error) {
        throw std::system_error(error, "bind raw Shadowsocks 2022 UDP socket");
    }
    const boost::asio::ip::udp::endpoint server_endpoint(server_address, server.port);
    spdlog::info("clash-native-test-host raw-udp-ready");
    socket.send_to(boost::asio::buffer(wire.value()), server_endpoint, 0, error);
    if (error) {
        throw std::system_error(error, "send raw Shadowsocks 2022 UDP packet");
    }
    socket.non_blocking(true, error);
    if (error) {
        throw std::system_error(error, "configure raw Shadowsocks 2022 UDP socket");
    }
    std::array<std::uint8_t, 65507> buffer{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        boost::asio::ip::udp::endpoint sender;
        const auto size = socket.receive_from(boost::asio::buffer(buffer), sender, 0, error);
        if (!error) {
            auto plaintext = codec.decrypt(std::span<const std::uint8_t>(buffer.data(), size));
            if (!plaintext || plaintext.value().size() != destination.size() + payload.size() ||
                !std::equal(destination.begin(), destination.end(), plaintext.value().begin()) ||
                !std::equal(payload.begin(), payload.end(),
                            plaintext.value().begin() +
                                static_cast<std::ptrdiff_t>(destination.size()))) {
                throw std::runtime_error("raw Shadowsocks 2022 UDP response payload mismatch");
            }
            spdlog::info("clash-native-test-host raw-udp-pass");
            return 0;
        }
        if (error != boost::asio::error::would_block && error != boost::asio::error::try_again) {
            throw std::system_error(error, "receive raw Shadowsocks 2022 UDP response");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    throw std::runtime_error("timed out waiting for raw Shadowsocks 2022 UDP response");
}

} // namespace

int main(int argc, char **) {
    auto logger = spdlog::stdout_color_mt("clash-native-test-host");
    logger->set_pattern("%v");
    logger->set_level(spdlog::level::info);
    logger->flush_on(spdlog::level::info);
    spdlog::set_default_logger(std::move(logger));

    if (argc != 1) {
        spdlog::error("clash-native-test-host does not accept command-line arguments.");
        return 2;
    }

    try {
        if (const auto raw_udp = environment_value("CLASH_NATIVE_TEST_RAW_SS2022_UDP");
            raw_udp && *raw_udp == "1") {
            return run_raw_shadowsocks2022_udp_test();
        }
        auto &runtime = clash_native::runtime::AsioRuntime::instance();
        std::shared_ptr<clash_native::dns::ResolverService> resolver;
        std::shared_ptr<clash_native::dns::ResolverService> reload_resolver;
        std::unique_ptr<clash_native::dns::DnsServer> dns_server;
        std::shared_ptr<clash_native::dns::FakeIpStore> fake_ip_store;
        std::function<bool(std::string_view)> fake_ip_filter;
        const auto stage2_composition = environment_value("CLASH_NATIVE_TEST_STAGE2_COMPOSITION");
        const bool run_stage2_composition = stage2_composition && *stage2_composition == "1";
        const auto fake_ip_domain = environment_value("CLASH_NATIVE_FAKE_IP_DOMAIN");
        if (const auto upstream_text = environment_value("CLASH_NATIVE_DNS_UPSTREAM");
            upstream_text) {
            auto upstream = parse_upstream_config(upstream_text->c_str());
            if (!upstream) {
                throw std::runtime_error(
                    "CLASH_NATIVE_DNS_UPSTREAM must be address:port or a supported "
                    "dot://, doh1://, doh2://, doq://, or doh3:// endpoint");
            }
            if (const auto verify_peer = environment_value("CLASH_NATIVE_DNS_VERIFY_PEER");
                verify_peer &&
                (*verify_peer == "0" || *verify_peer == "false" || *verify_peer == "FALSE")) {
                upstream->verify_peer = false;
            }
            const auto default_upstream_for_reload = *upstream;

            std::unordered_map<std::string, clash_native::dns::DnsUpstreamConfig> upstream_groups;
            std::shared_ptr<const clash_native::dns::DnsPolicyRouter> policy_router;
            if (const auto policy_upstream_text =
                    environment_value("CLASH_NATIVE_DNS_POLICY_UPSTREAM");
                policy_upstream_text) {
                auto policy_upstream = parse_upstream_config(policy_upstream_text->c_str());
                if (!policy_upstream) {
                    throw std::runtime_error(
                        "CLASH_NATIVE_DNS_POLICY_UPSTREAM must be a supported DNS endpoint");
                }
                upstream_groups.emplace("policy", std::move(*policy_upstream));
                auto mutable_policy =
                    std::make_shared<clash_native::dns::DnsPolicyRouter>("default");
                mutable_policy->add_rule({"stage2-policy-group",
                                          clash_native::dns::DnsPolicyRuleKind::exact,
                                          "policy-route.test", "policy"});
                policy_router = std::move(mutable_policy);
            }
            if (run_stage2_composition && (!fake_ip_domain || !policy_router)) {
                throw std::runtime_error(
                    "Stage 2 composition requires FakeIP and a DNS policy upstream");
            }
            clash_native::dns::DnsResolverConfig config(
                std::move(*upstream), std::move(upstream_groups), std::move(policy_router));
            resolver =
                std::make_shared<clash_native::dns::ResolverService>(runtime, std::move(config));
            if (run_stage2_composition) {
                auto reload_policy =
                    std::make_shared<clash_native::dns::DnsPolicyRouter>("default");
                reload_policy->add_rule({"stage2-policy-after-reload",
                                         clash_native::dns::DnsPolicyRuleKind::exact,
                                         "policy-route.test", "default"});
                clash_native::dns::DnsResolverConfig reload_config(default_upstream_for_reload, {},
                                                                   std::move(reload_policy));
                reload_resolver = std::make_shared<clash_native::dns::ResolverService>(
                    runtime, std::move(reload_config));
            }
        }
        if (fake_ip_domain) {
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

        boost::system::error_code proxy_address_error;
        auto proxy_address = boost::asio::ip::address_v4::loopback();
        if (const auto proxy_host = environment_value("CLASH_NATIVE_TEST_PROXY_HOST");
            proxy_host && !proxy_host->empty()) {
            const auto parsed = boost::asio::ip::make_address(*proxy_host, proxy_address_error);
            if (proxy_address_error || !parsed.is_v4()) {
                throw std::runtime_error("CLASH_NATIVE_TEST_PROXY_HOST must be an IPv4 address");
            }
            proxy_address = parsed.to_v4();
        }
        clash_native::proxy::ProxyServer proxy(runtime, {proxy_address, 0});
        if (resolver) {
            proxy.set_resolver(resolver);
        }
        const auto outbound_kind = environment_value("CLASH_NATIVE_TEST_OUTBOUND");
        if (outbound_kind) {
            const auto outbound_server = environment_value("CLASH_NATIVE_TEST_OUTBOUND_SERVER");
            const auto outbound_password = environment_value("CLASH_NATIVE_TEST_OUTBOUND_PASSWORD");
            if (!outbound_server || (!outbound_password && *outbound_kind != "http")) {
                throw std::runtime_error(
                    "CLASH_NATIVE_TEST_OUTBOUND_SERVER and _PASSWORD are required");
            }
            proxy.set_outbound_registry(
                test_outbound_registry(runtime, resolver, *outbound_kind, *outbound_server,
                                       outbound_password.value_or(std::string{})));
            proxy.set_default_action(clash_native::router::RouteAction::named("test-proxy"));
        }
        if (run_stage2_composition) {
            proxy.set_default_action(clash_native::router::RouteAction::reject());
            proxy.add_rule({"stage2-fakeip-direct", clash_native::router::RuleKind::domain,
                            *fake_ip_domain, 0, 0, false,
                            clash_native::router::RouteAction::direct()});
        }
        if (fake_ip_store) {
            proxy.set_fake_ip_store(fake_ip_store);
        }
        proxy.set_fake_ip_filter(fake_ip_filter);
        if (resolver) {
            dns_server = std::make_unique<clash_native::dns::DnsServer>(
                runtime, proxy.runtime_snapshot_store(),
                boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 0),
                boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
        }
        std::shared_ptr<Stage2ReloadControl> reload_control;
        if (run_stage2_composition) {
            reload_control =
                std::make_shared<Stage2ReloadControl>(runtime, proxy, std::move(reload_resolver));
        }
        boost::asio::signal_set signals(runtime.context(), SIGINT, SIGTERM);
        std::promise<void> stopped;
        auto stopped_future = stopped.get_future();

        signals.async_wait([&proxy, &dns_server, &reload_control,
                            &stopped](const boost::system::error_code &, int) {
            if (reload_control) {
                reload_control->stop();
            }
            if (dns_server) {
                dns_server->stop();
            }
            proxy.stop();
            stopped.set_value();
        });

        runtime.start();
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
        if (dns_server) {
            const auto dns_start_result = dns_server->start();
            if (!dns_start_result) {
                proxy.stop();
                runtime.stop();
                const auto &error = dns_start_result.error();
                if (error.cause) {
                    throw std::system_error(error.cause, error.context);
                }
                throw std::runtime_error(error.context);
            }
        }
        if (reload_control) {
            reload_control->start();
        }

        const auto endpoint = proxy.endpoint();
        spdlog::info("clash-native-test-host ready {}:{}", endpoint.address().to_string(),
                     endpoint.port());
        if (dns_server) {
            const auto udp_endpoint = dns_server->udp_endpoint();
            const auto tcp_endpoint = dns_server->tcp_endpoint();
            spdlog::info("clash-native-test-host dns-ready udp={}:{} tcp={}:{}",
                         udp_endpoint.address().to_string(), udp_endpoint.port(),
                         tcp_endpoint.address().to_string(), tcp_endpoint.port());
        }
        if (reload_control) {
            const auto control_endpoint = reload_control->endpoint();
            spdlog::info("clash-native-test-host control-ready tcp={}:{}",
                         control_endpoint.address().to_string(), control_endpoint.port());
        }

        stopped_future.wait();
        signals.cancel();
        if (reload_control) {
            reload_control->stop();
        }
        if (dns_server) {
            dns_server->stop();
        }
        proxy.stop();
        runtime.stop();
        return 0;
    } catch (const std::exception &error) {
        spdlog::error("clash-native-test-host error: {}", error.what());
        return 1;
    }
}
