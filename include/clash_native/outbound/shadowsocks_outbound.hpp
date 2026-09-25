#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/transport/shadowsocks/kcptun.hpp>
#include <clash_native/transport/shadowsocks/kcptun_session.hpp>
#include <clash_native/transport/shadowsocks/websocket_plugin.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace clash_native::outbound {

struct ShadowsocksOutboundConfig {
    std::string id;
    std::string server_host;
    std::uint16_t server_port = 0;
    std::string method;
    std::string password;
    // Mihomo `udp` option. When false, UDP opens fail and the outbound
    // reports no datagram support.
    bool udp_enabled = true;
    // Optional Shadowsocks TCP plugin. simple-obfs supports HTTP and TLS;
    // v2ray-plugin and gost-plugin support WebSocket with optional TLS;
    // shadow-tls supports Shadow-TLS v1, v2, and v3 carriers; restls supports
    // password-authenticated TLS 1.2 or TLS 1.3 carriers, while jls uses TLS 1.3.
    // Native Shadowsocks UDP remains direct.
    std::string plugin;
    std::string plugin_mode;
    std::string plugin_host;
    std::string plugin_path;
    bool plugin_tls = false;
    bool plugin_skip_cert_verify = false;
    // Reuse one WebSocket carrier for multiple logical Shadowsocks streams.
    // v2ray-plugin uses its native mux framing; gost-plugin uses smux.
    bool plugin_mux = false;
    std::uint8_t plugin_smux_version = 1;
    std::optional<transport::shadowsocks::KcptunClientOptions> kcptun;
    // Use the Shadowsocks TCP stream with the standardized UDP-over-TCP
    // framing. Version 1 is the legacy per-packet framing; version 2 adds a
    // packet-mode request before the first frame.
    bool udp_over_tcp = false;
    std::uint8_t udp_over_tcp_version = 1;
    std::string plugin_password;
    std::string plugin_username;
    // Server certificate SHA-256 pin for shadow-tls/restls carriers
    // (Mihomo plugin-opts fingerprint).
    std::string plugin_fingerprint;
    // ClientHello camouflage profile for the shadow-tls carrier
    // (Mihomo client-fingerprint).
    std::string plugin_client_fingerprint;
    int plugin_version = 2;
    std::vector<std::string> plugin_alpn;
    std::string plugin_version_hint = "tls12";
    std::string plugin_restls_script;
};

class ShadowsocksOutbound final : public core::Outbound {
  public:
    ShadowsocksOutbound(runtime::AsioRuntime &runtime, ShadowsocksOutboundConfig config,
                        std::shared_ptr<dns::ResolverService> resolver = nullptr);

    core::Status validate() const;
    const core::OutboundDescriptor &descriptor() const noexcept override;
    core::OutboundCapabilities capabilities() const noexcept override;
    io::AnySender<core::StreamOpenResult> connect_stream(core::StreamRequest request) override;
    io::AnySender<core::DatagramOpenResult> open_datagram(core::DatagramRequest request) override;

  private:
    runtime::AsioRuntime &runtime_;
    ShadowsocksOutboundConfig config_;
    std::shared_ptr<dns::ResolverService> resolver_;
    std::shared_ptr<transport::shadowsocks::KcptunClientPool> kcptun_pool_;
    std::shared_ptr<transport::shadowsocks::WebSocketPluginMuxPool> websocket_mux_pool_;
    core::OutboundDescriptor descriptor_;
    core::OutboundCapabilities capabilities_{true, core::DatagramSemantics::multi_destination,
                                             core::TargetRequirement::domain_or_ip,
                                             core::TargetRequirement::domain_or_ip};
};

} // namespace clash_native::outbound
