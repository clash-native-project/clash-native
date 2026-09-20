#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace clash_native::outbound {

struct ShadowsocksOutboundConfig {
    std::string id;
    std::string server_host;
    std::uint16_t server_port = 0;
    std::string method;
    std::string password;
    // Optional Shadowsocks TCP plugin. simple-obfs supports HTTP and TLS;
    // v2ray-plugin and gost-plugin support WebSocket with optional TLS.
    // Native Shadowsocks UDP remains direct.
    std::string plugin;
    std::string plugin_mode;
    std::string plugin_host;
    std::string plugin_path;
    bool plugin_tls = false;
    bool plugin_skip_cert_verify = false;
    // Use the Shadowsocks TCP stream with the standardized UDP-over-TCP
    // framing. Version 1 is the legacy per-packet framing; version 2 adds a
    // packet-mode request before the first frame.
    bool udp_over_tcp = false;
    std::uint8_t udp_over_tcp_version = 1;
};

class ShadowsocksOutbound final : public core::Outbound {
  public:
    ShadowsocksOutbound(runtime::AsioRuntime &runtime, ShadowsocksOutboundConfig config,
                        std::shared_ptr<dns::ResolverService> resolver = nullptr);

    core::Status validate() const;
    const core::OutboundDescriptor &descriptor() const noexcept override;
    core::OutboundCapabilities capabilities() const noexcept override;
    void connect_stream(core::StreamRequest request, core::StreamOpenHandler handler) override;
    void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) override;

  private:
    runtime::AsioRuntime &runtime_;
    ShadowsocksOutboundConfig config_;
    std::shared_ptr<dns::ResolverService> resolver_;
    core::OutboundDescriptor descriptor_;
    core::OutboundCapabilities capabilities_{true, core::DatagramSemantics::multi_destination,
                                             core::TargetRequirement::domain_or_ip,
                                             core::TargetRequirement::domain_or_ip};
};

} // namespace clash_native::outbound
