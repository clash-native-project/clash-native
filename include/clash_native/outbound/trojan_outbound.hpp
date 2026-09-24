#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/transport/websocket_client.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace clash_native::outbound {

struct TrojanOutboundConfig {
    std::string id;
    std::string server_host;
    std::uint16_t server_port = 0;
    std::string password;
    std::string server_name;
    std::string trusted_ca_pem;
    bool verify_peer = true;
    // Supported values are tcp, ws, and wss. The ws mode can be paired with
    // TLS by setting websocket_tls to true; wss always enables TLS.
    std::string network = "tcp";
    std::string websocket_host;
    std::string websocket_path = "/";
    std::vector<io::ExchangeField> websocket_headers;
    bool websocket_tls = false;
    // Empty means Mihomo defaults: {"h2", "http/1.1"} for TCP,
    // {"http/1.1"} for WebSocket.
    std::vector<std::string> alpn_protocols;
    // Trojan-SS (ss-opts): when enabled, the transport stream is wrapped
    // in classic Shadowsocks AEAD framing before the Trojan header is
    // written. Empty method means AES-128-GCM, matching Mihomo.
    bool ss_enabled = false;
    std::string ss_method;
    std::string ss_password;
};

class TrojanOutbound final : public core::Outbound {
  public:
    TrojanOutbound(runtime::AsioRuntime &runtime, TrojanOutboundConfig config,
                   std::shared_ptr<dns::ResolverService> resolver = nullptr);

    core::Status validate() const;
    const core::OutboundDescriptor &descriptor() const noexcept override;
    core::OutboundCapabilities capabilities() const noexcept override;
    io::AnySender<core::StreamOpenResult> connect_stream(core::StreamRequest request) override;
    io::AnySender<core::DatagramOpenResult> open_datagram(core::DatagramRequest request) override;

  private:
    runtime::AsioRuntime &runtime_;
    TrojanOutboundConfig config_;
    std::shared_ptr<dns::ResolverService> resolver_;
    core::OutboundDescriptor descriptor_;
    core::OutboundCapabilities capabilities_{true, core::DatagramSemantics::multi_destination,
                                             core::TargetRequirement::domain_or_ip,
                                             core::TargetRequirement::domain_or_ip};
};

} // namespace clash_native::outbound
