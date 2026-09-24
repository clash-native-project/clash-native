#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/transport/proxy/gun_client.hpp>
#include <clash_native/transport/proxy/jls_client.hpp>
#include <clash_native/transport/proxy/restls_client.hpp>
#include <clash_native/transport/proxy/shadow_tls.hpp>
#include <clash_native/transport/websocket_client.hpp>

#include <chrono>
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
    std::string name_cert_verify;
    std::string certificate;
    std::string private_key;
    // Supported values are tcp, ws, and wss. The ws mode can be paired with
    // TLS by setting websocket_tls to true; wss always enables TLS.
    std::string network = "tcp";
    std::string websocket_host;
    std::string websocket_path = "/";
    std::vector<io::ExchangeField> websocket_headers;
    bool websocket_tls = false;
    std::size_t websocket_max_early_data = 0;
    std::string websocket_early_data_header;
    bool websocket_v2ray_http_upgrade = false;
    bool websocket_v2ray_http_upgrade_fast_open = false;
    // Empty means Mihomo defaults: {"h2", "http/1.1"} for TCP,
    // {"http/1.1"} for WebSocket.
    std::vector<std::string> alpn_protocols;
    // Server certificate SHA-256 pin, hex with optional colons (Mihomo
    // fingerprint = SSL pinning). Empty disables pinning.
    std::string fingerprint;
    // ClientHello camouflage profile for every TLS handshake (Mihomo
    // client-fingerprint). Empty means the default BoringSSL emission;
    // "chrome" selects the Chrome profile. Required for REALITY.
    std::string client_fingerprint;
    // Trojan-SS (ss-opts): when enabled, the transport stream is wrapped
    // in classic Shadowsocks AEAD framing before the Trojan header is
    // written. Empty method means AES-128-GCM, matching Mihomo.
    bool ss_enabled = false;
    std::string ss_method;
    std::string ss_password;
    // TLS-underlay camouflage for TCP mode, matching Mihomo's mutually
    // exclusive shadow-tls/restls/jls options. Empty means direct TLS.
    // (Not applied under WebSocket TLS: the ws client owns its handshake.)
    std::string security_mode;
    // REALITY handshake (Mihomo reality-opts), mutually exclusive with
    // security_mode. Empty public key disables it.
    std::string reality_public_key;
    std::string reality_short_id;
    // ECH (Mihomo ech-opts). Disabled unless enabled; a static base64
    // ECHConfigList or an HTTPS-record lookup (with optional
    // query-server-name override) supplies the configs.
    bool ech_enabled = false;
    std::string ech_config;
    std::string ech_query_server_name;
    transport::proxy::ShadowTlsClientOptions shadow_tls_options;
    transport::proxy::RestlsClientOptions restls_options;
    transport::proxy::JlsClientOptions jls_options;
    // gRPC (gun) carrier for network "grpc". Empty service name means
    // "GunService", matching Mihomo.
    std::string grpc_service_name;
    std::string grpc_user_agent;
    // h2 PING keepalive for pooled grpc sessions, zero disables.
    std::chrono::seconds grpc_ping_interval{0};
    int grpc_max_connections = 0;
    int grpc_min_streams = 0;
    int grpc_max_streams = 0;
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
    std::shared_ptr<transport::proxy::gun::GunClient> gun_pool_;
    core::OutboundDescriptor descriptor_;
    core::OutboundCapabilities capabilities_{true, core::DatagramSemantics::multi_destination,
                                             core::TargetRequirement::domain_or_ip,
                                             core::TargetRequirement::domain_or_ip};
};

} // namespace clash_native::outbound
