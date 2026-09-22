#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace clash_native::outbound {

struct HttpProxyOutboundConfig {
    std::string id;
    std::string server_host;
    std::uint16_t server_port = 0;
    bool tls = false;
    std::string server_name;
    std::string trusted_ca_pem;
    bool verify_peer = true;
    std::string username;
    std::string password;
};

// Opens target streams through an HTTP/1.1 or HTTPS HTTP proxy using CONNECT.
// HTTPS proxy endpoints negotiate HTTP/2 when available and otherwise use HTTP/1.1.
class HttpProxyOutbound final : public core::Outbound {
  public:
    HttpProxyOutbound(runtime::AsioRuntime &runtime, HttpProxyOutboundConfig config,
                      std::shared_ptr<dns::ResolverService> resolver = nullptr);

    core::Status validate() const;
    const core::OutboundDescriptor &descriptor() const noexcept override;
    core::OutboundCapabilities capabilities() const noexcept override;
    io::AnySender<core::StreamOpenResult> connect_stream(core::StreamRequest request) override;
    void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) override;

  private:
    runtime::AsioRuntime &runtime_;
    HttpProxyOutboundConfig config_;
    std::shared_ptr<dns::ResolverService> resolver_;
    core::OutboundDescriptor descriptor_;
    core::OutboundCapabilities capabilities_{true, core::DatagramSemantics::unsupported,
                                             core::TargetRequirement::domain_or_ip,
                                             core::TargetRequirement::domain_or_ip};
};

} // namespace clash_native::outbound
