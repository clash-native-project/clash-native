#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ssl/context.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace clash_native::outbound {

struct TrojanOutboundConfig {
    std::string id;
    std::string server_host;
    std::uint16_t server_port = 0;
    std::string password;
    std::string server_name;
    std::string trusted_ca_pem;
    bool verify_peer = true;
};

class TrojanOutbound final : public core::Outbound {
  public:
    TrojanOutbound(runtime::AsioRuntime &runtime, TrojanOutboundConfig config,
                   std::shared_ptr<dns::ResolverService> resolver = nullptr);

    core::Status validate() const;
    const core::OutboundDescriptor &descriptor() const noexcept override;
    core::OutboundCapabilities capabilities() const noexcept override;
    void connect_stream(core::StreamRequest request, core::StreamOpenHandler handler) override;
    void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) override;

  private:
    runtime::AsioRuntime &runtime_;
    TrojanOutboundConfig config_;
    std::shared_ptr<dns::ResolverService> resolver_;
    std::shared_ptr<boost::asio::ssl::context> tls_context_;
    core::OutboundDescriptor descriptor_;
    core::OutboundCapabilities capabilities_{true, core::DatagramSemantics::unsupported,
                                             core::TargetRequirement::domain_or_ip,
                                             core::TargetRequirement::domain_or_ip};
};

} // namespace clash_native::outbound
