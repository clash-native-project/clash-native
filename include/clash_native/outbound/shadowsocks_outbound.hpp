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
