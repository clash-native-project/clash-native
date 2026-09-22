#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <string>

namespace clash_native::outbound {

class DirectOutbound final : public core::Outbound {
  public:
    explicit DirectOutbound(runtime::AsioRuntime &runtime,
                            std::shared_ptr<dns::ResolverService> resolver = nullptr);

    void set_resolver(std::shared_ptr<dns::ResolverService> resolver);

    const core::OutboundDescriptor &descriptor() const noexcept override;
    core::OutboundCapabilities capabilities() const noexcept override;
    io::AnySender<core::StreamOpenResult> connect_stream(core::StreamRequest request) override;
    void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) override;

  private:
    runtime::AsioRuntime &runtime_;
    std::shared_ptr<dns::ResolverService> resolver_;
    core::OutboundDescriptor descriptor_{"direct", "direct"};
    core::OutboundCapabilities capabilities_{true, core::DatagramSemantics::fixed_destination,
                                             core::TargetRequirement::domain_or_ip,
                                             core::TargetRequirement::ip_required};
};

class RejectOutbound final : public core::Outbound {
  public:
    explicit RejectOutbound(runtime::AsioRuntime &runtime);

    const core::OutboundDescriptor &descriptor() const noexcept override;
    core::OutboundCapabilities capabilities() const noexcept override;
    io::AnySender<core::StreamOpenResult> connect_stream(core::StreamRequest request) override;
    void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) override;

  private:
    runtime::AsioRuntime &runtime_;
    core::OutboundDescriptor descriptor_{"reject", "reject"};
    core::OutboundCapabilities capabilities_{false, core::DatagramSemantics::unsupported};
};

} // namespace clash_native::outbound
