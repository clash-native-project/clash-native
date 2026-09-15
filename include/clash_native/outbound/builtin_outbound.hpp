#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <string>

namespace clash_native::outbound {

class DirectOutbound final : public core::Outbound {
  public:
    explicit DirectOutbound(runtime::AsioRuntime &runtime);

    const core::OutboundDescriptor &descriptor() const noexcept override;
    core::OutboundCapabilities capabilities() const noexcept override;
    void connect_stream(core::StreamRequest request, core::StreamOpenHandler handler) override;
    void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) override;

  private:
    runtime::AsioRuntime &runtime_;
    core::OutboundDescriptor descriptor_{"direct", "direct"};
    core::OutboundCapabilities capabilities_{true, core::DatagramSemantics::unsupported};
};

class RejectOutbound final : public core::Outbound {
  public:
    explicit RejectOutbound(runtime::AsioRuntime &runtime);

    const core::OutboundDescriptor &descriptor() const noexcept override;
    core::OutboundCapabilities capabilities() const noexcept override;
    void connect_stream(core::StreamRequest request, core::StreamOpenHandler handler) override;
    void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) override;

  private:
    runtime::AsioRuntime &runtime_;
    core::OutboundDescriptor descriptor_{"reject", "reject"};
    core::OutboundCapabilities capabilities_{false, core::DatagramSemantics::unsupported};
};

} // namespace clash_native::outbound
