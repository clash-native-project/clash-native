#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/outbound/outbound_registry.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <memory>
#include <string>
#include <string_view>

namespace clash_native::transport {

struct EndpointDialRequirements {
    bool stream = false;
    bool datagram = false;
};

// An immutable selection made before a carrier connection is opened. A
// registry target retains its snapshot and may select a member from a group
// when the dial is executed.
class EndpointDialPlan final {
  public:
    static core::Result<EndpointDialPlan> from_outbound(std::shared_ptr<core::Outbound> outbound,
                                                        std::string egress_identity = {},
                                                        EndpointDialRequirements requirements = {});
    static core::Result<EndpointDialPlan>
    from_registry(outbound::OutboundRegistry::Snapshot registry, std::string target_id,
                  EndpointDialRequirements requirements = {});

    std::string_view egress_identity() const noexcept { return egress_identity_; }

  private:
    EndpointDialPlan(std::shared_ptr<core::Outbound> outbound,
                     outbound::OutboundRegistry::Snapshot registry, std::string target_id,
                     std::string egress_identity);

    core::Result<std::shared_ptr<core::Outbound>> select_outbound() const;

    std::shared_ptr<core::Outbound> outbound_;
    outbound::OutboundRegistry::Snapshot registry_;
    std::string target_id_;
    std::string egress_identity_;

    friend class EndpointDialer;
};

// Executes a prebound endpoint plan. Each request can carry a trace through
// nested outbound calls so accidental recursive chains fail before dialing.
class EndpointDialer final {
  public:
    EndpointDialer(boost::asio::any_io_executor executor, EndpointDialPlan plan);

    void connect_stream(core::StreamRequest request, core::StreamOpenHandler handler) const;
    void open_datagram(core::DatagramRequest request, core::DatagramOpenHandler handler) const;

    std::string_view egress_identity() const noexcept { return plan_.egress_identity(); }

  private:
    core::Result<std::shared_ptr<const core::EndpointDialTrace>>
    extend_trace(const std::shared_ptr<const core::EndpointDialTrace> &trace,
                 std::string_view outbound_id) const;

    boost::asio::any_io_executor executor_;
    EndpointDialPlan plan_;
};

} // namespace clash_native::transport
