#include <clash_native/transport/endpoint_dialer.hpp>

#include <boost/asio/post.hpp>

#include <algorithm>
#include <utility>

namespace clash_native::transport {

namespace {

constexpr std::size_t kMaximumOutboundChainDepth = 8;

core::Error configuration_error(std::string message) {
    return {core::ErrorCode::configuration, std::move(message), {}};
}

core::Status validate_requirements(const core::OutboundCapabilities &capabilities,
                                   EndpointDialRequirements requirements,
                                   std::string_view identity) {
    if (requirements.stream && !capabilities.stream) {
        return core::fail(configuration_error("endpoint plan target lacks stream support: " +
                                              std::string(identity)));
    }
    if (requirements.datagram && capabilities.datagram == core::DatagramSemantics::unsupported) {
        return core::fail(configuration_error("endpoint plan target lacks datagram support: " +
                                              std::string(identity)));
    }
    return {};
}

} // namespace

EndpointDialPlan::EndpointDialPlan(std::shared_ptr<core::Outbound> outbound,
                                   outbound::OutboundRegistry::Snapshot registry,
                                   std::string target_id, std::string egress_identity)
    : outbound_(std::move(outbound)), registry_(std::move(registry)),
      target_id_(std::move(target_id)), egress_identity_(std::move(egress_identity)) {}

core::Result<EndpointDialPlan>
EndpointDialPlan::from_outbound(std::shared_ptr<core::Outbound> outbound,
                                std::string egress_identity,
                                EndpointDialRequirements requirements) {
    if (!outbound) {
        return core::fail(configuration_error("endpoint dial plan requires an outbound"));
    }
    if (egress_identity.empty()) {
        egress_identity = outbound->descriptor().id;
    }
    if (egress_identity.empty()) {
        return core::fail(configuration_error("endpoint dial plan requires an egress identity"));
    }
    if (const auto valid =
            validate_requirements(outbound->capabilities(), requirements, egress_identity);
        !valid) {
        return core::fail(valid.error());
    }
    return EndpointDialPlan(std::move(outbound), {}, {}, std::move(egress_identity));
}

core::Result<EndpointDialPlan>
EndpointDialPlan::from_registry(outbound::OutboundRegistry::Snapshot registry,
                                std::string target_id, EndpointDialRequirements requirements) {
    if (!registry || target_id.empty()) {
        return core::fail(
            configuration_error("endpoint dial plan requires an outbound registry target"));
    }
    const auto ids = registry->ids();
    if (std::find(ids.begin(), ids.end(), target_id) == ids.end()) {
        return core::fail(
            configuration_error("endpoint dial plan references an unknown target: " + target_id));
    }
    const auto capabilities = registry->capabilities(target_id);
    if (!capabilities) {
        return core::fail(capabilities.error());
    }
    if (const auto valid = validate_requirements(capabilities.value(), requirements, target_id);
        !valid) {
        return core::fail(valid.error());
    }
    const auto identity = target_id;
    return EndpointDialPlan({}, std::move(registry), std::move(target_id), identity);
}

core::Result<std::shared_ptr<core::Outbound>> EndpointDialPlan::select_outbound() const {
    if (outbound_) {
        return outbound_;
    }
    if (!registry_) {
        return core::fail(configuration_error("endpoint dial plan has no outbound target"));
    }
    return registry_->select(target_id_);
}

EndpointDialer::EndpointDialer(boost::asio::any_io_executor executor, EndpointDialPlan plan)
    : executor_(std::move(executor)), plan_(std::move(plan)) {}

core::Result<std::shared_ptr<const core::EndpointDialTrace>>
EndpointDialer::extend_trace(const std::shared_ptr<const core::EndpointDialTrace> &trace,
                             std::string_view outbound_id) const {
    if (outbound_id.empty()) {
        return core::fail(configuration_error("selected outbound has no stable ID"));
    }
    core::EndpointDialTrace next = trace ? *trace : core::EndpointDialTrace{};
    if (next.outbound_ids.size() >= kMaximumOutboundChainDepth) {
        return core::fail(configuration_error("endpoint outbound chain exceeds the depth limit"));
    }
    if (std::find(next.outbound_ids.begin(), next.outbound_ids.end(), outbound_id) !=
        next.outbound_ids.end()) {
        return core::fail(configuration_error("endpoint outbound chain contains a runtime cycle: " +
                                              std::string(outbound_id)));
    }
    next.outbound_ids.emplace_back(outbound_id);
    return std::make_shared<const core::EndpointDialTrace>(std::move(next));
}

void EndpointDialer::connect_stream(core::StreamRequest request,
                                    core::StreamOpenHandler handler) const {
    const auto selected = plan_.select_outbound();
    if (!selected) {
        boost::asio::post(executor_,
                          [handler = std::move(handler), error = selected.error()]() mutable {
                              handler(core::StreamOpenResult::failed(error));
                          });
        return;
    }
    const auto outbound = selected.value();
    if (!outbound->capabilities().stream) {
        boost::asio::post(executor_, [handler = std::move(handler)]() mutable {
            handler(core::StreamOpenResult::unsupported());
        });
        return;
    }
    const auto trace = extend_trace(request.dial_trace, outbound->descriptor().id);
    if (!trace) {
        boost::asio::post(executor_,
                          [handler = std::move(handler), error = trace.error()]() mutable {
                              handler(core::StreamOpenResult::failed(error));
                          });
        return;
    }
    request.dial_trace = trace.value();
    outbound->connect_stream(std::move(request), std::move(handler));
}

void EndpointDialer::open_datagram(core::DatagramRequest request,
                                   core::DatagramOpenHandler handler) const {
    const auto selected = plan_.select_outbound();
    if (!selected) {
        boost::asio::post(executor_,
                          [handler = std::move(handler), error = selected.error()]() mutable {
                              handler(core::DatagramOpenResult::failed(error));
                          });
        return;
    }
    const auto outbound = selected.value();
    if (outbound->capabilities().datagram == core::DatagramSemantics::unsupported) {
        boost::asio::post(executor_, [handler = std::move(handler)]() mutable {
            handler(core::DatagramOpenResult::unsupported());
        });
        return;
    }
    const auto trace = extend_trace(request.dial_trace, outbound->descriptor().id);
    if (!trace) {
        boost::asio::post(executor_,
                          [handler = std::move(handler), error = trace.error()]() mutable {
                              handler(core::DatagramOpenResult::failed(error));
                          });
        return;
    }
    request.dial_trace = trace.value();
    outbound->open_datagram(std::move(request), std::move(handler));
}

} // namespace clash_native::transport
