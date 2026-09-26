#pragma once

#include <clash_native/async/bridge.hpp>
#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/outbound/outbound_registry.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <exception>
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

// Extends a dial trace with one outbound hop, rejecting cycles and
// over-deep chains. Chaining outbounds extend with their own ID before
// dialing through a nested EndpointDialer (which extends with the target).
core::Result<std::shared_ptr<const core::EndpointDialTrace>>
extend_endpoint_trace(const std::shared_ptr<const core::EndpointDialTrace> &trace,
                      std::string_view outbound_id);

// Drives a chained stream open into a bridge handler, unwrapping the
// StreamOpenResult into the transported handle.
struct ChainedStreamReceiver {
    using receiver_concept = stdexec::receiver_tag;
    async::BridgeSender<core::Result<std::unique_ptr<io::StreamHandle>>>::Handler handler;
    void set_value(core::StreamOpenResult result) && noexcept {
        auto done = std::move(handler);
        if (result.status == core::OpenStatus::opened && result.handle) {
            done(core::Result<std::unique_ptr<io::StreamHandle>>{std::move(result.handle)});
            return;
        }
        if (result.error) {
            done(core::fail(result.error.value()));
            return;
        }
        done(core::fail(
            core::Error{core::ErrorCode::endpoint_connection, "chained outbound dial failed", {}}));
    }
    void set_error(std::exception_ptr error) && noexcept {
        auto done = std::move(handler);
        try {
            std::rethrow_exception(std::move(error));
        } catch (const core::Error &failure) {
            done(core::fail(failure));
        } catch (...) {
            done(core::fail(core::Error{
                core::ErrorCode::endpoint_connection, "chained outbound dial failed", {}}));
        }
    }
    void set_stopped() && noexcept {
        auto done = std::move(handler);
        done(core::fail(
            core::Error{core::ErrorCode::cancelled, "chained outbound dial was cancelled", {}}));
    }
};

// Drives a chained datagram open into a bridge handler.
struct ChainedDatagramReceiver {
    using receiver_concept = stdexec::receiver_tag;
    async::BridgeSender<core::DatagramOpenResult>::Handler handler;
    void set_value(core::DatagramOpenResult result) && noexcept {
        auto done = std::move(handler);
        done(std::move(result));
    }
    void set_error(std::exception_ptr error) && noexcept {
        auto done = std::move(handler);
        try {
            std::rethrow_exception(std::move(error));
        } catch (const core::Error &failure) {
            done(core::DatagramOpenResult::failed(failure));
        } catch (...) {
            done(core::DatagramOpenResult::failed(
                {core::ErrorCode::endpoint_connection, "chained datagram open failed", {}}));
        }
    }
    void set_stopped() && noexcept {
        auto done = std::move(handler);
        done(core::DatagramOpenResult::failed(
            {core::ErrorCode::cancelled, "chained datagram open was cancelled", {}}));
    }
};

// Executes a prebound endpoint plan. Each request can carry a trace through
// nested outbound calls so accidental recursive chains fail before dialing.
class EndpointDialer final {
  public:
    EndpointDialer(boost::asio::any_io_executor executor, EndpointDialPlan plan);

    io::AnySender<core::StreamOpenResult> connect_stream(core::StreamRequest request) const;
    io::AnySender<core::DatagramOpenResult> open_datagram(core::DatagramRequest request) const;

    std::string_view egress_identity() const noexcept { return plan_.egress_identity(); }

  private:
    core::Result<std::shared_ptr<const core::EndpointDialTrace>>
    extend_trace(const std::shared_ptr<const core::EndpointDialTrace> &trace,
                 std::string_view outbound_id) const;

    boost::asio::any_io_executor executor_;
    EndpointDialPlan plan_;
};

} // namespace clash_native::transport
