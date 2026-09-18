#pragma once

#include <clash_native/core/error.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace clash_native::core {

enum class DatagramSemantics {
    unsupported,
    fixed_destination,
    multi_destination,
};

enum class TargetRequirement {
    domain_or_ip,
    ip_required,
};

enum class OpenStatus {
    opened,
    failed,
    unsupported,
};

class Destination {
  public:
    static Destination domain(std::string value, std::uint16_t port) {
        return Destination(std::move(value), port);
    }

    static Destination address(boost::asio::ip::address value, std::uint16_t port) {
        return Destination(std::move(value), port);
    }

    bool is_domain() const noexcept { return std::holds_alternative<std::string>(value_); }
    bool is_address() const noexcept {
        return std::holds_alternative<boost::asio::ip::address>(value_);
    }

    const std::string &domain() const { return std::get<std::string>(value_); }
    const boost::asio::ip::address &address() const {
        return std::get<boost::asio::ip::address>(value_);
    }
    std::uint16_t port() const noexcept { return port_; }

  private:
    Destination(std::string value, std::uint16_t port) : value_(std::move(value)), port_(port) {}
    Destination(boost::asio::ip::address value, std::uint16_t port)
        : value_(std::move(value)), port_(port) {}

    std::variant<std::string, boost::asio::ip::address> value_;
    std::uint16_t port_;
};

struct OutboundDescriptor {
    std::string id;
    std::string protocol;
};

struct OutboundCapabilities {
    bool stream = false;
    DatagramSemantics datagram = DatagramSemantics::unsupported;
    TargetRequirement stream_target = TargetRequirement::domain_or_ip;
    TargetRequirement datagram_target = TargetRequirement::domain_or_ip;
};

struct EndpointDialTrace {
    std::vector<std::string> outbound_ids;
};

struct StreamRequest {
    Destination destination;
    std::optional<boost::asio::ip::address> resolved_address;
    std::shared_ptr<const EndpointDialTrace> dial_trace;
};

struct DatagramRequest {
    std::optional<Destination> initial_destination;
    std::shared_ptr<const EndpointDialTrace> dial_trace;
};

class StreamHandle {
  public:
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
    using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    virtual void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) = 0;
    virtual void async_write(boost::asio::const_buffer buffer, WriteHandler handler) = 0;
    virtual boost::asio::any_io_executor executor() noexcept = 0;
    virtual boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept = 0;
    virtual void shutdown_send(boost::system::error_code &error) noexcept = 0;
    virtual void close() noexcept = 0;

    virtual ~StreamHandle() = default;
};

class DatagramHandle {
  public:
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t,
                                           boost::asio::ip::udp::endpoint)>;
    using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    virtual void async_send_to(boost::asio::const_buffer buffer,
                               boost::asio::ip::udp::endpoint destination,
                               WriteHandler handler) = 0;
    virtual void async_receive_from(boost::asio::mutable_buffer buffer, ReadHandler handler) = 0;
    virtual boost::asio::any_io_executor executor() noexcept = 0;
    virtual std::size_t max_datagram_size() const noexcept { return 65507; }
    virtual void cancel() noexcept = 0;
    virtual void close() noexcept = 0;

    virtual ~DatagramHandle() = default;
};

struct StreamOpenResult {
    OpenStatus status = OpenStatus::failed;
    std::unique_ptr<StreamHandle> handle;
    bool application_data_committed = false;
    std::optional<Error> error;

    static StreamOpenResult opened(std::unique_ptr<StreamHandle> value,
                                   bool application_data_committed = false) {
        return {OpenStatus::opened, std::move(value), application_data_committed, std::nullopt};
    }

    static StreamOpenResult failed(Error value, bool application_data_committed = false) {
        return {OpenStatus::failed, nullptr, application_data_committed, std::move(value)};
    }

    static StreamOpenResult unsupported() {
        return {OpenStatus::unsupported, nullptr, false,
                Error{ErrorCode::unsupported, "stream operation is not supported"}};
    }

    bool succeeded() const noexcept { return status == OpenStatus::opened && handle != nullptr; }
};

struct DatagramOpenResult {
    OpenStatus status = OpenStatus::failed;
    std::unique_ptr<DatagramHandle> handle;
    DatagramSemantics semantics = DatagramSemantics::unsupported;
    std::optional<Error> error;

    static DatagramOpenResult opened(std::unique_ptr<DatagramHandle> value,
                                     DatagramSemantics semantics) {
        return {OpenStatus::opened, std::move(value), semantics, std::nullopt};
    }

    static DatagramOpenResult failed(Error value) {
        return {OpenStatus::failed, nullptr, DatagramSemantics::unsupported, std::move(value)};
    }

    static DatagramOpenResult unsupported() {
        return {OpenStatus::unsupported, nullptr, DatagramSemantics::unsupported,
                Error{ErrorCode::unsupported, "datagram operation is not supported"}};
    }

    bool succeeded() const noexcept { return status == OpenStatus::opened && handle != nullptr; }
};

using StreamOpenHandler = std::function<void(StreamOpenResult)>;
using DatagramOpenHandler = std::function<void(DatagramOpenResult)>;

class Outbound {
  public:
    virtual const OutboundDescriptor &descriptor() const noexcept = 0;
    virtual OutboundCapabilities capabilities() const noexcept = 0;

    // An open handler must be called exactly once, including for unsupported operations.
    virtual void connect_stream(StreamRequest request, StreamOpenHandler handler) = 0;
    virtual void open_datagram(DatagramRequest request, DatagramOpenHandler handler) = 0;

    virtual ~Outbound() = default;
};

} // namespace clash_native::core
