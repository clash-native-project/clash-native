#pragma once

#include <clash_native/core/metadata.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace clash_native::observability {

struct ConnectionRecord {
    std::uint64_t id = 0;
    core::ConnectionMetadata metadata;
    std::string outbound_id;
};

class ConnectionRegistry final {
  public:
    using ConnectionId = std::uint64_t;

    ConnectionId add(core::ConnectionMetadata metadata, std::string outbound_id);
    bool update_outbound(ConnectionId id, std::string outbound_id);
    bool remove(ConnectionId id) noexcept;
    std::optional<ConnectionRecord> find(ConnectionId id) const;
    std::vector<ConnectionRecord> snapshot() const;
    std::size_t size() const noexcept;

  private:
    ConnectionId next_id_ = 1;
    std::unordered_map<ConnectionId, ConnectionRecord> records_;
};

} // namespace clash_native::observability
