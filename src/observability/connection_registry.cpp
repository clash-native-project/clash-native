#include <clash_native/observability/connection_registry.hpp>

#include <utility>

namespace clash_native::observability {

ConnectionRegistry::ConnectionId ConnectionRegistry::add(core::ConnectionMetadata metadata,
                                                         std::string outbound_id) {
    const auto id = next_id_++;
    records_.emplace(id, ConnectionRecord{id, std::move(metadata), std::move(outbound_id)});
    return id;
}

bool ConnectionRegistry::update_outbound(ConnectionId id, std::string outbound_id) {
    const auto found = records_.find(id);
    if (found == records_.end()) {
        return false;
    }
    found->second.outbound_id = std::move(outbound_id);
    return true;
}

bool ConnectionRegistry::remove(ConnectionId id) noexcept { return records_.erase(id) != 0; }

std::optional<ConnectionRecord> ConnectionRegistry::find(ConnectionId id) const {
    const auto found = records_.find(id);
    if (found == records_.end()) {
        return std::nullopt;
    }
    return found->second;
}

std::vector<ConnectionRecord> ConnectionRegistry::snapshot() const {
    std::vector<ConnectionRecord> result;
    result.reserve(records_.size());
    for (const auto &[id, record] : records_) {
        result.push_back(record);
    }
    return result;
}

std::size_t ConnectionRegistry::size() const noexcept { return records_.size(); }

} // namespace clash_native::observability
