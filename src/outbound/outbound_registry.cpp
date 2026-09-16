#include <clash_native/outbound/outbound_registry.hpp>

#include <algorithm>
#include <utility>

namespace clash_native::outbound {

namespace {

core::Error configuration_error(std::string context) {
    return {core::ErrorCode::configuration, std::move(context)};
}

} // namespace

core::Status OutboundRegistry::add_outbound(std::string id, OutboundPtr outbound) {
    if (id.empty() || !outbound) {
        return core::fail(configuration_error("outbound ID and instance are required"));
    }
    if (outbounds_.contains(id) || groups_.contains(id)) {
        return core::fail(configuration_error("duplicate outbound entry: " + id));
    }
    outbounds_.emplace(std::move(id), std::move(outbound));
    return {};
}

core::Status OutboundRegistry::add_group(std::string id, std::vector<std::string> members) {
    if (id.empty() || members.empty()) {
        return core::fail(configuration_error("outbound group ID and members are required"));
    }
    if (outbounds_.contains(id) || groups_.contains(id)) {
        return core::fail(configuration_error("duplicate outbound entry: " + id));
    }
    if (std::any_of(members.begin(), members.end(),
                    [](const std::string &member) { return member.empty(); })) {
        return core::fail(configuration_error("outbound group members cannot be empty"));
    }
    groups_.emplace(std::move(id), Group{std::move(members), 0});
    return {};
}

core::Status OutboundRegistry::validate_group(std::string_view id,
                                              std::vector<std::string> &visiting) const {
    if (outbounds_.contains(std::string(id))) {
        return {};
    }
    const auto group = groups_.find(std::string(id));
    if (group == groups_.end()) {
        return core::fail(configuration_error("unknown outbound target: " + std::string(id)));
    }
    if (std::find(visiting.begin(), visiting.end(), id) != visiting.end()) {
        return core::fail(
            configuration_error("outbound group dependency cycle at: " + std::string(id)));
    }

    visiting.emplace_back(id);
    for (const auto &member : group->second.members) {
        const auto result = validate_group(member, visiting);
        if (!result) {
            visiting.pop_back();
            return result;
        }
    }
    visiting.pop_back();
    return {};
}

core::Status OutboundRegistry::validate() const {
    std::vector<std::string> visiting;
    for (const auto &[id, group] : groups_) {
        const auto result = validate_group(id, visiting);
        if (!result) {
            return result;
        }
    }
    return {};
}

core::Result<OutboundRegistry::OutboundPtr>
OutboundRegistry::select_entry(std::string_view id, std::vector<std::string> &visiting) const {
    const auto outbound = outbounds_.find(std::string(id));
    if (outbound != outbounds_.end()) {
        return outbound->second;
    }

    const auto group = groups_.find(std::string(id));
    if (group == groups_.end()) {
        return core::fail(configuration_error("unknown outbound target: " + std::string(id)));
    }
    if (std::find(visiting.begin(), visiting.end(), id) != visiting.end()) {
        return core::fail(
            configuration_error("outbound group dependency cycle at: " + std::string(id)));
    }

    visiting.emplace_back(id);
    const auto begin = group->second.next_member.fetch_add(1, std::memory_order_relaxed) %
                       group->second.members.size();
    core::Result<OutboundPtr> last_error =
        core::fail(configuration_error("outbound group has no usable member: " + std::string(id)));
    for (std::size_t offset = 0; offset < group->second.members.size(); ++offset) {
        const auto result = select_entry(
            group->second.members[(begin + offset) % group->second.members.size()], visiting);
        if (result) {
            visiting.pop_back();
            return result;
        }
        last_error = result;
    }
    visiting.pop_back();
    return last_error;
}

core::Result<OutboundRegistry::OutboundPtr> OutboundRegistry::select(std::string_view id) const {
    std::vector<std::string> visiting;
    return select_entry(id, visiting);
}

std::vector<std::string> OutboundRegistry::ids() const {
    std::vector<std::string> result;
    result.reserve(outbounds_.size() + groups_.size());
    for (const auto &[id, outbound] : outbounds_) {
        result.push_back(id);
    }
    for (const auto &[id, group] : groups_) {
        result.push_back(id);
    }
    return result;
}

OutboundRegistry::Snapshot OutboundRegistry::snapshot() const {
    return std::make_shared<const OutboundRegistry>(*this);
}

} // namespace clash_native::outbound
