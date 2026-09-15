#include <clash_native/dns/resolver_graph.hpp>

#include <algorithm>
#include <utility>

namespace clash_native::dns {

namespace {

core::Error configuration_error(std::string context) {
    return {core::ErrorCode::configuration, std::move(context)};
}

} // namespace

core::Status ResolverDependencyGraph::add_resolver(std::string id, ResolverRole role) {
    if (id.empty()) {
        return core::fail(configuration_error("resolver ID is required"));
    }
    if (nodes_.contains(id)) {
        return core::fail(configuration_error("duplicate resolver ID: " + id));
    }
    nodes_.emplace(std::move(id), ResolverNode{role, {}});
    return {};
}

core::Status ResolverDependencyGraph::add_dependency(std::string resolver_id,
                                                     std::string dependency_id) {
    const auto resolver = nodes_.find(resolver_id);
    if (resolver == nodes_.end()) {
        return core::fail(configuration_error("unknown resolver: " + resolver_id));
    }
    if (!nodes_.contains(dependency_id)) {
        return core::fail(configuration_error("unknown resolver dependency: " + dependency_id));
    }
    if (resolver->second.role == ResolverRole::bootstrap) {
        return core::fail(configuration_error("bootstrap resolver cannot depend on another "
                                              "resolver: " +
                                              dependency_id));
    }
    if (std::find(resolver->second.dependencies.begin(), resolver->second.dependencies.end(),
                  dependency_id) == resolver->second.dependencies.end()) {
        resolver->second.dependencies.push_back(std::move(dependency_id));
    }
    return {};
}

core::Status ResolverDependencyGraph::visit(std::string_view id, std::vector<std::string> &visiting,
                                            std::vector<std::string> &visited) const {
    if (std::find(visited.begin(), visited.end(), id) != visited.end()) {
        return {};
    }
    if (std::find(visiting.begin(), visiting.end(), id) != visiting.end()) {
        return core::fail(configuration_error("resolver dependency cycle at: " + std::string(id)));
    }
    const auto node = nodes_.find(std::string(id));
    if (node == nodes_.end()) {
        return core::fail(configuration_error("unknown resolver dependency: " + std::string(id)));
    }
    visiting.emplace_back(id);
    for (const auto &dependency : node->second.dependencies) {
        const auto result = visit(dependency, visiting, visited);
        if (!result) {
            visiting.pop_back();
            return result;
        }
    }
    visiting.pop_back();
    visited.emplace_back(id);
    return {};
}

core::Status ResolverDependencyGraph::validate() const {
    std::vector<std::string> visiting;
    std::vector<std::string> visited;
    for (const auto &[id, node] : nodes_) {
        const auto result = visit(id, visiting, visited);
        if (!result) {
            return result;
        }
    }
    return {};
}

std::optional<ResolverRole> ResolverDependencyGraph::role(std::string_view id) const {
    const auto node = nodes_.find(std::string(id));
    if (node == nodes_.end()) {
        return std::nullopt;
    }
    return node->second.role;
}

} // namespace clash_native::dns
