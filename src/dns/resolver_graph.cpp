#include <clash_native/dns/resolver_graph.hpp>

#include <algorithm>
#include <utility>

namespace clash_native::dns {

namespace {

core::Error configuration_error(std::string context) {
    return {core::ErrorCode::configuration, std::move(context)};
}

} // namespace

core::Status ResolverDependencyGraph::add_node(std::string id, DependencyNodeKind kind) {
    if (id.empty()) {
        return core::fail(configuration_error("dependency node ID is required"));
    }
    if (nodes_.contains(id)) {
        return core::fail(configuration_error("duplicate dependency node ID: " + id));
    }
    nodes_.emplace(std::move(id), ResolverNode{kind, std::nullopt, {}});
    return {};
}

core::Status ResolverDependencyGraph::add_resolver(std::string id, ResolverRole role) {
    if (id.empty()) {
        return core::fail(configuration_error("resolver ID is required"));
    }
    if (nodes_.contains(id)) {
        return core::fail(configuration_error("duplicate resolver ID: " + id));
    }
    for (const auto &[existing_id, node] : nodes_) {
        if (node.role && *node.role == role) {
            return core::fail(configuration_error("duplicate resolver role for: " + existing_id));
        }
    }
    nodes_.emplace(std::move(id), ResolverNode{DependencyNodeKind::resolver, role, {}});
    return {};
}

core::Status ResolverDependencyGraph::add_dns_upstream(std::string id) {
    return add_node(std::move(id), DependencyNodeKind::dns_upstream);
}

core::Status ResolverDependencyGraph::add_outbound(std::string id) {
    return add_node(std::move(id), DependencyNodeKind::outbound);
}

core::Status ResolverDependencyGraph::add_outbound_group(std::string id) {
    return add_node(std::move(id), DependencyNodeKind::outbound_group);
}

core::Status ResolverDependencyGraph::add_proxy_endpoint(std::string id) {
    return add_node(std::move(id), DependencyNodeKind::proxy_endpoint);
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
        return core::fail(configuration_error("dependency cycle at: " + std::string(id)));
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

    for (const auto &[id, node] : nodes_) {
        if (!node.role || *node.role != ResolverRole::bootstrap) {
            continue;
        }
        std::vector<std::string> pending(node.dependencies.begin(), node.dependencies.end());
        std::vector<std::string> visited_bootstrap;
        while (!pending.empty()) {
            auto current = std::move(pending.back());
            pending.pop_back();
            if (std::find(visited_bootstrap.begin(), visited_bootstrap.end(), current) !=
                visited_bootstrap.end()) {
                continue;
            }
            visited_bootstrap.push_back(current);
            const auto dependency = nodes_.find(current);
            if (dependency == nodes_.end()) {
                return core::fail(configuration_error("unknown bootstrap dependency: " + current));
            }
            if (dependency->second.role) {
                return core::fail(configuration_error(
                    "bootstrap resolver transitively depends on resolver: " + current));
            }
            pending.insert(pending.end(), dependency->second.dependencies.begin(),
                           dependency->second.dependencies.end());
        }
    }
    return {};
}

std::optional<DependencyNodeKind> ResolverDependencyGraph::kind(std::string_view id) const {
    const auto node = nodes_.find(std::string(id));
    if (node == nodes_.end()) {
        return std::nullopt;
    }
    return node->second.kind;
}

const std::vector<std::string> *
ResolverDependencyGraph::dependencies(std::string_view id) const noexcept {
    const auto node = nodes_.find(std::string(id));
    return node == nodes_.end() ? nullptr : &node->second.dependencies;
}

std::optional<ResolverRole> ResolverDependencyGraph::role(std::string_view id) const {
    const auto node = nodes_.find(std::string(id));
    if (node == nodes_.end()) {
        return std::nullopt;
    }
    return node->second.role;
}

} // namespace clash_native::dns
