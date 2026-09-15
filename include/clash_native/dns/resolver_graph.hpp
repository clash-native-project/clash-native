#pragma once

#include <clash_native/core/result.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace clash_native::dns {

enum class ResolverRole {
    bootstrap,
    default_resolver,
    proxy_endpoint,
    direct,
};

class ResolverDependencyGraph final {
  public:
    core::Status add_resolver(std::string id, ResolverRole role);
    core::Status add_dependency(std::string resolver_id, std::string dependency_id);
    core::Status validate() const;
    std::optional<ResolverRole> role(std::string_view id) const;

  private:
    struct ResolverNode {
        ResolverRole role;
        std::vector<std::string> dependencies;
    };

    core::Status visit(std::string_view id, std::vector<std::string> &visiting,
                       std::vector<std::string> &visited) const;

    std::unordered_map<std::string, ResolverNode> nodes_;
};

} // namespace clash_native::dns
