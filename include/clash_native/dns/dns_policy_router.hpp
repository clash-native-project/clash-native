#pragma once

#include <clash_native/dns/dns_types.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace clash_native::dns {

enum class DnsPolicyRuleKind {
    exact,
    suffix,
    keyword,
};

struct DnsPolicyRule {
    std::string id;
    DnsPolicyRuleKind kind = DnsPolicyRuleKind::suffix;
    std::string value;
    std::string upstream_group;
};

struct DnsPolicyDecision {
    std::string upstream_group;
    std::string matched_rule;
    bool used_default = false;
};

class DnsPolicyRouter final {
  public:
    explicit DnsPolicyRouter(std::string default_upstream = "default");

    void set_default_upstream(std::string upstream);
    const std::string &default_upstream() const noexcept;
    void add_rule(DnsPolicyRule rule);
    const std::vector<DnsPolicyRule> &rules() const noexcept;
    DnsPolicyDecision select(std::string_view name) const;

  private:
    std::string default_upstream_;
    std::vector<DnsPolicyRule> rules_;
};

} // namespace clash_native::dns
