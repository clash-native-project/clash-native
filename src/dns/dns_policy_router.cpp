#include <clash_native/dns/dns_policy_router.hpp>

#include <algorithm>
#include <cctype>

namespace clash_native::dns {

namespace {

bool matches(const DnsPolicyRule &rule, std::string_view name) {
    const auto value = normalize_name(rule.value);
    switch (rule.kind) {
    case DnsPolicyRuleKind::exact:
        return name == value;
    case DnsPolicyRuleKind::suffix:
        return name == value ||
               (name.size() > value.size() &&
                name.compare(name.size() - value.size(), value.size(), value) == 0 &&
                name[name.size() - value.size() - 1] == '.');
    case DnsPolicyRuleKind::keyword:
        return name.find(value) != std::string_view::npos;
    }
    return false;
}

} // namespace

DnsPolicyRouter::DnsPolicyRouter(std::string default_upstream)
    : default_upstream_(std::move(default_upstream)) {}

void DnsPolicyRouter::set_default_upstream(std::string upstream) {
    default_upstream_ = std::move(upstream);
}

const std::string &DnsPolicyRouter::default_upstream() const noexcept { return default_upstream_; }

void DnsPolicyRouter::add_rule(DnsPolicyRule rule) { rules_.push_back(std::move(rule)); }

const std::vector<DnsPolicyRule> &DnsPolicyRouter::rules() const noexcept { return rules_; }

DnsPolicyDecision DnsPolicyRouter::select(std::string_view name) const {
    const auto normalized = normalize_name(name);
    for (const auto &rule : rules_) {
        if (matches(rule, normalized)) {
            return {rule.upstream_group, rule.id, false};
        }
    }
    return {default_upstream_, {}, true};
}

} // namespace clash_native::dns
