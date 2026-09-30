#include <clash_native/dns/dns_policy_router.hpp>

#include <algorithm>
#include <cctype>

namespace clash_native::dns {

namespace {

bool matches(const DnsPolicyRule &rule, std::string_view normalized_value, std::string_view name) {
    switch (rule.kind) {
    case DnsPolicyRuleKind::exact:
        return name == normalized_value;
    case DnsPolicyRuleKind::suffix:
        return name == normalized_value ||
               (name.size() > normalized_value.size() &&
                name.compare(name.size() - normalized_value.size(), normalized_value.size(),
                             normalized_value) == 0 &&
                name[name.size() - normalized_value.size() - 1] == '.');
    case DnsPolicyRuleKind::keyword:
        return name.find(normalized_value) != std::string_view::npos;
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

void DnsPolicyRouter::add_rule(DnsPolicyRule rule) {
    normalized_values_.push_back(normalize_name(rule.value));
    rules_.push_back(std::move(rule));
}

const std::vector<DnsPolicyRule> &DnsPolicyRouter::rules() const noexcept { return rules_; }

DnsPolicyDecision DnsPolicyRouter::select(std::string_view name) const {
    const auto normalized = normalize_name(name);
    for (std::size_t index = 0; index < rules_.size(); ++index) {
        if (matches(rules_[index], normalized_values_[index], normalized)) {
            return {rules_[index].upstream_group, rules_[index].id, false};
        }
    }
    return {default_upstream_, {}, true};
}

} // namespace clash_native::dns
