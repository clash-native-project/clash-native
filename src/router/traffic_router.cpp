#include <clash_native/router/traffic_router.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <string_view>

namespace clash_native::router {

namespace {

std::string lower_copy(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

std::vector<std::uint8_t> address_bytes(const boost::asio::ip::address &address) {
    if (address.is_v4()) {
        const auto bytes = address.to_v4().to_bytes();
        return {bytes.begin(), bytes.end()};
    }
    const auto bytes = address.to_v6().to_bytes();
    return {bytes.begin(), bytes.end()};
}

bool domain_matches(const core::Destination &destination, const TrafficRule &rule) {
    if (!destination.is_domain()) {
        return false;
    }

    const auto domain = lower_copy(destination.domain());
    const auto value = lower_copy(rule.value);
    switch (rule.kind) {
    case RuleKind::domain:
        return domain == value;
    case RuleKind::domain_suffix:
        return domain == value ||
               (domain.size() > value.size() &&
                domain.compare(domain.size() - value.size(), value.size(), value) == 0 &&
                domain[domain.size() - value.size() - 1] == '.');
    case RuleKind::domain_keyword:
        return domain.find(value) != std::string::npos;
    default:
        return false;
    }
}

bool matches_rule(const TrafficRule &rule, const core::ConnectionMetadata &metadata,
                  const RoutingContext &context) {
    switch (rule.kind) {
    case RuleKind::domain:
    case RuleKind::domain_suffix:
    case RuleKind::domain_keyword:
        return domain_matches(metadata.destination, rule);
    case RuleKind::network:
        return (rule.value == "tcp" && metadata.network == core::Network::tcp) ||
               (rule.value == "udp" && metadata.network == core::Network::udp);
    case RuleKind::destination_port:
        return metadata.destination.port() >= rule.port_from &&
               metadata.destination.port() <= (rule.port_to == 0 ? rule.port_from : rule.port_to);
    case RuleKind::inbound:
        return rule.value == metadata.inbound_name || rule.value == metadata.inbound_type;
    case RuleKind::destination_ip_cidr: {
        const auto address =
            context.destination_address
                ? context.destination_address
                : (metadata.destination.is_address()
                       ? std::optional<boost::asio::ip::address>(metadata.destination.address())
                       : std::nullopt);
        if (!address) {
            return false;
        }

        const auto separator = rule.value.find('/');
        if (separator == std::string::npos) {
            return false;
        }
        boost::system::error_code error;
        const auto network =
            boost::asio::ip::make_address(std::string_view(rule.value).substr(0, separator), error);
        if (error || network.is_v4() != address->is_v4()) {
            return false;
        }
        unsigned int prefix = 0;
        const auto prefix_text = std::string_view(rule.value).substr(separator + 1);
        const auto parsed =
            std::from_chars(prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
        const auto max_prefix = network.is_v4() ? 32U : 128U;
        if (parsed.ec != std::errc{} || parsed.ptr != prefix_text.data() + prefix_text.size() ||
            prefix > max_prefix) {
            return false;
        }

        const auto network_bytes = address_bytes(network);
        const auto target_bytes = address_bytes(*address);
        const auto full_bytes = prefix / 8;
        const auto remaining_bits = prefix % 8;
        if (!std::equal(network_bytes.begin(), network_bytes.begin() + full_bytes,
                        target_bytes.begin())) {
            return false;
        }
        return remaining_bits == 0 || (network_bytes[full_bytes] >> (8 - remaining_bits)) ==
                                          (target_bytes[full_bytes] >> (8 - remaining_bits));
    }
    }

    return false;
}

} // namespace

RouteAction RouteAction::direct() { return {RouteActionKind::direct, {}}; }

RouteAction RouteAction::reject() { return {RouteActionKind::reject, {}}; }

RouteAction RouteAction::named(std::string id) { return {RouteActionKind::named, std::move(id)}; }

TrafficRouter::TrafficRouter(RouteAction default_action)
    : default_action_(std::move(default_action)) {}

void TrafficRouter::set_default_action(RouteAction action) { default_action_ = std::move(action); }

const RouteAction &TrafficRouter::default_action() const noexcept { return default_action_; }

void TrafficRouter::add_rule(TrafficRule rule) { rules_.push_back(std::move(rule)); }

const std::vector<TrafficRule> &TrafficRouter::rules() const noexcept { return rules_; }

TrafficRouter::Snapshot TrafficRouter::snapshot() const {
    return std::make_shared<const TrafficRouter>(*this);
}

RuleEvaluation TrafficRouter::evaluate(const core::ConnectionMetadata &metadata,
                                       const RoutingContext &context, std::size_t start) const {
    for (std::size_t index = start; index < rules_.size(); ++index) {
        const auto &rule = rules_[index];
        if (rule.kind == RuleKind::destination_ip_cidr && !context.destination_address &&
            !metadata.destination.is_address()) {
            if (!rule.no_resolve && context.destination_lookup == LookupState::unrequested) {
                return NeedMetadata{MetadataNeed::destination_ip, index};
            }
            continue;
        }

        if (matches_rule(rule, metadata, context)) {
            return Matched{RouteDecision{rule.action, rule.id, false}};
        }
    }

    return Matched{RouteDecision{default_action_, {}, true}};
}

} // namespace clash_native::router
