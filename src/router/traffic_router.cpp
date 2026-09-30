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

// Pre-parsed rule data for PreparedRule: lowered domain values plus CIDR
// network/prefix, so evaluate() never parses or folds rule strings.
TrafficRouter::PreparedRule prepare_rule(const TrafficRule &rule) {
    TrafficRouter::PreparedRule prepared;
    switch (rule.kind) {
    case RuleKind::domain:
    case RuleKind::domain_suffix:
    case RuleKind::domain_keyword:
        prepared.lowered_value = lower_copy(rule.value);
        break;
    case RuleKind::destination_ip_cidr: {
        const auto separator = rule.value.find('/');
        if (separator == std::string::npos) {
            break;
        }
        boost::system::error_code error;
        const auto network =
            boost::asio::ip::make_address(std::string_view(rule.value).substr(0, separator), error);
        if (error) {
            break;
        }
        unsigned int prefix = 0;
        const auto prefix_text = std::string_view(rule.value).substr(separator + 1);
        const auto parsed =
            std::from_chars(prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
        const auto max_prefix = network.is_v4() ? 32U : 128U;
        if (parsed.ec != std::errc{} || parsed.ptr != prefix_text.data() + prefix_text.size() ||
            prefix > max_prefix) {
            break;
        }
        prepared.cidr_valid = true;
        prepared.network = network;
        prepared.network_bytes = address_bytes(network);
        prepared.prefix = prefix;
        break;
    }
    default:
        break;
    }
    return prepared;
}

bool domain_matches(const core::Destination &destination, const TrafficRule &rule,
                    const TrafficRouter::PreparedRule &prepared, std::string &lowered_cache,
                    bool &lowered_ready) {
    if (!destination.is_domain()) {
        return false;
    }
    // One allocation per evaluate() at most; the old code paid one per rule.
    if (!lowered_ready) {
        lowered_cache = lower_copy(destination.domain());
        lowered_ready = true;
    }
    const std::string_view domain = lowered_cache;
    const std::string_view value = prepared.lowered_value;
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

bool matches_rule(const TrafficRule &rule, const TrafficRouter::PreparedRule &prepared,
                  const core::ConnectionMetadata &metadata, const RoutingContext &context,
                  std::string &lowered_cache, bool &lowered_ready) {
    switch (rule.kind) {
    case RuleKind::domain:
    case RuleKind::domain_suffix:
    case RuleKind::domain_keyword:
        return domain_matches(metadata.destination, rule, prepared, lowered_cache, lowered_ready);
    case RuleKind::network:
        return (rule.value == "tcp" && metadata.network == core::Network::tcp) ||
               (rule.value == "udp" && metadata.network == core::Network::udp);
    case RuleKind::destination_port:
        return metadata.destination.port() >= rule.port_from &&
               metadata.destination.port() <= (rule.port_to == 0 ? rule.port_from : rule.port_to);
    case RuleKind::inbound:
        return rule.value == metadata.inbound_name || rule.value == metadata.inbound_type;
    case RuleKind::destination_ip_cidr: {
        if (!prepared.cidr_valid) {
            return false;
        }
        std::vector<boost::asio::ip::address> addresses;
        if (!context.destination_addresses.empty()) {
            addresses = context.destination_addresses;
        } else if (context.destination_address) {
            addresses.push_back(*context.destination_address);
        } else if (metadata.destination.is_address()) {
            addresses.push_back(metadata.destination.address());
        }
        if (addresses.empty()) {
            return false;
        }
        const auto full_bytes = prepared.prefix / 8;
        const auto remaining_bits = prepared.prefix % 8;
        return std::any_of(addresses.begin(), addresses.end(), [&](const auto &address) {
            if (prepared.network.is_v4() != address.is_v4()) {
                return false;
            }
            const auto target_bytes = address_bytes(address);
            if (!std::equal(prepared.network_bytes.begin(),
                            prepared.network_bytes.begin() + full_bytes, target_bytes.begin())) {
                return false;
            }
            return remaining_bits == 0 ||
                   (prepared.network_bytes[full_bytes] >> (8 - remaining_bits)) ==
                       (target_bytes[full_bytes] >> (8 - remaining_bits));
        });
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

void TrafficRouter::add_rule(TrafficRule rule) {
    prepared_.push_back(prepare_rule(rule));
    rules_.push_back(std::move(rule));
}

TrafficRouter::Snapshot TrafficRouter::snapshot() const {
    return std::make_shared<const TrafficRouter>(*this);
}

core::Status TrafficRouter::validate(std::span<const std::string> outbound_ids) const {
    const auto has_target = [outbound_ids](const std::string &target) {
        return std::find(outbound_ids.begin(), outbound_ids.end(), target) != outbound_ids.end();
    };
    const auto validate_action = [has_target](const RouteAction &action) -> core::Status {
        if (action.kind == RouteActionKind::named &&
            (action.target.empty() || !has_target(action.target))) {
            return core::fail(
                core::Error{core::ErrorCode::configuration,
                            "route action references an unknown outbound: " + action.target});
        }
        return {};
    };

    if (const auto result = validate_action(default_action_); !result) {
        return result;
    }
    for (const auto &rule : rules_) {
        if (const auto result = validate_action(rule.action); !result) {
            return result;
        }
    }
    return {};
}

RuleEvaluation TrafficRouter::evaluate(const core::ConnectionMetadata &metadata,
                                       const RoutingContext &context, std::size_t start) const {
    std::string lowered_domain;
    bool lowered_ready = false;
    for (std::size_t index = start; index < rules_.size(); ++index) {
        const auto &rule = rules_[index];
        if (rule.kind == RuleKind::destination_ip_cidr && context.destination_addresses.empty() &&
            !context.destination_address && !metadata.destination.is_address()) {
            if (!rule.no_resolve && context.destination_lookup == LookupState::unrequested) {
                return NeedMetadata{MetadataNeed::destination_ip, index};
            }
            continue;
        }

        if (matches_rule(rule, prepared_[index], metadata, context, lowered_domain,
                         lowered_ready)) {
            return Matched{RouteDecision{rule.action, rule.id, false}};
        }
    }

    return Matched{RouteDecision{default_action_, {}, true}};
}

} // namespace clash_native::router
