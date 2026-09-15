#pragma once

#include <clash_native/core/metadata.hpp>

#include <boost/asio/ip/address.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace clash_native::router {

enum class RouteActionKind {
    direct,
    reject,
    named,
};

struct RouteAction {
    RouteActionKind kind = RouteActionKind::direct;
    std::string target;

    static RouteAction direct();
    static RouteAction reject();
    static RouteAction named(std::string id);
};

struct RouteDecision {
    RouteAction action;
    std::string matched_rule;
    bool used_default = false;
};

struct NoMatch {};

struct Matched {
    RouteDecision decision;
};

enum class MetadataNeed {
    destination_ip,
    process_info,
};

struct NeedMetadata {
    MetadataNeed need;
};

using RuleEvaluation = std::variant<NoMatch, Matched, NeedMetadata>;

enum class RuleKind {
    domain,
    domain_suffix,
    domain_keyword,
    network,
    destination_port,
    inbound,
    destination_ip_cidr,
};

struct TrafficRule {
    std::string id;
    RuleKind kind = RuleKind::domain;
    std::string value;
    std::uint16_t port_from = 0;
    std::uint16_t port_to = 0;
    bool no_resolve = false;
    RouteAction action;
};

enum class LookupState {
    unrequested,
    in_progress,
    resolved,
    failed,
};

struct RoutingContext {
    LookupState destination_lookup = LookupState::unrequested;
    std::optional<boost::asio::ip::address> destination_address;
};

class TrafficRouter {
  public:
    explicit TrafficRouter(RouteAction default_action = RouteAction::direct());

    void set_default_action(RouteAction action);
    const RouteAction &default_action() const noexcept;
    void add_rule(TrafficRule rule);
    const std::vector<TrafficRule> &rules() const noexcept;

    RuleEvaluation evaluate(const core::ConnectionMetadata &metadata, const RoutingContext &context,
                            std::size_t start = 0) const;

  private:
    RouteAction default_action_;
    std::vector<TrafficRule> rules_;
};

} // namespace clash_native::router
