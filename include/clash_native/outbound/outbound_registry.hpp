#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace clash_native::outbound {

class OutboundRegistry final {
  public:
    using OutboundPtr = std::shared_ptr<core::Outbound>;
    using Snapshot = std::shared_ptr<const OutboundRegistry>;

    core::Status add_outbound(std::string id, OutboundPtr outbound);
    core::Status add_group(std::string id, std::vector<std::string> members);
    core::Status validate() const;
    core::Result<OutboundPtr> select(std::string_view id) const;
    std::vector<std::string> ids() const;
    Snapshot snapshot() const;

  private:
    struct Group {
        std::vector<std::string> members;
        mutable std::size_t next_member = 0;
    };

    core::Status validate_group(std::string_view id, std::vector<std::string> &visiting) const;
    core::Result<OutboundPtr> select_entry(std::string_view id,
                                           std::vector<std::string> &visiting) const;

    std::unordered_map<std::string, OutboundPtr> outbounds_;
    std::unordered_map<std::string, Group> groups_;
};

} // namespace clash_native::outbound
