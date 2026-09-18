#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <atomic>
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
    core::Result<core::OutboundCapabilities> capabilities(std::string_view id) const;
    std::vector<std::string> ids() const;
    Snapshot snapshot() const;

  private:
    struct Group {
        std::vector<std::string> members;
        mutable std::atomic<std::size_t> next_member{0};

        Group() = default;
        Group(std::vector<std::string> members, std::size_t next_member = 0)
            : members(std::move(members)), next_member(next_member) {}

        Group(const Group &other)
            : members(other.members),
              next_member(other.next_member.load(std::memory_order_relaxed)) {}

        Group &operator=(const Group &other) {
            if (this == &other) {
                return *this;
            }
            members = other.members;
            next_member.store(other.next_member.load(std::memory_order_relaxed),
                              std::memory_order_relaxed);
            return *this;
        }

        Group(Group &&other) noexcept
            : members(std::move(other.members)),
              next_member(other.next_member.load(std::memory_order_relaxed)) {}

        Group &operator=(Group &&other) noexcept {
            if (this == &other) {
                return *this;
            }
            members = std::move(other.members);
            next_member.store(other.next_member.load(std::memory_order_relaxed),
                              std::memory_order_relaxed);
            return *this;
        }
    };

    core::Status validate_group(std::string_view id, std::vector<std::string> &visiting) const;
    core::Result<core::OutboundCapabilities>
    capabilities_entry(std::string_view id, std::vector<std::string> &visiting) const;
    core::Result<OutboundPtr> select_entry(std::string_view id,
                                           std::vector<std::string> &visiting) const;

    std::unordered_map<std::string, OutboundPtr> outbounds_;
    std::unordered_map<std::string, Group> groups_;
};

} // namespace clash_native::outbound
