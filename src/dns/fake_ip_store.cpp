#include <clash_native/dns/dns_types.hpp>
#include <clash_native/dns/fake_ip_store.hpp>

#include <limits>
#include <utility>

namespace clash_native::dns {

namespace {

core::Error configuration_error(std::string context) {
    return {core::ErrorCode::configuration, std::move(context)};
}

core::Error exhaustion_error() {
    return {core::ErrorCode::unsupported, "FakeIP address pool is exhausted"};
}

} // namespace

FakeIpStore::FakeIpStore(boost::asio::ip::address_v4 network, std::uint8_t prefix,
                         std::size_t capacity) {
    const auto result = configure(network, prefix, capacity);
    if (!result) {
        network_ = 0;
        prefix_ = 32;
        first_offset_ = 0;
        address_count_ = 0;
        capacity_ = 0;
    }
}

core::Status FakeIpStore::configure(boost::asio::ip::address_v4 network, std::uint8_t prefix,
                                    std::size_t capacity) {
    if (prefix > 30 || capacity == 0) {
        return core::fail(configuration_error("FakeIP requires a non-empty IPv4 pool"));
    }
    const auto total = std::uint64_t{1} << (32 - prefix);
    if (capacity > total - 2 || capacity > std::numeric_limits<std::uint32_t>::max()) {
        return core::fail(configuration_error("FakeIP pool capacity exceeds the network"));
    }

    clear();
    const auto mask = prefix == 0 ? 0U : static_cast<std::uint32_t>(0xffffffffU << (32 - prefix));
    network_ = network.to_uint() & mask;
    prefix_ = prefix;
    first_offset_ = 1;
    address_count_ = static_cast<std::uint32_t>(total - 2);
    next_offset_ = first_offset_;
    capacity_ = capacity;
    return {};
}

core::Result<boost::asio::ip::address_v4> FakeIpStore::resolve(std::string_view domain) {
    const auto normalized = normalize_name(domain);
    if (normalized.empty()) {
        return core::fail(configuration_error("FakeIP requires a non-empty domain"));
    }
    if (const auto existing = by_domain_.find(normalized); existing != by_domain_.end()) {
        return existing->second;
    }
    if (by_domain_.size() >= capacity_ || address_count_ == 0) {
        return core::fail(exhaustion_error());
    }

    for (std::uint64_t attempt = 0; attempt < address_count_; ++attempt) {
        const auto offset = first_offset_ + (next_offset_ - first_offset_) % address_count_;
        next_offset_ = first_offset_ + (offset - first_offset_ + 1) % address_count_;
        const auto value = network_ + offset;
        if (!by_address_.contains(value)) {
            const auto address = boost::asio::ip::address_v4(value);
            by_domain_.emplace(normalized, address);
            by_address_.emplace(value, normalized);
            return address;
        }
    }
    return core::fail(exhaustion_error());
}

std::optional<std::string> FakeIpStore::reverse(boost::asio::ip::address_v4 address) const {
    const auto found = by_address_.find(address.to_uint());
    if (found == by_address_.end()) {
        return std::nullopt;
    }
    return found->second;
}

bool FakeIpStore::release(std::string_view domain) noexcept {
    const auto normalized = normalize_name(domain);
    const auto found = by_domain_.find(normalized);
    if (found == by_domain_.end()) {
        return false;
    }
    by_address_.erase(found->second.to_uint());
    by_domain_.erase(found);
    return true;
}

void FakeIpStore::clear() noexcept {
    by_domain_.clear();
    by_address_.clear();
}

std::size_t FakeIpStore::size() const noexcept { return by_domain_.size(); }

} // namespace clash_native::dns
