#pragma once

#include <clash_native/core/result.hpp>

#include <boost/asio/ip/address_v4.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace clash_native::dns {

class FakeIpStore final {
  public:
    explicit FakeIpStore(
        boost::asio::ip::address_v4 network = boost::asio::ip::make_address_v4("198.18.0.0"),
        std::uint8_t prefix = 15, std::size_t capacity = 65534);

    core::Status configure(boost::asio::ip::address_v4 network, std::uint8_t prefix,
                           std::size_t capacity);
    core::Result<boost::asio::ip::address_v4> resolve(std::string_view domain);
    std::optional<std::string> reverse(boost::asio::ip::address_v4 address) const;
    bool release(std::string_view domain) noexcept;
    void clear() noexcept;
    std::size_t size() const noexcept;

  private:
    std::uint32_t network_ = 0;
    std::uint8_t prefix_ = 0;
    std::uint32_t first_offset_ = 1;
    std::uint32_t address_count_ = 0;
    std::uint32_t next_offset_ = 1;
    std::size_t capacity_ = 0;
    std::unordered_map<std::string, boost::asio::ip::address_v4> by_domain_;
    std::unordered_map<std::uint32_t, std::string> by_address_;
};

} // namespace clash_native::dns
