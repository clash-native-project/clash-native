#include "proxy_session.hpp"

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <iterator>
#include <string>
#include <utility>

namespace clash_native::proxy {

namespace {

constexpr std::uint8_t kSocks4Version = 0x04;
constexpr std::uint8_t kSocks4Connect = 0x01;
constexpr std::uint8_t kSocks4Rejected = 0x5b;
constexpr std::uint8_t kSocks4IdentdMismatched = 0x5d;
constexpr std::size_t kSocks4MaximumStringLength = 256;

bool is_socks4a_address(const std::array<std::uint8_t, 8> &request) {
    return request[4] == 0 && request[5] == 0 && request[6] == 0 && request[7] != 0;
}

std::uint16_t socks4_port(const std::array<std::uint8_t, 8> &request) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(request[2]) << 8) | request[3]);
}

std::optional<std::size_t> null_position(const std::vector<std::uint8_t> &payload) {
    const auto iterator = std::find(payload.begin(), payload.end(), 0);
    if (iterator == payload.end()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(payload.begin(), iterator));
}

} // namespace

void ProxySession::read_socks4_request() {
    auto self = shared_from_this();
    boost::asio::async_read(
        client_, boost::asio::buffer(socks4_request_.data() + 1, socks4_request_.size() - 1),
        [self](const boost::system::error_code &error, std::size_t) {
            if (error || self->socks4_request_[0] != kSocks4Version ||
                self->socks4_request_[1] != kSocks4Connect) {
                self->close();
                return;
            }
            self->socks4_payload_.clear();
            self->read_socks4_user_id();
        });
}

void ProxySession::read_socks4_user_id() {
    if (const auto position = null_position(socks4_payload_)) {
        if (*position > kSocks4MaximumStringLength) {
            close();
            return;
        }
        socks4_user_id_.assign(socks4_payload_.begin(),
                               socks4_payload_.begin() + static_cast<std::ptrdiff_t>(*position));
        socks4_payload_.erase(socks4_payload_.begin(),
                              socks4_payload_.begin() + static_cast<std::ptrdiff_t>(*position + 1));

        if (owner_.socks5_users_.empty()) {
            authenticated_user_ = std::string(socks4_user_id_.begin(), socks4_user_id_.end());
        } else {
            const auto user = std::find_if(
                owner_.socks5_users_.begin(), owner_.socks5_users_.end(),
                [this](const Socks5User &candidate) {
                    return candidate.password.empty() &&
                           candidate.username.size() == socks4_user_id_.size() &&
                           std::equal(candidate.username.begin(), candidate.username.end(),
                                      socks4_user_id_.begin());
                });
            if (user == owner_.socks5_users_.end()) {
                send_socks4_reply(kSocks4IdentdMismatched, false);
                return;
            }
            authenticated_user_ = user->username;
        }

        if (is_socks4a_address(socks4_request_)) {
            read_socks4_domain();
        } else {
            open_socks4_target();
        }
        return;
    }

    if (socks4_payload_.size() > kSocks4MaximumStringLength) {
        close();
        return;
    }
    auto self = shared_from_this();
    auto buffer = std::make_shared<std::array<std::uint8_t, 1024>>();
    client_.async_read_some(
        boost::asio::buffer(*buffer),
        ProxyStream::ReadHandler(
            [self, buffer](const boost::system::error_code &error, std::size_t size) {
                if (error || size == 0 ||
                    self->socks4_payload_.size() + size > kSocks4MaximumStringLength + 1) {
                    self->close();
                    return;
                }
                self->socks4_payload_.insert(self->socks4_payload_.end(), buffer->begin(),
                                             buffer->begin() + static_cast<std::ptrdiff_t>(size));
                self->read_socks4_user_id();
            }));
}

void ProxySession::read_socks4_domain() {
    if (const auto position = null_position(socks4_payload_)) {
        if (*position == 0 || *position > kSocks4MaximumStringLength) {
            send_socks4_reply(kSocks4Rejected, false);
            return;
        }
        socks4_domain_.assign(socks4_payload_.begin(),
                              socks4_payload_.begin() + static_cast<std::ptrdiff_t>(*position));
        socks4_payload_.erase(socks4_payload_.begin(),
                              socks4_payload_.begin() + static_cast<std::ptrdiff_t>(*position + 1));
        open_socks4_target();
        return;
    }

    if (socks4_payload_.size() > kSocks4MaximumStringLength) {
        close();
        return;
    }
    auto self = shared_from_this();
    auto buffer = std::make_shared<std::array<std::uint8_t, 1024>>();
    client_.async_read_some(
        boost::asio::buffer(*buffer),
        ProxyStream::ReadHandler(
            [self, buffer](const boost::system::error_code &error, std::size_t size) {
                if (error || size == 0 ||
                    self->socks4_payload_.size() + size > kSocks4MaximumStringLength + 1) {
                    self->close();
                    return;
                }
                self->socks4_payload_.insert(self->socks4_payload_.end(), buffer->begin(),
                                             buffer->begin() + static_cast<std::ptrdiff_t>(size));
                self->read_socks4_domain();
            }));
}

void ProxySession::open_socks4_target() {
    const auto port = socks4_port(socks4_request_);
    if (is_socks4a_address(socks4_request_)) {
        open_target(core::Destination::domain(
            std::string(socks4_domain_.begin(), socks4_domain_.end()), port));
        return;
    }

    boost::asio::ip::address_v4::bytes_type bytes{};
    std::copy_n(socks4_request_.begin() + 4, bytes.size(), bytes.begin());
    open_target(core::Destination::address(boost::asio::ip::address_v4(bytes), port));
}

void ProxySession::send_socks4_reply(std::uint8_t status, bool start_relay) {
    if (closed_.load(std::memory_order_acquire)) {
        return;
    }
    socks4_reply_[0] = 0x00;
    socks4_reply_[1] = status;
    std::copy(socks4_request_.begin() + 2, socks4_request_.begin() + 8, socks4_reply_.begin() + 2);

    auto self = shared_from_this();
    boost::asio::async_write(
        client_, boost::asio::buffer(socks4_reply_),
        [self, start_relay](const boost::system::error_code &error, std::size_t) {
            if (error || !start_relay) {
                self->close();
                return;
            }
            self->start_relay();
        });
}

} // namespace clash_native::proxy
