#include "proxy_session.hpp"

#include <clash_native/async/async.hpp>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <exec/asio/use_sender.hpp>

#include <stdexec/execution.hpp>

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

stdexec::task<void> ProxySession::run_socks4_request(std::shared_ptr<ProxySession> self) {
    try {
        co_await read_handshake_exact(self, boost::asio::buffer(self->socks4_request_.data() + 1,
                                                                self->socks4_request_.size() - 1));
    } catch (...) {
        self->close();
        co_return;
    }
    if (self->socks4_request_[0] != kSocks4Version || self->socks4_request_[1] != kSocks4Connect) {
        self->close();
        co_return;
    }
    // NUL-terminated user-id then (for SOCKS4a) domain via one shared task
    // helper instead of two re-armed receivers.
    try {
        self->socks4_user_id_ = co_await read_socks4_cstring(self);
    } catch (...) {
        self->close();
        co_return;
    }
    if (self->socks4_user_id_.size() > kSocks4MaximumStringLength) {
        self->close();
        co_return;
    }
    if (self->owner_.socks5_users_.empty()) {
        self->authenticated_user_ =
            std::string(self->socks4_user_id_.begin(), self->socks4_user_id_.end());
    } else {
        const auto user =
            std::find_if(self->owner_.socks5_users_.begin(), self->owner_.socks5_users_.end(),
                         [self](const Socks5User &candidate) {
                             return candidate.password.empty() &&
                                    candidate.username.size() == self->socks4_user_id_.size() &&
                                    std::equal(candidate.username.begin(), candidate.username.end(),
                                               self->socks4_user_id_.begin());
                         });
        if (user == self->owner_.socks5_users_.end()) {
            self->send_socks4_reply(kSocks4IdentdMismatched, false);
            co_return;
        }
        self->authenticated_user_ = user->username;
    }
    if (is_socks4a_address(self->socks4_request_)) {
        try {
            self->socks4_domain_ = co_await read_socks4_cstring(self);
        } catch (...) {
            self->close();
            co_return;
        }
        if (self->socks4_domain_.empty() ||
            self->socks4_domain_.size() > kSocks4MaximumStringLength) {
            self->send_socks4_reply(kSocks4Rejected, false);
            co_return;
        }
    }
    self->open_socks4_target();
}

stdexec::task<std::vector<std::uint8_t>>
ProxySession::read_socks4_cstring(std::shared_ptr<ProxySession> self) {
    self->socks4_payload_.clear();
    std::array<std::uint8_t, 1024> chunk{};
    while (true) {
        if (const auto position = null_position(self->socks4_payload_)) {
            std::vector<std::uint8_t> text(self->socks4_payload_.begin(),
                                           self->socks4_payload_.begin() +
                                               static_cast<std::ptrdiff_t>(*position));
            self->socks4_payload_.erase(self->socks4_payload_.begin(),
                                        self->socks4_payload_.begin() +
                                            static_cast<std::ptrdiff_t>(*position + 1));
            co_return text;
        }
        if (self->socks4_payload_.size() > kSocks4MaximumStringLength) {
            throw core::Error{core::ErrorCode::protocol_framing, "SOCKS4 string too long"};
        }
        std::optional<std::size_t> pulled;
        try {
            pulled = co_await self->client_.async_read_some(boost::asio::buffer(chunk));
        } catch (...) {
            throw core::Error{core::ErrorCode::transport_io, "SOCKS4 handshake read failed"};
        }
        if (!pulled || *pulled == 0 ||
            self->socks4_payload_.size() + *pulled > kSocks4MaximumStringLength + 1) {
            throw core::Error{core::ErrorCode::protocol_framing, "SOCKS4 string too long"};
        }
        self->socks4_payload_.insert(self->socks4_payload_.end(), chunk.begin(),
                                     chunk.begin() + static_cast<std::ptrdiff_t>(*pulled));
    }
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
    auto self = shared_from_this();
    async::spawn_detached(run_socks4_reply(self, status, start_relay));
}

stdexec::task<void> ProxySession::run_socks4_reply(std::shared_ptr<ProxySession> self,
                                                   std::uint8_t status, bool start_relay) {
    if (self->closed_.load(std::memory_order_acquire)) {
        co_return;
    }
    self->socks4_reply_[0] = 0x00;
    self->socks4_reply_[1] = status;
    std::copy(self->socks4_request_.begin() + 2, self->socks4_request_.begin() + 8,
              self->socks4_reply_.begin() + 2);
    try {
        co_await (boost::asio::async_write(self->client_, boost::asio::buffer(self->socks4_reply_),
                                           exec::asio::use_sender) |
                  stdexec::then([](std::size_t) {}) |
                  stdexec::let_error([](std::exception_ptr error) {
                      try {
                          std::rethrow_exception(std::move(error));
                      } catch (const boost::system::system_error &failure) {
                          return stdexec::just_error(std::make_exception_ptr(core::Error{
                              core::ErrorCode::transport_io, "SOCKS4 handshake write failed",
                              std::error_code(failure.code().value(), std::system_category())}));
                      }
                      std::rethrow_exception(std::current_exception());
                  }));
    } catch (...) {
        self->close();
        co_return;
    }
    if (!start_relay) {
        self->close();
        co_return;
    }
    self->start_relay();
}

} // namespace clash_native::proxy
