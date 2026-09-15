#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/resolver_service.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

std::string cache_key(const DnsQuestion &question) {
    return normalize_name(question.name) + "|" +
           std::to_string(static_cast<std::uint16_t>(question.type)) + "|" +
           std::to_string(question.class_code);
}

core::Error upstream_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "DNS upstream query timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "DNS upstream query was cancelled"};
}

} // namespace

class ResolverService::Operation final
    : public std::enable_shared_from_this<ResolverService::Operation> {
  public:
    struct Waiter {
        RequestId id;
        Handler handler;
    };

    Operation(ResolverService &owner, std::string key, DnsQuestion question, std::uint16_t query_id)
        : owner_(owner), key_(std::move(key)), question_(std::move(question)), query_id_(query_id),
          udp_socket_(owner.runtime_.context()), tcp_socket_(owner.runtime_.context()),
          timeout_timer_(owner.runtime_.context()) {}

    const std::string &key() const noexcept { return key_; }

    void add_waiter(RequestId id, Handler handler) { waiters_.push_back({id, std::move(handler)}); }

    bool remove_waiter(RequestId id) {
        const auto old_size = waiters_.size();
        waiters_.erase(std::remove_if(waiters_.begin(), waiters_.end(),
                                      [id](const Waiter &waiter) { return waiter.id == id; }),
                       waiters_.end());
        return old_size != waiters_.size();
    }

    bool has_waiters() const noexcept { return !waiters_.empty(); }

    std::vector<Waiter> take_waiters() { return std::move(waiters_); }

    void start() {
        const auto encoded = DnsMessageCodec::encode_query(question_, query_id_);
        if (!encoded) {
            finish(core::fail(encoded.error()));
            return;
        }
        query_ = encoded.value();

        timeout_timer_.expires_after(owner_.config_.timeout);
        auto self = shared_from_this();
        timeout_timer_.async_wait([self](const boost::system::error_code &error) {
            if (!error) {
                self->finish(core::fail(timeout_error()));
            }
        });

        if (owner_.config_.prefer_tcp) {
            start_tcp();
            return;
        }

        boost::system::error_code error;
        udp_socket_.open(owner_.config_.endpoint.protocol(), error);
        if (error) {
            finish(core::fail(upstream_error("failed to open DNS UDP socket", error)));
            return;
        }
        udp_socket_.async_send_to(boost::asio::buffer(query_), owner_.config_.endpoint,
                                  [self](const boost::system::error_code &send_error, std::size_t) {
                                      if (send_error) {
                                          self->finish(core::fail(upstream_error(
                                              "failed to send DNS UDP query", send_error)));
                                          return;
                                      }
                                      self->receive_udp();
                                  });
    }

    void cancel_shared() { finish(core::fail(cancelled_error())); }

  private:
    void receive_udp() {
        if (completed_) {
            return;
        }
        auto self = shared_from_this();
        udp_socket_.async_receive_from(
            boost::asio::buffer(response_buffer_), sender_,
            [self](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    self->finish(
                        core::fail(upstream_error("failed to receive DNS UDP response", error)));
                    return;
                }
                if (size < 2 ||
                    static_cast<std::uint16_t>(self->response_buffer_[0] << 8 |
                                               self->response_buffer_[1]) != self->query_id_) {
                    self->receive_udp();
                    return;
                }

                const auto response = DnsMessageCodec::decode_response(
                    std::span<const std::uint8_t>(self->response_buffer_.data(), size),
                    self->query_id_);
                if (!response) {
                    self->finish(core::fail(response.error()));
                    return;
                }
                if (response.value().truncated) {
                    self->start_tcp();
                    return;
                }
                self->finish(response);
            });
    }

    void start_tcp() {
        boost::system::error_code error;
        udp_socket_.close(error);
        const auto endpoint = owner_.config_.tcp_endpoint.value_or(boost::asio::ip::tcp::endpoint(
            owner_.config_.endpoint.address(), owner_.config_.endpoint.port()));
        tcp_socket_.open(endpoint.protocol(), error);
        if (error) {
            finish(core::fail(upstream_error("failed to open DNS TCP socket", error)));
            return;
        }

        auto self = shared_from_this();
        tcp_socket_.async_connect(endpoint, [self](const boost::system::error_code &connect_error) {
            if (connect_error) {
                self->finish(core::fail(
                    upstream_error("failed to connect to DNS TCP upstream", connect_error)));
                return;
            }

            self->tcp_query_.resize(2 + self->query_.size());
            self->tcp_query_[0] = static_cast<std::uint8_t>(self->query_.size() >> 8);
            self->tcp_query_[1] = static_cast<std::uint8_t>(self->query_.size() & 0xff);
            std::copy(self->query_.begin(), self->query_.end(), self->tcp_query_.begin() + 2);
            boost::asio::async_write(
                self->tcp_socket_, boost::asio::buffer(self->tcp_query_),
                [self](const boost::system::error_code &write_error, std::size_t) {
                    if (write_error) {
                        self->finish(core::fail(
                            upstream_error("failed to send DNS TCP query", write_error)));
                        return;
                    }
                    self->read_tcp_length();
                });
        });
    }

    void read_tcp_length() {
        auto self = shared_from_this();
        boost::asio::async_read(
            tcp_socket_, boost::asio::buffer(tcp_length_),
            [self](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    self->finish(
                        core::fail(upstream_error("failed to receive DNS TCP length", error)));
                    return;
                }
                const auto size =
                    static_cast<std::size_t>(self->tcp_length_[0] << 8 | self->tcp_length_[1]);
                if (size == 0 || size > self->response_buffer_.size()) {
                    self->finish(core::fail(
                        {core::ErrorCode::protocol_framing, "DNS TCP response length is invalid"}));
                    return;
                }
                self->tcp_response_.resize(size);
                boost::asio::async_read(
                    self->tcp_socket_, boost::asio::buffer(self->tcp_response_),
                    [self](const boost::system::error_code &read_error, std::size_t) {
                        if (read_error) {
                            self->finish(core::fail(
                                upstream_error("failed to receive DNS TCP response", read_error)));
                            return;
                        }
                        const auto response =
                            DnsMessageCodec::decode_response(self->tcp_response_, self->query_id_);
                        if (!response) {
                            self->finish(core::fail(response.error()));
                            return;
                        }
                        self->finish(response);
                    });
            });
    }

    void finish(core::Result<DnsAnswer> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        timeout_timer_.cancel();
        boost::system::error_code ignored;
        udp_socket_.close(ignored);
        tcp_socket_.close(ignored);
        owner_.complete(shared_from_this(), std::move(result));
    }

    ResolverService &owner_;
    std::string key_;
    DnsQuestion question_;
    std::uint16_t query_id_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::tcp::socket tcp_socket_;
    boost::asio::steady_timer timeout_timer_;
    boost::asio::ip::udp::endpoint sender_;
    std::array<std::uint8_t, 4096> response_buffer_{};
    std::array<std::uint8_t, 2> tcp_length_{};
    std::vector<std::uint8_t> query_;
    std::vector<std::uint8_t> tcp_query_;
    std::vector<std::uint8_t> tcp_response_;
    std::vector<Waiter> waiters_;
    bool completed_ = false;
};

ResolverService::ResolverService(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
    : runtime_(runtime), config_(std::move(config)) {}

ResolverService::~ResolverService() { stop(); }

ResolverService::RequestId ResolverService::resolve(DnsQuestion question, Handler handler) {
    const auto request_id = next_request_id_++;
    if (stopped_) {
        boost::asio::post(runtime_.context(), [handler = std::move(handler)]() mutable {
            handler(core::fail(cancelled_error()));
        });
        return request_id;
    }

    question.name = normalize_name(question.name);
    const auto key = cache_key(question);
    const auto now = std::chrono::steady_clock::now();
    if (const auto cached = cache_.find(key); cached != cache_.end()) {
        if (cached->second.expires > now) {
            const auto answer = cached->second.answer;
            boost::asio::post(runtime_.context(),
                              [handler = std::move(handler), answer = std::move(answer)]() mutable {
                                  handler(answer);
                              });
            return request_id;
        }
        cache_.erase(cached);
    }

    if (const auto existing = in_flight_.find(key); existing != in_flight_.end()) {
        existing->second->add_waiter(request_id, std::move(handler));
        requests_[request_id] = existing->second;
        return request_id;
    }

    const auto query_id = next_query_id_++;
    auto operation = std::make_shared<Operation>(*this, key, std::move(question), query_id);
    operation->add_waiter(request_id, std::move(handler));
    in_flight_.emplace(key, operation);
    requests_[request_id] = operation;
    operation->start();
    return request_id;
}

void ResolverService::cancel(RequestId request_id) noexcept {
    const auto request = requests_.find(request_id);
    if (request == requests_.end()) {
        return;
    }
    auto operation = request->second.lock();
    requests_.erase(request);
    if (!operation || !operation->remove_waiter(request_id)) {
        return;
    }
    if (!operation->has_waiters()) {
        operation->cancel_shared();
    }
}

void ResolverService::stop() noexcept {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    std::vector<std::shared_ptr<Operation>> operations;
    operations.reserve(in_flight_.size());
    for (const auto &[key, operation] : in_flight_) {
        operations.push_back(operation);
    }
    for (const auto &operation : operations) {
        operation->cancel_shared();
    }
    in_flight_.clear();
    requests_.clear();
}

void ResolverService::clear_cache() noexcept { cache_.clear(); }

std::size_t ResolverService::cache_size() const noexcept { return cache_.size(); }

void ResolverService::complete(const std::shared_ptr<Operation> &operation,
                               core::Result<DnsAnswer> result) {
    const auto in_flight = in_flight_.find(operation->key());
    if (in_flight != in_flight_.end() && in_flight->second == operation) {
        in_flight_.erase(in_flight);
    }

    if (result) {
        const auto ttl =
            result.value().negative()
                ? std::chrono::seconds(30)
                : std::chrono::seconds(std::max<std::uint32_t>(1, result.value().ttl_seconds));
        cache_[operation->key()] = {result.value(), std::chrono::steady_clock::now() + ttl};
    }

    auto waiters = operation->take_waiters();
    for (const auto &waiter : waiters) {
        requests_.erase(waiter.id);
    }
    for (auto &waiter : waiters) {
        waiter.handler(result);
    }
}

} // namespace clash_native::dns
