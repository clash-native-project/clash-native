#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_server.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <semaphore>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

core::Error listener_error(std::string operation, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, "failed to " + std::move(operation),
            std::error_code(error.value(), std::system_category())};
}

std::size_t udp_payload_limit(const DnsPacket &query) {
    const auto opt = std::find_if(
        query.additionals.begin(), query.additionals.end(), [](const DnsResourceRecord &record) {
            return record.type == static_cast<std::uint16_t>(DnsRecordType::opt);
        });
    if (opt == query.additionals.end()) {
        return 512;
    }
    return std::max<std::size_t>(512, opt->class_code);
}

core::Result<std::vector<std::uint8_t>>
limit_udp_response(const DnsPacket &query, core::Result<std::vector<std::uint8_t>> response) {
    if (!response) {
        return core::fail(response.error());
    }
    return DnsMessageCodec::truncate_udp_response(response.value(), udp_payload_limit(query));
}

std::optional<core::Result<std::vector<std::uint8_t>>>
fake_ip_response(const DnsPacket &query, const std::shared_ptr<FakeIpStore> &store,
                 const std::function<bool(std::string_view)> &filter) {
    if (!store || !filter || query.response() || query.questions.size() != 1 ||
        query.questions.front().type != DnsRecordType::a || !filter(query.questions.front().name)) {
        return std::nullopt;
    }

    const auto address = store->resolve(query.questions.front().name);
    if (!address) {
        return DnsMessageCodec::encode_error_response(query, 2);
    }

    DnsAnswer answer;
    answer.question = query.questions.front();
    answer.addresses.push_back(address.value());
    answer.ttl_seconds = 60;
    return DnsMessageCodec::encode_response(query, answer);
}

} // namespace

DnsServer::DnsServer(runtime::AsioRuntime &runtime, ResolverService &resolver,
                     boost::asio::ip::udp::endpoint udp_endpoint,
                     boost::asio::ip::tcp::endpoint tcp_endpoint)
    : DnsServer(runtime, resolver.query_service(), udp_endpoint, tcp_endpoint) {}

DnsServer::DnsServer(runtime::AsioRuntime &runtime, DnsQueryService &query_service,
                     boost::asio::ip::udp::endpoint udp_endpoint,
                     boost::asio::ip::tcp::endpoint tcp_endpoint)
    : runtime_(runtime), query_service_(&query_service),
      udp_socket_(runtime.context().get_executor()), tcp_acceptor_(runtime.context()),
      udp_endpoint_(udp_endpoint), tcp_endpoint_(tcp_endpoint),
      callback_gate_(std::make_shared<std::atomic_bool>(false)) {}

DnsServer::DnsServer(runtime::AsioRuntime &runtime,
                     std::shared_ptr<runtime::RuntimeSnapshotStore> snapshot_store,
                     boost::asio::ip::udp::endpoint udp_endpoint,
                     boost::asio::ip::tcp::endpoint tcp_endpoint)
    : runtime_(runtime), snapshot_store_(std::move(snapshot_store)),
      udp_socket_(runtime.context().get_executor()), tcp_acceptor_(runtime.context()),
      udp_endpoint_(udp_endpoint), tcp_endpoint_(tcp_endpoint),
      callback_gate_(std::make_shared<std::atomic_bool>(false)) {
    if (!snapshot_store_) {
        throw std::invalid_argument("DNS server requires a runtime snapshot store");
    }
}

DnsServer::~DnsServer() { stop(); }

core::Status DnsServer::start() {
    if (running_.load(std::memory_order_acquire)) {
        return {};
    }

    boost::system::error_code error;
    udp_socket_.open(udp_endpoint_.protocol(), error);
    if (!error) {
        udp_socket_.set_option(boost::asio::socket_base::reuse_address(true), error);
    }
    if (!error) {
        udp_socket_.bind(udp_endpoint_, error);
    }
    if (!error) {
        tcp_acceptor_.open(tcp_endpoint_.protocol(), error);
    }
    if (!error) {
        tcp_acceptor_.set_option(boost::asio::socket_base::reuse_address(true), error);
    }
    if (!error) {
        tcp_acceptor_.bind(tcp_endpoint_, error);
    }
    if (!error) {
        tcp_acceptor_.listen(boost::asio::socket_base::max_listen_connections, error);
    }
    if (error) {
        spdlog::error("DNS server failed to open local listeners: {}", error.message());
        boost::system::error_code ignored;
        udp_socket_.close();
        tcp_acceptor_.close(ignored);
        return core::fail(listener_error("open the local DNS server", error));
    }

    udp_endpoint_ = udp_socket_.local_endpoint(error);
    if (!error) {
        tcp_endpoint_ = tcp_acceptor_.local_endpoint(error);
    }
    if (error) {
        spdlog::error("DNS server failed to query local listener endpoints: {}", error.message());
        boost::system::error_code ignored;
        udp_socket_.close();
        tcp_acceptor_.close(ignored);
        return core::fail(listener_error("query the local DNS server endpoint", error));
    }

    callback_gate_ = std::make_shared<std::atomic_bool>(true);
    running_.store(true, std::memory_order_release);
    spdlog::info("DNS server listening on UDP {}:{} and TCP {}:{}",
                 udp_endpoint_.address().to_string(), udp_endpoint_.port(),
                 tcp_endpoint_.address().to_string(), tcp_endpoint_.port());
    receive_udp();
    accept_tcp();
    return {};
}

void DnsServer::stop() noexcept {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        spdlog::debug("DNS server stop requested while already stopped");
        return;
    }
    spdlog::debug("Stopping DNS server");
    callback_gate_->store(false, std::memory_order_release);

    if (!runtime_.running()) {
        stop_on_owner();
        return;
    }

    std::binary_semaphore completed(0);
    boost::asio::dispatch(runtime_.context(), [this, &completed] {
        stop_on_owner();
        completed.release();
    });
    completed.acquire();
}

void DnsServer::set_fake_ip_store(std::shared_ptr<FakeIpStore> store,
                                  std::function<bool(std::string_view)> filter) {
    if (running()) {
        throw std::logic_error("Cannot change FakeIP configuration on a running DNS server");
    }
    fake_ip_store_ = std::move(store);
    fake_ip_filter_ = std::move(filter);
}

void DnsServer::stop_on_owner() noexcept {
    for (const auto &[token, request] : query_requests_) {
        (void)token;
        if (request.query_service != nullptr && request.request_id != 0) {
            request.query_service->cancel(request.request_id);
        }
    }
    query_requests_.clear();

    boost::system::error_code ignored;
    udp_socket_.close();
    tcp_acceptor_.cancel(ignored);
    tcp_acceptor_.close(ignored);
    for (const auto &socket : tcp_sockets_) {
        socket->cancel(ignored);
        socket->close(ignored);
    }
    tcp_sockets_.clear();
    spdlog::debug("DNS server stopped");
}

bool DnsServer::running() const noexcept { return running_.load(std::memory_order_acquire); }

boost::asio::ip::udp::endpoint DnsServer::udp_endpoint() const noexcept { return udp_endpoint_; }

boost::asio::ip::tcp::endpoint DnsServer::tcp_endpoint() const noexcept { return tcp_endpoint_; }

runtime::RuntimeSnapshotPtr DnsServer::current_snapshot() const noexcept {
    return snapshot_store_ ? snapshot_store_->load() : nullptr;
}

void DnsServer::receive_udp() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }
    const auto gate = callback_gate_;
    udp_socket_.async_receive_from(
        boost::asio::buffer(udp_buffer_),
        [this, gate](const boost::system::error_code &error, std::size_t size,
                     boost::asio::ip::udp::endpoint sender) {
            if (!gate->load(std::memory_order_acquire)) {
                return;
            }
            if (!error) {
                const auto query = DnsMessageCodec::decode_packet(
                    std::span<const std::uint8_t>(udp_buffer_.data(), size));
                if (query) {
                    resolve_udp(std::move(query.value()), std::move(sender));
                }
            }
            if (gate->load(std::memory_order_acquire)) {
                receive_udp();
            }
        });
}

void DnsServer::accept_tcp() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }
    const auto gate = callback_gate_;
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(runtime_.context());
    tcp_acceptor_.async_accept(*socket,
                               [this, gate, socket](const boost::system::error_code &error) {
                                   if (!gate->load(std::memory_order_acquire)) {
                                       return;
                                   }
                                   if (!error && running_.load(std::memory_order_acquire)) {
                                       tcp_sockets_.insert(socket);
                                       read_tcp_query(socket);
                                   }
                                   if (gate->load(std::memory_order_acquire)) {
                                       accept_tcp();
                                   }
                               });
}

void DnsServer::read_tcp_query(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
    const auto gate = callback_gate_;
    auto length = std::make_shared<std::array<std::uint8_t, 2>>();
    boost::asio::async_read(
        *socket, boost::asio::buffer(*length),
        [this, gate, socket, length](const boost::system::error_code &error, std::size_t) {
            if (!gate->load(std::memory_order_acquire)) {
                return;
            }
            if (error) {
                close_tcp_socket(socket);
                return;
            }
            const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
            if (size == 0 || size > udp_buffer_.size()) {
                close_tcp_socket(socket);
                return;
            }
            auto payload = std::make_shared<std::vector<std::uint8_t>>(size);
            boost::asio::async_read(*socket, boost::asio::buffer(*payload),
                                    [this, gate, socket, payload](
                                        const boost::system::error_code &read_error, std::size_t) {
                                        if (!gate->load(std::memory_order_acquire)) {
                                            return;
                                        }
                                        if (read_error) {
                                            close_tcp_socket(socket);
                                            return;
                                        }
                                        const auto query = DnsMessageCodec::decode_packet(*payload);
                                        if (query) {
                                            resolve_tcp(socket, std::move(query.value()));
                                            return;
                                        }
                                        close_tcp_socket(socket);
                                    });
        });
}

void DnsServer::close_tcp_socket(
    const std::shared_ptr<boost::asio::ip::tcp::socket> &socket) noexcept {
    if (!socket) {
        return;
    }
    boost::system::error_code ignored;
    socket->cancel(ignored);
    socket->close(ignored);
    tcp_sockets_.erase(socket);
}

void DnsServer::resolve_udp(DnsPacket query, boost::asio::ip::udp::endpoint sender) {
    const auto gate = callback_gate_;
    const auto snapshot = current_snapshot();
    const auto &fake_store = snapshot ? snapshot->fake_ip_store : fake_ip_store_;
    const auto &fake_filter = snapshot ? snapshot->fake_ip_filter : fake_ip_filter_;
    if (const auto fake_response = fake_ip_response(query, fake_store, fake_filter)) {
        const auto response = limit_udp_response(query, *fake_response);
        if (!response || response.value().size() > 0xffff) {
            return;
        }
        auto payload = std::make_shared<std::vector<std::uint8_t>>(response.value());
        udp_socket_.async_send_to(boost::asio::buffer(*payload), sender,
                                  [payload](const boost::system::error_code &, std::size_t) {});
        return;
    }
    auto resolver_owner = snapshot ? snapshot->resolver : resolver_owner_;
    auto *query_service =
        snapshot && resolver_owner != nullptr ? &resolver_owner->query_service() : query_service_;
    if (query_service == nullptr) {
        const auto response =
            limit_udp_response(query, DnsMessageCodec::encode_error_response(query, 2));
        if (response) {
            auto payload = std::make_shared<std::vector<std::uint8_t>>(response.value());
            udp_socket_.async_send_to(boost::asio::buffer(*payload), sender,
                                      [payload](const boost::system::error_code &, std::size_t) {});
        }
        return;
    }
    const auto token = next_query_request_id_++;
    query_requests_.emplace(token, PendingQuery{resolver_owner, query_service, 0});
    const auto request_id = std::make_shared<DnsQueryService::RequestId>();
    const auto query_copy = query;
    *request_id = query_service->query(
        std::move(query),
        [this, gate, token, resolver_owner, query = query_copy,
         sender](core::Result<DnsPacket> result) mutable {
            (void)resolver_owner;
            if (!gate->load(std::memory_order_acquire)) {
                return;
            }
            query_requests_.erase(token);
            const auto response = limit_udp_response(
                query, result ? core::Result<std::vector<std::uint8_t>>(result.value().wire)
                              : DnsMessageCodec::encode_error_response(query, 2));
            if (!response || response.value().size() > 0xffff) {
                return;
            }
            auto payload = std::make_shared<std::vector<std::uint8_t>>(response.value());
            udp_socket_.async_send_to(boost::asio::buffer(*payload), sender,
                                      [payload](const boost::system::error_code &, std::size_t) {});
        },
        runtime_.scheduler());
    if (const auto pending = query_requests_.find(token); pending != query_requests_.end()) {
        pending->second.request_id = *request_id;
    }
}

void DnsServer::resolve_tcp(std::shared_ptr<boost::asio::ip::tcp::socket> socket, DnsPacket query) {
    const auto gate = callback_gate_;
    const auto snapshot = current_snapshot();
    const auto &fake_store = snapshot ? snapshot->fake_ip_store : fake_ip_store_;
    const auto &fake_filter = snapshot ? snapshot->fake_ip_filter : fake_ip_filter_;
    if (const auto fake_response = fake_ip_response(query, fake_store, fake_filter)) {
        if (!*fake_response || fake_response->value().size() > 0xffff) {
            close_tcp_socket(socket);
            return;
        }
        auto frame = std::make_shared<std::vector<std::uint8_t>>();
        frame->reserve(2 + fake_response->value().size());
        frame->push_back(static_cast<std::uint8_t>(fake_response->value().size() >> 8));
        frame->push_back(static_cast<std::uint8_t>(fake_response->value().size() & 0xff));
        frame->insert(frame->end(), fake_response->value().begin(), fake_response->value().end());
        boost::asio::async_write(
            *socket, boost::asio::buffer(*frame),
            [this, gate, socket, frame](const boost::system::error_code &error, std::size_t) {
                if (!gate->load(std::memory_order_acquire) || error) {
                    close_tcp_socket(socket);
                    return;
                }
                read_tcp_query(socket);
            });
        return;
    }
    auto resolver_owner = snapshot ? snapshot->resolver : resolver_owner_;
    auto *query_service =
        snapshot && resolver_owner != nullptr ? &resolver_owner->query_service() : query_service_;
    if (query_service == nullptr) {
        const auto response = DnsMessageCodec::encode_error_response(query, 2);
        if (!response || response.value().size() > 0xffff) {
            close_tcp_socket(socket);
            return;
        }
        auto frame = std::make_shared<std::vector<std::uint8_t>>();
        frame->reserve(2 + response.value().size());
        frame->push_back(static_cast<std::uint8_t>(response.value().size() >> 8));
        frame->push_back(static_cast<std::uint8_t>(response.value().size() & 0xff));
        frame->insert(frame->end(), response.value().begin(), response.value().end());
        boost::asio::async_write(
            *socket, boost::asio::buffer(*frame),
            [this, gate, socket, frame](const boost::system::error_code &error, std::size_t) {
                if (!gate->load(std::memory_order_acquire) || error) {
                    close_tcp_socket(socket);
                    return;
                }
                read_tcp_query(socket);
            });
        return;
    }
    const auto token = next_query_request_id_++;
    query_requests_.emplace(token, PendingQuery{resolver_owner, query_service, 0});
    const auto request_id = std::make_shared<DnsQueryService::RequestId>();
    const auto query_copy = query;
    *request_id = query_service->query(
        std::move(query),
        [this, gate, token, resolver_owner, socket = std::move(socket),
         query = query_copy](core::Result<DnsPacket> result) mutable {
            (void)resolver_owner;
            if (!gate->load(std::memory_order_acquire)) {
                return;
            }
            query_requests_.erase(token);
            const auto response = result
                                      ? core::Result<std::vector<std::uint8_t>>(result.value().wire)
                                      : DnsMessageCodec::encode_error_response(query, 2);
            if (!response || response.value().size() > 0xffff) {
                close_tcp_socket(socket);
                return;
            }
            auto frame = std::make_shared<std::vector<std::uint8_t>>();
            frame->reserve(2 + response.value().size());
            frame->push_back(static_cast<std::uint8_t>(response.value().size() >> 8));
            frame->push_back(static_cast<std::uint8_t>(response.value().size() & 0xff));
            frame->insert(frame->end(), response.value().begin(), response.value().end());
            boost::asio::async_write(
                *socket, boost::asio::buffer(*frame),
                [this, gate, socket, frame](const boost::system::error_code &error, std::size_t) {
                    if (!gate->load(std::memory_order_acquire) || error) {
                        close_tcp_socket(socket);
                        return;
                    }
                    read_tcp_query(socket);
                });
        },
        runtime_.scheduler());
    if (const auto pending = query_requests_.find(token); pending != query_requests_.end()) {
        pending->second.request_id = *request_id;
    }
}

} // namespace clash_native::dns
