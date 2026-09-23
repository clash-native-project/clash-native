#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_policy_router.hpp>
#include <clash_native/dns/dns_query_service.hpp>
#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/outbound/builtin_outbound.hpp>
#include <clash_native/outbound/outbound_registry.hpp>
#include <clash_native/transport/http_sessions.hpp>

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>

#include <nghttp2/nghttp2.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

struct FakeTransportStats {
    std::atomic_int exchanges{0};
    std::atomic_int cancellations{0};
    std::shared_ptr<std::promise<void>> exchange_started;
};

using FakeResponseFactory = std::function<clash_native::core::Result<clash_native::dns::DnsPacket>(
    const clash_native::dns::DnsPacket &)>;

void append_u16(std::vector<std::uint8_t> &message, std::uint16_t value) {
    message.push_back(static_cast<std::uint8_t>(value >> 8));
    message.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void append_u32(std::vector<std::uint8_t> &message, std::uint32_t value) {
    message.push_back(static_cast<std::uint8_t>(value >> 24));
    message.push_back(static_cast<std::uint8_t>(value >> 16));
    message.push_back(static_cast<std::uint8_t>(value >> 8));
    message.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void append_name(std::vector<std::uint8_t> &message, std::string_view name) {
    std::size_t begin = 0;
    while (begin < name.size()) {
        const auto end = name.find('.', begin);
        const auto label_end = end == std::string_view::npos ? name.size() : end;
        message.push_back(static_cast<std::uint8_t>(label_end - begin));
        message.insert(message.end(), name.begin() + static_cast<std::ptrdiff_t>(begin),
                       name.begin() + static_cast<std::ptrdiff_t>(label_end));
        if (end == std::string_view::npos) {
            break;
        }
        begin = end + 1;
    }
    message.push_back(0);
}

clash_native::core::Result<clash_native::dns::DnsPacket>
cname_response(const clash_native::dns::DnsPacket &query, std::string_view target) {
    auto response = query.wire;
    response[2] = 0x81;
    response[3] = 0x80;
    response[6] = 0;
    response[7] = 1;
    response.insert(response.end(), {0xc0, 0x0c});
    append_u16(response, static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::cname));
    append_u16(response, 1);
    append_u32(response, 20);
    std::vector<std::uint8_t> target_wire;
    append_name(target_wire, target);
    append_u16(response, static_cast<std::uint16_t>(target_wire.size()));
    response.insert(response.end(), target_wire.begin(), target_wire.end());
    return clash_native::dns::DnsMessageCodec::decode_packet(response, query.id);
}

class FakeDnsTransport final : public clash_native::dns::DnsTransport,
                               public std::enable_shared_from_this<FakeDnsTransport> {
  public:
    FakeDnsTransport(boost::asio::any_io_executor executor, boost::asio::ip::address answer_address,
                     std::shared_ptr<FakeTransportStats> stats, bool respond, bool fail = false,
                     std::uint8_t response_code = 0, bool return_query = false,
                     FakeResponseFactory response_factory = {})
        : executor_(std::move(executor)), answer_address_(std::move(answer_address)),
          stats_(std::move(stats)), respond_(respond), fail_(fail), response_code_(response_code),
          return_query_(return_query), response_factory_(std::move(response_factory)) {}

    ExchangeId exchange(clash_native::dns::DnsExchangeRequest request, Handler handler) override {
        ++stats_->exchanges;
        if (stats_->exchange_started) {
            stats_->exchange_started->set_value();
            stats_->exchange_started.reset();
        }
        query_ = std::move(request.query);
        question_ = query_.questions.front();
        handler_ = std::move(handler);
        completed_ = false;
        started_ = true;
        if (respond_) {
            auto self = shared_from_this();
            boost::asio::post(executor_, [self] {
                if (self->completed_) {
                    return;
                }
                self->completed_ = true;
                auto handler = std::move(self->handler_);
                if (!handler) {
                    return;
                }
                if (self->fail_) {
                    handler(clash_native::core::fail({clash_native::core::ErrorCode::transport_io,
                                                      "fake DNS upstream member failed"}));
                    return;
                }
                if (self->return_query_) {
                    handler(self->query_);
                    return;
                }
                if (self->response_factory_) {
                    handler(self->response_factory_(self->query_));
                    return;
                }
                clash_native::dns::DnsAnswer answer;
                answer.question = self->question_;
                answer.addresses.push_back(self->answer_address_);
                answer.ttl_seconds = 60;
                answer.response_code = self->response_code_;
                if (answer.response_code != 0) {
                    answer.addresses.clear();
                }
                const clash_native::dns::DnsQuery query{self->query_.id, self->question_, true};
                const auto encoded =
                    clash_native::dns::DnsMessageCodec::encode_response(query, answer);
                if (!encoded) {
                    handler(clash_native::core::fail(encoded.error()));
                    return;
                }
                const auto response =
                    clash_native::dns::DnsMessageCodec::decode_packet(encoded.value(), query.id);
                if (!response) {
                    handler(clash_native::core::fail(response.error()));
                    return;
                }
                handler(response);
            });
        }
        return 1;
    }

    void cancel(ExchangeId) noexcept override {
        if (completed_) {
            return;
        }
        completed_ = true;
        ++stats_->cancellations;
        auto handler = std::move(handler_);
        if (handler) {
            handler(clash_native::core::fail(
                {clash_native::core::ErrorCode::cancelled, "fake DNS transport cancelled"}));
        }
    }

    void stop() noexcept override {
        if (started_) {
            cancel(1);
        }
    }

  private:
    boost::asio::any_io_executor executor_;
    boost::asio::ip::address answer_address_;
    std::shared_ptr<FakeTransportStats> stats_;
    Handler handler_;
    clash_native::dns::DnsPacket query_;
    clash_native::dns::DnsQuestion question_;
    bool respond_;
    bool fail_;
    std::uint8_t response_code_;
    bool return_query_;
    FakeResponseFactory response_factory_;
    bool started_ = false;
    bool completed_ = false;
};

class ProbeDnsStream final : public clash_native::core::StreamHandle {
  public:
    explicit ProbeDnsStream(boost::asio::any_io_executor executor,
                            std::shared_ptr<std::atomic_bool> closed)
        : executor_(std::move(executor)), closed_(std::move(closed)) {}

    void async_read_some(boost::asio::mutable_buffer, ReadHandler handler) override {
        handler(boost::asio::error::eof, 0);
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        handler({}, buffer.size());
    }

    boost::asio::any_io_executor executor() noexcept override { return executor_; }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        error.clear();
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept override { error.clear(); }

    void close() noexcept override { closed_->store(true, std::memory_order_release); }

  private:
    boost::asio::any_io_executor executor_;
    std::shared_ptr<std::atomic_bool> closed_;
};

class ProbeDnsDialer final : public clash_native::dns::DnsUpstreamDialer {
  public:
    ProbeDnsDialer(boost::asio::any_io_executor executor, std::shared_ptr<std::atomic_int> calls,
                   std::shared_ptr<std::atomic_bool> closed)
        : executor_(std::move(executor)), calls_(std::move(calls)), closed_(std::move(closed)) {}

    clash_native::io::AnySender<clash_native::core::StreamOpenResult>
    connect_stream(clash_native::core::StreamRequest) override {
        ++*calls_;
        // Test debt: the probe stream is still core::; adapt at the edge.
        return clash_native::io::AnySender<clash_native::core::StreamOpenResult>{stdexec::just(
            clash_native::core::StreamOpenResult::opened(clash_native::net::adapt_core_to_io(
                std::make_unique<ProbeDnsStream>(executor_, closed_))))};
    }

  private:
    boost::asio::any_io_executor executor_;
    std::shared_ptr<std::atomic_int> calls_;
    std::shared_ptr<std::atomic_bool> closed_;
};

class CountingDnsDialer final : public clash_native::dns::DnsUpstreamDialer {
  public:
    CountingDnsDialer(std::shared_ptr<clash_native::dns::DnsUpstreamDialer> delegate,
                      std::shared_ptr<std::atomic_int> stream_calls)
        : delegate_(std::move(delegate)), stream_calls_(std::move(stream_calls)) {}

    clash_native::io::AnySender<clash_native::core::StreamOpenResult>
    connect_stream(clash_native::core::StreamRequest request) override {
        ++*stream_calls_;
        return delegate_->connect_stream(std::move(request));
    }

    clash_native::io::AnySender<clash_native::core::DatagramOpenResult>
    open_datagram(clash_native::core::DatagramRequest request) override {
        return delegate_->open_datagram(std::move(request));
    }

  private:
    std::shared_ptr<clash_native::dns::DnsUpstreamDialer> delegate_;
    std::shared_ptr<std::atomic_int> stream_calls_;
};

class PersistentTcpDnsServer final {
  public:
    explicit PersistentTcpDnsServer(boost::asio::any_io_executor executor)
        : acceptor_(executor), gate_(std::make_shared<std::atomic_bool>(false)) {
        boost::system::error_code error;
        acceptor_.open(boost::asio::ip::tcp::v4(), error);
        if (!error) {
            acceptor_.set_option(boost::asio::socket_base::reuse_address(true), error);
        }
        if (!error) {
            acceptor_.bind({boost::asio::ip::address_v4::loopback(), 0}, error);
        }
        if (!error) {
            acceptor_.listen(boost::asio::socket_base::max_listen_connections, error);
        }
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
    }

    boost::asio::ip::tcp::endpoint endpoint() const noexcept { return acceptor_.local_endpoint(); }
    int connection_count() const noexcept { return connection_count_.load(); }
    int query_count() const noexcept { return query_count_.load(); }

    int responses_written() const noexcept { return responses_written_.load(); }
    int first_response_id() const noexcept { return first_response_id_.load(); }
    int second_response_id() const noexcept { return second_response_id_.load(); }

    void start() {
        gate_->store(true, std::memory_order_release);
        accept();
    }

    void stop() noexcept {
        gate_->store(false, std::memory_order_release);
        boost::system::error_code ignored;
        acceptor_.cancel(ignored);
        acceptor_.close(ignored);
        if (socket_) {
            socket_->cancel(ignored);
            socket_->close(ignored);
        }
    }

  private:
    void accept() {
        socket_ = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
        const auto gate = gate_;
        acceptor_.async_accept(*socket_, [this, gate](const boost::system::error_code &error) {
            if (!gate->load(std::memory_order_acquire) || error) {
                return;
            }
            ++connection_count_;
            read_query();
        });
    }

    void read_query() {
        auto length = std::make_shared<std::array<std::uint8_t, 2>>();
        const auto gate = gate_;
        boost::asio::async_read(
            *socket_, boost::asio::buffer(*length),
            [this, gate, length](const boost::system::error_code &error, std::size_t) {
                if (!gate->load(std::memory_order_acquire) || error) {
                    return;
                }
                const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
                if (size == 0) {
                    return;
                }
                auto query = std::make_shared<std::vector<std::uint8_t>>(size);
                boost::asio::async_read(
                    *socket_, boost::asio::buffer(*query),
                    [this, gate, query](const boost::system::error_code &read_error, std::size_t) {
                        if (!gate->load(std::memory_order_acquire) || read_error) {
                            return;
                        }
                        ++query_count_;
                        queries_.push_back(make_response(*query));
                        if (queries_.size() == 2) {
                            write_responses(0);
                            return;
                        }
                        read_query();
                    });
            });
    }

    static std::vector<std::uint8_t> make_response(const std::vector<std::uint8_t> &query_wire) {
        const auto query = clash_native::dns::DnsMessageCodec::decode_packet(query_wire);
        if (!query || query.value().questions.size() != 1) {
            return {};
        }
        clash_native::dns::DnsAnswer answer;
        answer.question = query.value().questions.front();
        answer.addresses.push_back(boost::asio::ip::make_address(
            answer.question.name == "first.example" ? "192.0.2.31" : "192.0.2.32"));
        answer.ttl_seconds = 30;
        const clash_native::dns::DnsQuery legacy_query{query.value().id, answer.question, true};
        const auto response =
            clash_native::dns::DnsMessageCodec::encode_response(legacy_query, answer);
        if (!response || response.value().size() > 0xffff) {
            return {};
        }
        std::vector<std::uint8_t> frame;
        frame.reserve(2 + response.value().size());
        frame.push_back(static_cast<std::uint8_t>(response.value().size() >> 8));
        frame.push_back(static_cast<std::uint8_t>(response.value().size() & 0xff));
        frame.insert(frame.end(), response.value().begin(), response.value().end());
        return frame;
    }

    void write_responses(std::size_t index) {
        if (!gate_->load(std::memory_order_acquire) || index >= queries_.size()) {
            return;
        }
        const auto query_index = queries_.size() - 1 - index;
        auto frame = std::make_shared<std::vector<std::uint8_t>>(queries_[query_index]);
        boost::asio::async_write(
            *socket_, boost::asio::buffer(*frame),
            [this, frame, index](const boost::system::error_code &error, std::size_t) {
                if (!error) {
                    const auto response_number = responses_written_.fetch_add(1);
                    const auto response_id =
                        frame->size() >= 4 ? static_cast<int>((*frame)[2] << 8 | (*frame)[3]) : -1;
                    if (response_number == 0) {
                        first_response_id_.store(response_id);
                    } else if (response_number == 1) {
                        second_response_id_.store(response_id);
                    }
                    write_responses(index + 1);
                }
            });
    }

    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::shared_ptr<std::atomic_bool> gate_;
    std::vector<std::vector<std::uint8_t>> queries_;
    std::atomic_int connection_count_{0};
    std::atomic_int query_count_{0};
    std::atomic_int responses_written_{0};
    std::atomic_int first_response_id_{-1};
    std::atomic_int second_response_id_{-1};
};

class PersistentUdpDnsServer final {
  public:
    explicit PersistentUdpDnsServer(boost::asio::any_io_executor executor)
        : socket_(executor, {boost::asio::ip::address_v4::loopback(), 0}),
          gate_(std::make_shared<std::atomic_bool>(false)) {}

    boost::asio::ip::udp::endpoint endpoint() const noexcept { return socket_.local_endpoint(); }

    void start() {
        gate_->store(true, std::memory_order_release);
        receive_query();
    }

    void stop() noexcept {
        gate_->store(false, std::memory_order_release);
        boost::system::error_code ignored;
        socket_.cancel(ignored);
        socket_.close(ignored);
    }

  private:
    void receive_query() {
        auto query = std::make_shared<std::array<std::uint8_t, 4096>>();
        auto sender = std::make_shared<boost::asio::ip::udp::endpoint>();
        const auto gate = gate_;
        socket_.async_receive_from(
            boost::asio::buffer(*query), *sender,
            [this, gate, query, sender](const boost::system::error_code &error, std::size_t size) {
                if (!gate->load(std::memory_order_acquire) || error) {
                    return;
                }
                const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(
                    std::span<const std::uint8_t>(query->data(), size));
                if (!packet || packet.value().questions.size() != 1) {
                    return;
                }

                clash_native::dns::DnsAnswer answer;
                answer.question = packet.value().questions.front();
                answer.addresses.push_back(boost::asio::ip::make_address("192.0.2.123"));
                answer.ttl_seconds = 30;
                const clash_native::dns::DnsQuery dns_query{packet.value().id, answer.question,
                                                            true};
                const auto encoded =
                    clash_native::dns::DnsMessageCodec::encode_response(dns_query, answer);
                if (!encoded) {
                    return;
                }
                auto response = std::make_shared<std::vector<std::uint8_t>>(encoded.value());
                socket_.async_send_to(
                    boost::asio::buffer(*response), *sender,
                    [gate, response](const boost::system::error_code &, std::size_t) {});
            });
    }

    boost::asio::ip::udp::socket socket_;
    std::shared_ptr<std::atomic_bool> gate_;
};

struct TestCertificate {
    std::string certificate;
    std::string private_key;
};

std::optional<std::string> bio_string(BIO *bio) {
    char *data = nullptr;
    const auto size = BIO_get_mem_data(bio, &data);
    if (size <= 0 || data == nullptr) {
        return std::nullopt;
    }
    return std::string(data, static_cast<std::size_t>(size));
}

std::optional<TestCertificate> make_test_certificate() {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> key_context(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!key_context || EVP_PKEY_keygen_init(key_context.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(key_context.get(), 2048) != 1) {
        return std::nullopt;
    }

    EVP_PKEY *raw_key = nullptr;
    if (EVP_PKEY_keygen(key_context.get(), &raw_key) != 1) {
        return std::nullopt;
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, EVP_PKEY_free);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(), X509_free);
    if (!certificate || X509_set_version(certificate.get(), 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) != 1 ||
        !X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(certificate.get()), 3600) ||
        X509_set_pubkey(certificate.get(), key.get()) != 1) {
        return std::nullopt;
    }

    auto *name = X509_get_subject_name(certificate.get());
    const unsigned char common_name[] = "localhost";
    if (name == nullptr ||
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, common_name, -1, -1, 0) != 1 ||
        X509_set_issuer_name(certificate.get(), name) != 1 ||
        X509_sign(certificate.get(), key.get(), EVP_sha256()) <= 0) {
        return std::nullopt;
    }

    BIO *certificate_bio = BIO_new(BIO_s_mem());
    BIO *key_bio = BIO_new(BIO_s_mem());
    if (certificate_bio == nullptr || key_bio == nullptr ||
        PEM_write_bio_X509(certificate_bio, certificate.get()) != 1 ||
        PEM_write_bio_PrivateKey(key_bio, key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(certificate_bio);
        BIO_free(key_bio);
        return std::nullopt;
    }
    const auto certificate_pem = bio_string(certificate_bio);
    const auto key_pem = bio_string(key_bio);
    BIO_free(certificate_bio);
    BIO_free(key_bio);
    if (!certificate_pem || !key_pem) {
        return std::nullopt;
    }
    return TestCertificate{*certificate_pem, *key_pem};
}

class DotDnsTestServer final {
  public:
    static std::unique_ptr<DotDnsTestServer> create(boost::asio::any_io_executor executor) {
        const auto certificate = make_test_certificate();
        if (!certificate) {
            return nullptr;
        }
        return std::unique_ptr<DotDnsTestServer>(
            new DotDnsTestServer(executor, certificate->certificate, certificate->private_key));
    }

    boost::asio::ip::tcp::endpoint endpoint() const noexcept { return acceptor_.local_endpoint(); }
    int connection_count() const noexcept { return connection_count_.load(); }
    int query_count() const noexcept { return query_count_.load(); }

    void start() {
        gate_->store(true, std::memory_order_release);
        accept();
    }

    void stop() noexcept {
        gate_->store(false, std::memory_order_release);
        boost::system::error_code ignored;
        acceptor_.cancel(ignored);
        acceptor_.close(ignored);
    }

  private:
    using Stream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

    DotDnsTestServer(boost::asio::any_io_executor executor, std::string certificate,
                     std::string private_key)
        : certificate_(std::move(certificate)), private_key_(std::move(private_key)),
          ssl_context_(boost::asio::ssl::context::tls_server), acceptor_(executor),
          gate_(std::make_shared<std::atomic_bool>(false)) {
        boost::system::error_code error;
        ssl_context_.use_certificate_chain(boost::asio::buffer(certificate_), error);
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
        ssl_context_.use_private_key(boost::asio::buffer(private_key_),
                                     boost::asio::ssl::context::pem, error);
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
        acceptor_.open(boost::asio::ip::tcp::v4(), error);
        if (!error) {
            acceptor_.set_option(boost::asio::socket_base::reuse_address(true), error);
        }
        if (!error) {
            acceptor_.bind({boost::asio::ip::address_v4::loopback(), 0}, error);
        }
        if (!error) {
            acceptor_.listen(boost::asio::socket_base::max_listen_connections, error);
        }
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
    }

    void accept() {
        auto stream = std::make_shared<Stream>(acceptor_.get_executor(), ssl_context_);
        const auto gate = gate_;
        acceptor_.async_accept(stream->next_layer(), [this, gate, stream](
                                                         const boost::system::error_code &error) {
            if (!gate->load(std::memory_order_acquire) || error) {
                return;
            }
            ++connection_count_;
            accept();
            stream->async_handshake(boost::asio::ssl::stream_base::server,
                                    [this, gate, stream](const boost::system::error_code &error) {
                                        if (!gate->load(std::memory_order_acquire) || error) {
                                            return;
                                        }
                                        read_length(stream);
                                    });
        });
    }

    void read_length(const std::shared_ptr<Stream> &stream) {
        auto length = std::make_shared<std::array<std::uint8_t, 2>>();
        const auto gate = gate_;
        boost::asio::async_read(
            *stream, boost::asio::buffer(*length),
            [this, gate, stream, length](const boost::system::error_code &error, std::size_t) {
                if (!gate->load(std::memory_order_acquire) || error) {
                    return;
                }
                const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
                if (size == 0) {
                    return;
                }
                auto query = std::make_shared<std::vector<std::uint8_t>>(size);
                boost::asio::async_read(
                    *stream, boost::asio::buffer(*query),
                    [this, gate, stream, query](const boost::system::error_code &read_error,
                                                std::size_t) {
                        if (!gate->load(std::memory_order_acquire) || read_error) {
                            return;
                        }
                        const auto packet =
                            clash_native::dns::DnsMessageCodec::decode_packet(*query);
                        if (!packet || packet.value().questions.size() != 1) {
                            return;
                        }
                        clash_native::dns::DnsAnswer answer;
                        answer.question = packet.value().questions.front();
                        answer.addresses.push_back(boost::asio::ip::make_address("203.0.113.9"));
                        answer.ttl_seconds = 30;
                        const clash_native::dns::DnsQuery legacy_query{packet.value().id,
                                                                       answer.question, true};
                        const auto response = clash_native::dns::DnsMessageCodec::encode_response(
                            legacy_query, answer);
                        if (!response || response.value().size() > 0xffff) {
                            return;
                        }
                        ++query_count_;
                        auto frame = std::make_shared<std::vector<std::uint8_t>>();
                        frame->reserve(2 + response.value().size());
                        frame->push_back(static_cast<std::uint8_t>(response.value().size() >> 8));
                        frame->push_back(static_cast<std::uint8_t>(response.value().size() & 0xff));
                        frame->insert(frame->end(), response.value().begin(),
                                      response.value().end());
                        boost::asio::async_write(
                            *stream, boost::asio::buffer(*frame),
                            [this, gate, stream, frame](const boost::system::error_code &error,
                                                        std::size_t) {
                                if (!gate->load(std::memory_order_acquire) || error) {
                                    return;
                                }
                                read_length(stream);
                            });
                    });
            });
    }

    std::string certificate_;
    std::string private_key_;
    boost::asio::ssl::context ssl_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<std::atomic_bool> gate_;
    std::atomic_int connection_count_{0};
    std::atomic_int query_count_{0};
};

class Doh1DnsTestServer final {
  public:
    static std::unique_ptr<Doh1DnsTestServer>
    create(boost::asio::any_io_executor executor,
           std::string content_type = "application/dns-message", int status_code = 200,
           bool chunked = false) {
        const auto certificate = make_test_certificate();
        if (!certificate) {
            return nullptr;
        }
        return std::unique_ptr<Doh1DnsTestServer>(
            new Doh1DnsTestServer(executor, certificate->certificate, certificate->private_key,
                                  std::move(content_type), status_code, chunked));
    }

    boost::asio::ip::tcp::endpoint endpoint() const noexcept { return acceptor_.local_endpoint(); }
    int connection_count() const noexcept { return connection_count_.load(); }
    int query_count() const noexcept { return query_count_.load(); }
    bool request_valid() const noexcept { return request_valid_.load(); }

    void start() {
        gate_->store(true, std::memory_order_release);
        accept();
    }

    void stop() noexcept {
        gate_->store(false, std::memory_order_release);
        boost::system::error_code ignored;
        acceptor_.cancel(ignored);
        acceptor_.close(ignored);
    }

  private:
    using Stream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

    Doh1DnsTestServer(boost::asio::any_io_executor executor, std::string certificate,
                      std::string private_key, std::string content_type, int status_code,
                      bool chunked)
        : certificate_(std::move(certificate)), private_key_(std::move(private_key)),
          content_type_(std::move(content_type)), status_code_(status_code), chunked_(chunked),
          ssl_context_(boost::asio::ssl::context::tls_server), acceptor_(executor),
          gate_(std::make_shared<std::atomic_bool>(false)) {
        boost::system::error_code error;
        ssl_context_.use_certificate_chain(boost::asio::buffer(certificate_), error);
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
        ssl_context_.use_private_key(boost::asio::buffer(private_key_),
                                     boost::asio::ssl::context::pem, error);
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
        acceptor_.open(boost::asio::ip::tcp::v4(), error);
        if (!error) {
            acceptor_.set_option(boost::asio::socket_base::reuse_address(true), error);
        }
        if (!error) {
            acceptor_.bind({boost::asio::ip::address_v4::loopback(), 0}, error);
        }
        if (!error) {
            acceptor_.listen(boost::asio::socket_base::max_listen_connections, error);
        }
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
    }

    void accept() {
        auto stream = std::make_shared<Stream>(acceptor_.get_executor(), ssl_context_);
        const auto gate = gate_;
        acceptor_.async_accept(stream->next_layer(), [this, gate, stream](
                                                         const boost::system::error_code &error) {
            if (!gate->load(std::memory_order_acquire) || error) {
                return;
            }
            ++connection_count_;
            accept();
            stream->async_handshake(boost::asio::ssl::stream_base::server,
                                    [this, gate, stream](const boost::system::error_code &error) {
                                        if (!gate->load(std::memory_order_acquire) || error) {
                                            return;
                                        }
                                        read_request(stream);
                                    });
        });
    }

    void read_request(const std::shared_ptr<Stream> &stream) {
        auto request = std::make_shared<std::string>();
        const auto gate = gate_;
        boost::asio::async_read_until(
            *stream, boost::asio::dynamic_buffer(*request, 64 * 1024), "\r\n\r\n",
            [this, gate, stream, request](const boost::system::error_code &error,
                                          std::size_t header_size) {
                if (!gate->load(std::memory_order_acquire) || error) {
                    return;
                }
                const auto header_text = request->substr(0, header_size);
                std::istringstream headers(header_text);
                std::string request_line;
                std::getline(headers, request_line);
                std::size_t content_length = 0;
                std::string line;
                bool has_dns_content_type = false;
                while (std::getline(headers, line)) {
                    if (line == "\r" || line.empty()) {
                        break;
                    }
                    if (line.back() == '\r') {
                        line.pop_back();
                    }
                    const auto separator = line.find(':');
                    if (separator == std::string::npos) {
                        continue;
                    }
                    auto name = line.substr(0, separator);
                    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char value) {
                        return static_cast<char>(std::tolower(value));
                    });
                    auto value = line.substr(separator + 1);
                    if (name == "content-length") {
                        content_length = static_cast<std::size_t>(std::stoul(value));
                    } else if (name == "content-type") {
                        has_dns_content_type =
                            value.find("application/dns-message") != std::string::npos;
                    }
                }
                if (content_length == 0 || content_length > 0xffff) {
                    return;
                }
                const auto separator = request_line.find(' ');
                const auto path_end = separator == std::string::npos
                                          ? std::string::npos
                                          : request_line.find(' ', separator + 1);
                request_valid_.store(
                    separator != std::string::npos && path_end != std::string::npos &&
                        request_line.substr(0, separator) == "POST" &&
                        request_line.substr(separator + 1, path_end - separator - 1) ==
                            "/dns-query" &&
                        has_dns_content_type,
                    std::memory_order_release);

                const auto buffered_body = request->size() - header_size;
                const auto missing_body =
                    content_length > buffered_body ? content_length - buffered_body : 0;
                request->resize(header_size + content_length);
                if (missing_body == 0) {
                    handle_request(stream, request, header_size, content_length);
                    return;
                }
                boost::asio::async_read(
                    *stream,
                    boost::asio::buffer(request->data() + header_size + buffered_body,
                                        missing_body),
                    boost::asio::transfer_exactly(missing_body),
                    [this, gate, stream, request, header_size,
                     content_length](const boost::system::error_code &read_error, std::size_t) {
                        if (!gate->load(std::memory_order_acquire) || read_error) {
                            return;
                        }
                        handle_request(stream, request, header_size, content_length);
                    });
            });
    }

    void handle_request(const std::shared_ptr<Stream> &stream,
                        const std::shared_ptr<std::string> &request, std::size_t header_size,
                        std::size_t content_length) {
        const auto *body_data =
            reinterpret_cast<const std::uint8_t *>(request->data() + header_size);
        const auto query = clash_native::dns::DnsMessageCodec::decode_query(
            std::span<const std::uint8_t>(body_data, content_length));
        if (!query) {
            return;
        }
        clash_native::dns::DnsAnswer answer;
        answer.question = query.value().question;
        answer.addresses.push_back(boost::asio::ip::make_address("203.0.113.10"));
        answer.ttl_seconds = 30;
        const auto body =
            clash_native::dns::DnsMessageCodec::encode_response(query.value(), answer);
        if (!body) {
            return;
        }
        ++query_count_;

        auto response = std::make_shared<std::string>();
        *response = "HTTP/1.1 " + std::to_string(status_code_) +
                    (status_code_ == 200 ? " OK\r\n" : " Bad Gateway\r\n");
        *response += "Content-Type: " + content_type_ + "\r\n";
        if (chunked_) {
            std::ostringstream chunk_size;
            chunk_size << std::hex << body.value().size();
            *response += "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
            *response += chunk_size.str() + "\r\n";
            response->append(reinterpret_cast<const char *>(body.value().data()),
                             body.value().size());
            *response += "\r\n0\r\n\r\n";
        } else {
            *response += "Content-Length: " + std::to_string(body.value().size()) +
                         "\r\nConnection: close\r\n\r\n";
            response->append(reinterpret_cast<const char *>(body.value().data()),
                             body.value().size());
        }
        const auto gate = gate_;
        boost::asio::async_write(
            *stream, boost::asio::buffer(*response),
            [gate, stream, response](const boost::system::error_code &, std::size_t) {});
    }

    std::string certificate_;
    std::string private_key_;
    std::string content_type_;
    int status_code_;
    bool chunked_;
    boost::asio::ssl::context ssl_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<std::atomic_bool> gate_;
    std::atomic_int connection_count_{0};
    std::atomic_int query_count_{0};
    std::atomic_bool request_valid_{false};
};

class Doh2DnsTestServer final {
  public:
    static std::unique_ptr<Doh2DnsTestServer> create(boost::asio::any_io_executor executor) {
        const auto certificate = make_test_certificate();
        if (!certificate) {
            return nullptr;
        }
        return std::unique_ptr<Doh2DnsTestServer>(
            new Doh2DnsTestServer(executor, certificate->certificate, certificate->private_key));
    }

    boost::asio::ip::tcp::endpoint endpoint() const noexcept { return acceptor_.local_endpoint(); }
    int connection_count() const noexcept { return connection_count_.load(); }
    int query_count() const noexcept { return query_count_.load(); }

    void start() {
        gate_->store(true, std::memory_order_release);
        accept();
    }

    void stop() noexcept {
        gate_->store(false, std::memory_order_release);
        boost::system::error_code ignored;
        acceptor_.cancel(ignored);
        acceptor_.close(ignored);
    }

  private:
    using Stream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

    class Session final : public std::enable_shared_from_this<Session> {
      public:
        Session(Doh2DnsTestServer &owner, std::shared_ptr<Stream> stream)
            : owner_(owner), stream_(std::move(stream)), gate_(owner.gate_) {}

        void start() {
            nghttp2_session_callbacks *callbacks = nullptr;
            if (nghttp2_session_callbacks_new(&callbacks) != 0) {
                close();
                return;
            }
            nghttp2_session_callbacks_set_on_header_callback(callbacks, &on_header);
            nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &on_data);
            nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &on_frame);
            nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &on_stream_close);
            const auto result = nghttp2_session_server_new2(&session_, callbacks, this, nullptr);
            nghttp2_session_callbacks_del(callbacks);
            if (result != 0 || session_ == nullptr ||
                nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0) != 0) {
                close();
                return;
            }
            send_pending();
        }

      private:
        struct StreamState {
            std::vector<std::uint8_t> request_body;
            std::vector<std::uint8_t> response_body;
            std::size_t response_offset = 0;
            bool path_received = false;
            bool request_complete = false;
            bool response_submitted = false;
        };

        static StreamState &stream_state(Session &self, std::int32_t stream_id) {
            auto &state = self.streams_[stream_id];
            if (!state) {
                state = std::make_shared<StreamState>();
            }
            return *state;
        }

        static int on_header(nghttp2_session *, const nghttp2_frame *frame,
                             const std::uint8_t *name, std::size_t name_length,
                             const std::uint8_t *, std::size_t, std::uint8_t, void *user_data) {
            auto &self = *static_cast<Session *>(user_data);
            auto &state = stream_state(self, frame->hd.stream_id);
            if (name_length == 5 && std::memcmp(name, ":path", 5) == 0) {
                state.path_received = true;
            }
            return 0;
        }

        static int on_data(nghttp2_session *, std::uint8_t, std::int32_t stream_id,
                           const std::uint8_t *data, std::size_t length, void *user_data) {
            auto &state = stream_state(*static_cast<Session *>(user_data), stream_id);
            state.request_body.insert(state.request_body.end(), data, data + length);
            return 0;
        }

        static int on_frame(nghttp2_session *, const nghttp2_frame *frame, void *user_data) {
            if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) &&
                (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
                stream_state(*static_cast<Session *>(user_data), frame->hd.stream_id)
                    .request_complete = true;
            }
            return 0;
        }

        static int on_stream_close(nghttp2_session *, std::int32_t stream_id, std::uint32_t,
                                   void *user_data) {
            static_cast<Session *>(user_data)->streams_.erase(stream_id);
            return 0;
        }

        static nghttp2_ssize read_response(nghttp2_session *, std::int32_t, std::uint8_t *buffer,
                                           std::size_t length, std::uint32_t *flags,
                                           nghttp2_data_source *source, void *) {
            auto &state = *static_cast<StreamState *>(source->ptr);
            const auto remaining = state.response_body.size() - state.response_offset;
            const auto copied = std::min(length, remaining);
            if (copied != 0) {
                std::copy_n(state.response_body.data() + state.response_offset, copied, buffer);
                state.response_offset += copied;
            }
            if (state.response_offset == state.response_body.size()) {
                *flags |= NGHTTP2_DATA_FLAG_EOF;
            }
            return static_cast<nghttp2_ssize>(copied);
        }

        static nghttp2_nv header(const char *name, const char *value) {
            return {reinterpret_cast<std::uint8_t *>(const_cast<char *>(name)),
                    reinterpret_cast<std::uint8_t *>(const_cast<char *>(value)), std::strlen(name),
                    std::strlen(value), NGHTTP2_NV_FLAG_NONE};
        }

        void submit_responses() {
            for (auto &[stream_id, state] : streams_) {
                if (!state || !state->path_received || !state->request_complete ||
                    state->response_submitted) {
                    continue;
                }
                const auto query =
                    clash_native::dns::DnsMessageCodec::decode_packet(state->request_body);
                if (!query || query.value().questions.size() != 1) {
                    continue;
                }
                clash_native::dns::DnsAnswer answer;
                answer.question = query.value().questions.front();
                answer.addresses.push_back(boost::asio::ip::make_address("203.0.113.10"));
                answer.ttl_seconds = 30;
                const clash_native::dns::DnsQuery legacy_query{query.value().id, answer.question,
                                                               true};
                const auto encoded =
                    clash_native::dns::DnsMessageCodec::encode_response(legacy_query, answer);
                if (!encoded) {
                    continue;
                }
                state->response_body = encoded.value();
                const auto content_length = std::to_string(state->response_body.size());
                auto response_headers = std::array{
                    header(":status", "200"), header("content-type", "application/dns-message"),
                    header("content-length", content_length.c_str())};
                nghttp2_data_provider2 provider{};
                provider.source.ptr = state.get();
                provider.read_callback = &read_response;
                if (nghttp2_submit_response2(session_, stream_id, response_headers.data(),
                                             response_headers.size(), &provider) == 0) {
                    state->response_submitted = true;
                    ++owner_.query_count_;
                }
            }
        }

        void send_pending() {
            if (session_ == nullptr || write_in_progress_) {
                return;
            }
            pending_write_.clear();
            for (;;) {
                const std::uint8_t *serialized = nullptr;
                const auto length = nghttp2_session_mem_send2(session_, &serialized);
                if (length < 0) {
                    close();
                    return;
                }
                if (length == 0) {
                    break;
                }
                pending_write_.insert(pending_write_.end(), serialized,
                                      serialized + static_cast<std::size_t>(length));
            }
            if (pending_write_.empty()) {
                read_request();
                return;
            }
            write_in_progress_ = true;
            auto self = shared_from_this();
            boost::asio::async_write(*stream_, boost::asio::buffer(pending_write_),
                                     [self](const boost::system::error_code &error, std::size_t) {
                                         self->write_in_progress_ = false;
                                         if (!self->gate_->load(std::memory_order_acquire)) {
                                             return;
                                         }
                                         if (error) {
                                             self->close();
                                             return;
                                         }
                                         self->send_pending();
                                     });
        }

        void read_request() {
            if (read_in_progress_ || !gate_->load(std::memory_order_acquire)) {
                return;
            }
            read_in_progress_ = true;
            auto self = shared_from_this();
            stream_->async_read_some(
                boost::asio::buffer(read_buffer_),
                [self](const boost::system::error_code &error, std::size_t size) {
                    self->read_in_progress_ = false;
                    if (!self->gate_->load(std::memory_order_acquire)) {
                        return;
                    }
                    if (error) {
                        self->close();
                        return;
                    }
                    const auto consumed =
                        nghttp2_session_mem_recv2(self->session_, self->read_buffer_.data(), size);
                    if (consumed < 0 || static_cast<std::size_t>(consumed) != size) {
                        self->close();
                        return;
                    }
                    self->submit_responses();
                    self->send_pending();
                });
        }

        void close() noexcept {
            boost::system::error_code ignored;
            stream_->next_layer().cancel(ignored);
            stream_->next_layer().close(ignored);
        }

        Doh2DnsTestServer &owner_;
        std::shared_ptr<Stream> stream_;
        nghttp2_session *session_ = nullptr;
        std::array<std::uint8_t, 16384> read_buffer_{};
        std::vector<std::uint8_t> pending_write_;
        std::shared_ptr<std::atomic_bool> gate_;
        std::unordered_map<std::int32_t, std::shared_ptr<StreamState>> streams_;
        bool write_in_progress_ = false;
        bool read_in_progress_ = false;

      public:
        ~Session() {
            if (session_ != nullptr) {
                nghttp2_session_del(session_);
            }
        }
    };

    Doh2DnsTestServer(boost::asio::any_io_executor executor, std::string certificate,
                      std::string private_key)
        : certificate_(std::move(certificate)), private_key_(std::move(private_key)),
          ssl_context_(boost::asio::ssl::context::tls_server), acceptor_(executor),
          gate_(std::make_shared<std::atomic_bool>(false)) {
        boost::system::error_code error;
        ssl_context_.use_certificate_chain(boost::asio::buffer(certificate_), error);
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
        ssl_context_.use_private_key(boost::asio::buffer(private_key_),
                                     boost::asio::ssl::context::pem, error);
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
        SSL_CTX_set_alpn_select_cb(ssl_context_.native_handle(), &select_alpn, nullptr);
        acceptor_.open(boost::asio::ip::tcp::v4(), error);
        if (!error) {
            acceptor_.set_option(boost::asio::socket_base::reuse_address(true), error);
        }
        if (!error) {
            acceptor_.bind({boost::asio::ip::address_v4::loopback(), 0}, error);
        }
        if (!error) {
            acceptor_.listen(boost::asio::socket_base::max_listen_connections, error);
        }
        if (error) {
            throw std::system_error(error.value(), std::system_category());
        }
    }

    static int select_alpn(SSL *, const unsigned char **out, unsigned char *out_length,
                           const unsigned char *input, unsigned int input_length, void *) {
        static const unsigned char h2[] = {2, 'h', '2'};
        unsigned char *selected = nullptr;
        unsigned char selected_length = 0;
        const auto result =
            SSL_select_next_proto(&selected, &selected_length, h2, sizeof(h2), input, input_length);
        if (result != OPENSSL_NPN_NEGOTIATED) {
            return SSL_TLSEXT_ERR_NOACK;
        }
        *out = selected;
        *out_length = selected_length;
        return SSL_TLSEXT_ERR_OK;
    }

    void accept() {
        auto stream = std::make_shared<Stream>(acceptor_.get_executor(), ssl_context_);
        const auto gate = gate_;
        acceptor_.async_accept(stream->next_layer(), [this, gate, stream](
                                                         const boost::system::error_code &error) {
            if (!gate->load(std::memory_order_acquire) || error) {
                return;
            }
            ++connection_count_;
            accept();
            stream->async_handshake(boost::asio::ssl::stream_base::server,
                                    [this, gate, stream](const boost::system::error_code &error) {
                                        if (!gate->load(std::memory_order_acquire) || error) {
                                            return;
                                        }
                                        std::make_shared<Session>(*this, stream)->start();
                                    });
        });
    }

    std::string certificate_;
    std::string private_key_;
    boost::asio::ssl::context ssl_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<std::atomic_bool> gate_;
    std::atomic_int connection_count_{0};
    std::atomic_int query_count_{0};
};

clash_native::dns::DnsResolverConfig
fake_config(std::shared_ptr<FakeTransportStats> default_stats,
            std::shared_ptr<FakeTransportStats> internal_stats, bool respond,
            clash_native::dns::DnsTransportFactory *factory_out) {
    auto policy = std::make_shared<clash_native::dns::DnsPolicyRouter>("default");
    policy->add_rule({"internal", clash_native::dns::DnsPolicyRuleKind::suffix, "internal.example",
                      "internal-dns"});

    const auto default_endpoint =
        boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 5300);
    const auto internal_endpoint =
        boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 5301);
    auto factory = [default_endpoint, internal_endpoint, default_stats, internal_stats,
                    respond](clash_native::runtime::AsioRuntime &runtime,
                             clash_native::dns::DnsUpstreamConfig config) {
        const bool internal = config.endpoint == internal_endpoint;
        return std::make_shared<FakeDnsTransport>(
            runtime.serialized_executor(),
            internal ? boost::asio::ip::make_address("198.51.100.2")
                     : boost::asio::ip::make_address("192.0.2.2"),
            internal ? internal_stats : default_stats, respond);
    };
    *factory_out = std::move(factory);
    return {{default_endpoint, std::chrono::milliseconds(500)},
            {{"internal-dns", {internal_endpoint, std::chrono::milliseconds(500)}}},
            std::move(policy),
            *factory_out};
}

} // namespace

TEST(ResolverServiceTransportTest, UsesInjectedTransportForPolicySelectedGroups) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto default_stats = std::make_shared<FakeTransportStats>();
    auto internal_stats = std::make_shared<FakeTransportStats>();
    clash_native::dns::DnsTransportFactory factory;
    auto config = fake_config(default_stats, internal_stats, true, &factory);
    clash_native::dns::ResolverService resolver(runtime, std::move(config));
    runtime.start();

    auto completed = std::make_shared<std::atomic_int>(0);
    auto failures = std::make_shared<std::atomic_int>(0);
    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(runtime.serialized_executor(), [&resolver, completed, failures, done] {
        const auto handler = [completed, failures, done](
                                 clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
            if (!result) {
                ++*failures;
            }
            if (++*completed == 2) {
                done->set_value();
            }
        };
        resolver.resolve({"api.internal.example", clash_native::dns::DnsRecordType::a, 1}, handler);
        resolver.resolve({"www.example.org", clash_native::dns::DnsRecordType::a, 1}, handler);
    });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(*failures, 0);
    EXPECT_EQ(default_stats->exchanges.load(), 1);
    EXPECT_EQ(internal_stats->exchanges.load(), 1);
    EXPECT_EQ(default_stats->cancellations.load(), 0);
    EXPECT_EQ(internal_stats->cancellations.load(), 0);

    resolver.stop();
    runtime.stop();
}

TEST(ResolverServiceTransportTest, UsesNamedOutboundForPlainUdpEgress) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    PersistentUdpDnsServer upstream(runtime.serialized_executor());
    upstream.start();

    auto registry = std::make_shared<clash_native::outbound::OutboundRegistry>();
    ASSERT_TRUE(registry->add_outbound(
        "dns-direct", std::make_shared<clash_native::outbound::DirectOutbound>(runtime)));
    ASSERT_TRUE(registry->validate());

    clash_native::dns::DnsResolverConfig config{
        {upstream.endpoint(), std::chrono::milliseconds(500)},
        {},
        nullptr,
        {},
        {},
        4096,
        std::chrono::seconds(5),
        0,
        nullptr,
        registry->snapshot()};
    config.default_upstream.dial_policy.kind = clash_native::dns::DnsDialPolicyKind::named_outbound;
    config.default_upstream.dial_policy.outbound_id = "dns-direct";

    clash_native::dns::ResolverService resolver(runtime, std::move(config));
    ASSERT_TRUE(resolver.validate());
    runtime.start();

    auto done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsAnswer>>>();
    auto future = done->get_future();
    resolver.resolve({"named-egress.example", clash_native::dns::DnsRecordType::a, 1},
                     [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                         done->set_value(std::move(result));
                     });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    const auto result = future.get();
    ASSERT_TRUE(result) << (result ? "" : result.error().context);
    ASSERT_EQ(result.value().addresses.size(), 1U);
    EXPECT_EQ(result.value().addresses.front().to_string(), "192.0.2.123");

    resolver.stop();
    upstream.stop();
    runtime.stop();
}

TEST(ResolverServiceTransportTest, FollowsCnameInASeparateDnsResponse) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    runtime.start();
    auto stats = std::make_shared<FakeTransportStats>();
    const auto endpoint =
        boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 5304);
    clash_native::dns::DnsTransportFactory factory =
        [stats](clash_native::runtime::AsioRuntime &owner_runtime,
                clash_native::dns::DnsUpstreamConfig) {
            const FakeResponseFactory response_factory =
                [](const clash_native::dns::DnsPacket &query)
                -> clash_native::core::Result<clash_native::dns::DnsPacket> {
                if (query.questions.front().name == "alias.example") {
                    return cname_response(query, "target.example");
                }
                clash_native::dns::DnsAnswer answer;
                answer.question = query.questions.front();
                answer.addresses.push_back(boost::asio::ip::make_address("192.0.2.44"));
                answer.ttl_seconds = 40;
                const clash_native::dns::DnsQuery legacy_query{query.id, query.questions.front(),
                                                               true};
                const auto encoded =
                    clash_native::dns::DnsMessageCodec::encode_response(legacy_query, answer);
                if (!encoded) {
                    return clash_native::core::fail(encoded.error());
                }
                return clash_native::dns::DnsMessageCodec::decode_packet(encoded.value(), query.id);
            };
            return std::make_shared<FakeDnsTransport>(
                owner_runtime.serialized_executor(), boost::asio::ip::make_address("192.0.2.44"),
                stats, true, false, 0, false, response_factory);
        };
    clash_native::dns::ResolverService resolver(
        runtime, clash_native::dns::DnsResolverConfig{
                     {endpoint, std::chrono::milliseconds(500)}, {}, nullptr, std::move(factory)});

    auto done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsAnswer>>>();
    auto future = done->get_future();
    resolver.resolve({"alias.example", clash_native::dns::DnsRecordType::a, 1},
                     [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                         done->set_value(std::move(result));
                     });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    const auto result = future.get();
    ASSERT_TRUE(result) << (result ? "" : result.error().context);
    ASSERT_EQ(result.value().addresses.size(), 1U);
    EXPECT_EQ(result.value().addresses.front().to_string(), "192.0.2.44");
    EXPECT_EQ(result.value().question.name, "alias.example");
    EXPECT_EQ(result.value().ttl_seconds, 20U);
    EXPECT_EQ(stats->exchanges.load(), 2);

    resolver.stop();
    runtime.stop();
}

TEST(ResolverServiceTransportTest, DoesNotCallTransportForUnknownPolicyGroup) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto stats = std::make_shared<FakeTransportStats>();
    clash_native::dns::DnsTransportFactory factory;
    auto config = fake_config(stats, stats, false, &factory);
    auto policy = std::make_shared<clash_native::dns::DnsPolicyRouter>("default");
    policy->add_rule(
        {"missing", clash_native::dns::DnsPolicyRuleKind::exact, "missing.example", "missing-dns"});
    config.policy_router = std::move(policy);
    clash_native::dns::ResolverService resolver(runtime, std::move(config));
    runtime.start();

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(runtime.serialized_executor(), [&resolver, done] {
        resolver.resolve({"missing.example", clash_native::dns::DnsRecordType::a, 1},
                         [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                             ASSERT_FALSE(result);
                             EXPECT_EQ(result.error().code,
                                       clash_native::core::ErrorCode::configuration);
                             done->set_value();
                         });
    });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(stats->exchanges.load(), 0);
    EXPECT_EQ(stats->cancellations.load(), 0);

    resolver.stop();
    runtime.stop();
}

TEST(ResolverServiceTransportTest, CancelsInjectedTransportExchangeOnce) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto stats = std::make_shared<FakeTransportStats>();
    clash_native::dns::DnsTransportFactory factory;
    auto config = fake_config(stats, stats, false, &factory);
    clash_native::dns::ResolverService resolver(runtime, std::move(config));
    runtime.start();

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(runtime.serialized_executor(), [&resolver, done] {
        const auto request_id = resolver.resolve(
            {"cancel.example", clash_native::dns::DnsRecordType::a, 1},
            [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                ASSERT_FALSE(result);
                EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::cancelled);
                done->set_value();
            });
        resolver.cancel(request_id);
    });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(stats->exchanges.load(), 1);
    EXPECT_EQ(stats->cancellations.load(), 1);

    resolver.stop();
    runtime.stop();
}

TEST(ResolverServiceTransportTest, StopsPendingInjectedTransportAndCompletesWaiterOnce) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto stats = std::make_shared<FakeTransportStats>();
    stats->exchange_started = std::make_shared<std::promise<void>>();
    auto exchange_started = stats->exchange_started->get_future();
    clash_native::dns::DnsTransportFactory factory;
    auto config = fake_config(stats, stats, false, &factory);
    clash_native::dns::ResolverService resolver(runtime, std::move(config));
    runtime.start();

    auto callback_count = std::make_shared<std::atomic_int>(0);
    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(runtime.serialized_executor(), [&resolver, callback_count, done] {
        resolver.resolve({"shutdown.example", clash_native::dns::DnsRecordType::a, 1},
                         [callback_count,
                          done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                             ASSERT_FALSE(result);
                             EXPECT_EQ(result.error().code,
                                       clash_native::core::ErrorCode::cancelled);
                             ++*callback_count;
                             done->set_value();
                         });
    });

    ASSERT_EQ(exchange_started.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    resolver.stop();
    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(*callback_count, 1);
    EXPECT_EQ(stats->exchanges.load(), 1);
    EXPECT_EQ(stats->cancellations.load(), 1);

    runtime.stop();
}

TEST(ResolverServiceTransportTest, SkipsUnhealthyUpstreamMembersUntilTheyRecover) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    const auto first_endpoint =
        boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 5302);
    const auto second_endpoint =
        boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 5303);
    auto first_stats = std::make_shared<FakeTransportStats>();
    auto second_stats = std::make_shared<FakeTransportStats>();
    clash_native::dns::DnsTransportFactory factory =
        [first_endpoint, second_endpoint, first_stats,
         second_stats](clash_native::runtime::AsioRuntime &owner_runtime,
                       clash_native::dns::DnsUpstreamConfig config) {
            const bool first = config.endpoint == first_endpoint;
            return std::make_shared<FakeDnsTransport>(
                owner_runtime.serialized_executor(), boost::asio::ip::make_address("192.0.2.20"),
                first ? first_stats : second_stats, true, first);
        };

    auto policy = std::make_shared<clash_native::dns::DnsPolicyRouter>("resilient");
    clash_native::dns::DnsUpstreamGroupConfig group;
    group.members = {{first_endpoint, std::chrono::milliseconds(500)},
                     {second_endpoint, std::chrono::milliseconds(500)}};
    group.timeout = std::chrono::milliseconds(500);
    clash_native::dns::DnsResolverConfig config{{first_endpoint, std::chrono::milliseconds(500)},
                                                {},
                                                std::move(policy),
                                                std::move(factory),
                                                {{"resilient", std::move(group)}}};
    clash_native::dns::ResolverService resolver(runtime, std::move(config));
    runtime.start();

    auto resolve = [&resolver](std::string name) {
        auto done = std::make_shared<
            std::promise<clash_native::core::Result<clash_native::dns::DnsAnswer>>>();
        auto future = done->get_future();
        resolver.resolve({std::move(name), clash_native::dns::DnsRecordType::a, 1},
                         [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                             done->set_value(std::move(result));
                         });
        return future;
    };

    auto first_future = resolve("first-health.example");
    ASSERT_EQ(first_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    const auto first_result = first_future.get();
    ASSERT_TRUE(first_result) << (first_result ? "" : first_result.error().context);
    ASSERT_EQ(first_stats->exchanges.load(), 1);
    ASSERT_EQ(second_stats->exchanges.load(), 1);

    auto second_future = resolve("second-health.example");
    ASSERT_EQ(second_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    const auto second_result = second_future.get();
    ASSERT_TRUE(second_result) << (second_result ? "" : second_result.error().context);
    EXPECT_EQ(first_stats->exchanges.load(), 1);
    EXPECT_EQ(second_stats->exchanges.load(), 2);

    resolver.stop();
    runtime.stop();
}

TEST(ResolverServiceTransportTest, TriesGroupMembersWithinOneDeadline) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    const auto first_endpoint =
        boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 5310);
    const auto second_endpoint =
        boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 5311);
    auto first_stats = std::make_shared<FakeTransportStats>();
    auto second_stats = std::make_shared<FakeTransportStats>();
    auto factory = [first_endpoint, first_stats,
                    second_stats](clash_native::runtime::AsioRuntime &owner_runtime,
                                  clash_native::dns::DnsUpstreamConfig config) {
        const bool first = config.endpoint == first_endpoint;
        return std::make_shared<FakeDnsTransport>(owner_runtime.serialized_executor(),
                                                  first
                                                      ? boost::asio::ip::make_address("192.0.2.10")
                                                      : boost::asio::ip::make_address("192.0.2.11"),
                                                  first ? first_stats : second_stats, true, first);
    };
    auto policy = std::make_shared<clash_native::dns::DnsPolicyRouter>("default");
    policy->add_rule(
        {"group", clash_native::dns::DnsPolicyRuleKind::exact, "group.example", "fallback-group"});
    clash_native::dns::DnsResolverConfig config{
        {first_endpoint, std::chrono::milliseconds(500)},
        {},
        std::move(policy),
        factory,
        {{"fallback-group",
          {{{first_endpoint, std::chrono::milliseconds(500)},
            {second_endpoint, std::chrono::milliseconds(500)}},
           clash_native::dns::DnsUpstreamSelection::sequential,
           std::chrono::milliseconds(500)}}}};
    clash_native::dns::ResolverService resolver(runtime, std::move(config));
    runtime.start();

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(runtime.serialized_executor(), [&resolver, done] {
        resolver.resolve({"group.example", clash_native::dns::DnsRecordType::a, 1},
                         [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                             ASSERT_TRUE(result) << (result ? "" : result.error().context);
                             ASSERT_EQ(result.value().addresses.size(), 1U);
                             EXPECT_EQ(result.value().addresses.front().to_string(), "192.0.2.11");
                             done->set_value();
                         });
    });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(first_stats->exchanges.load(), 1);
    EXPECT_EQ(second_stats->exchanges.load(), 1);
    resolver.stop();
    runtime.stop();
}

TEST(ResolverServiceTransportTest, FallsBackAfterRetryableDnsResponse) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    const auto first_endpoint =
        boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 5324);
    const auto second_endpoint =
        boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 5325);
    auto first_stats = std::make_shared<FakeTransportStats>();
    auto second_stats = std::make_shared<FakeTransportStats>();
    auto factory = [first_endpoint, first_stats,
                    second_stats](clash_native::runtime::AsioRuntime &owner_runtime,
                                  clash_native::dns::DnsUpstreamConfig config) {
        const bool first = config.endpoint == first_endpoint;
        return std::make_shared<FakeDnsTransport>(
            owner_runtime.serialized_executor(), boost::asio::ip::make_address("192.0.2.12"),
            first ? first_stats : second_stats, true, false, first ? 2 : 0);
    };

    auto policy = std::make_shared<clash_native::dns::DnsPolicyRouter>("default");
    policy->add_rule(
        {"retry", clash_native::dns::DnsPolicyRuleKind::exact, "retry.example", "retry-group"});
    clash_native::dns::DnsUpstreamGroupConfig group;
    group.members = {{first_endpoint, std::chrono::milliseconds(500)},
                     {second_endpoint, std::chrono::milliseconds(500)}};
    group.timeout = std::chrono::milliseconds(500);
    clash_native::dns::ResolverService resolver(runtime,
                                                {{first_endpoint, std::chrono::milliseconds(500)},
                                                 {},
                                                 std::move(policy),
                                                 factory,
                                                 {{"retry-group", std::move(group)}}});
    runtime.start();

    auto done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsAnswer>>>();
    auto future = done->get_future();
    resolver.resolve({"retry.example", clash_native::dns::DnsRecordType::a, 1},
                     [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                         done->set_value(std::move(result));
                     });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    const auto result = future.get();
    ASSERT_TRUE(result) << (result ? "" : result.error().context);
    ASSERT_EQ(result.value().addresses.size(), 1U);
    EXPECT_EQ(result.value().addresses.front().to_string(), "192.0.2.12");
    EXPECT_EQ(first_stats->exchanges.load(), 1);
    EXPECT_EQ(second_stats->exchanges.load(), 1);

    resolver.stop();
    runtime.stop();
}

TEST(DnsQueryServiceTest, ReturnsTheCompletePacketThroughAnInjectedTransport) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto stats = std::make_shared<FakeTransportStats>();
    clash_native::dns::DnsTransportFactory factory;
    auto config = fake_config(stats, stats, true, &factory);
    clash_native::dns::DnsQueryService service(runtime, std::move(config));
    runtime.start();

    const clash_native::dns::DnsQuestion question{"packet.example",
                                                  clash_native::dns::DnsRecordType::a, 1};
    const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x2468);
    ASSERT_TRUE(encoded);
    const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
    ASSERT_TRUE(packet);

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    service.query(packet.value(),
                  [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                      ASSERT_TRUE(result) << (result ? "" : result.error().context);
                      ASSERT_EQ(result.value().questions.size(), 1U);
                      ASSERT_EQ(result.value().answers.size(), 1U);
                      EXPECT_EQ(result.value().answers.front().rdata.size(), 4U);
                      EXPECT_EQ(result.value().id, 0x2468);
                      done->set_value();
                  });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(stats->exchanges.load(), 1);
    service.stop();
    runtime.stop();
}

TEST(DnsQueryServiceTest, RejectsAQueryWithoutWireDataBeforeTransportCreation) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto stats = std::make_shared<FakeTransportStats>();
    clash_native::dns::DnsTransportFactory factory;
    auto config = fake_config(stats, stats, true, &factory);
    clash_native::dns::DnsQueryService service(runtime, std::move(config));
    runtime.start();

    clash_native::dns::DnsPacket packet;
    packet.questions.push_back({"invalid.example", clash_native::dns::DnsRecordType::a, 1});
    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    service.query(packet, [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
        ASSERT_FALSE(result);
        EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::protocol_framing);
        done->set_value();
    });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(stats->exchanges.load(), 0);
    service.stop();
    runtime.stop();
}

TEST(DnsQueryServiceTest, CachesNxDomainButDoesNotCacheServfail) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    runtime.start();

    const auto endpoint =
        boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 5320);
    auto nxdomain_stats = std::make_shared<FakeTransportStats>();
    auto nxdomain_factory = [endpoint, nxdomain_stats](clash_native::runtime::AsioRuntime &owner,
                                                       clash_native::dns::DnsUpstreamConfig) {
        return std::make_shared<FakeDnsTransport>(owner.serialized_executor(),
                                                  boost::asio::ip::make_address("192.0.2.20"),
                                                  nxdomain_stats, true, false, 3);
    };
    clash_native::dns::DnsQueryService nxdomain_service(
        runtime, {{endpoint, std::chrono::milliseconds(500)}, {}, nullptr, nxdomain_factory});

    auto nxdomain_done = std::make_shared<std::promise<void>>();
    auto nxdomain_future = nxdomain_done->get_future();
    const auto nxdomain_query = [](std::uint16_t id) {
        const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
            {"missing.example", clash_native::dns::DnsRecordType::a, 1}, id);
        if (!encoded) {
            return clash_native::dns::DnsPacket{};
        }
        const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
        return packet ? packet.value() : clash_native::dns::DnsPacket{};
    };
    nxdomain_service.query(
        nxdomain_query(0x1001), [nxdomain_done, &nxdomain_service, nxdomain_query](auto first) {
            if (!first || first.value().response_code() != 3) {
                ADD_FAILURE() << "expected NXDOMAIN response";
                nxdomain_done->set_value();
                return;
            }
            nxdomain_service.query(nxdomain_query(0x1002), [nxdomain_done](auto second) {
                if (!second || second.value().response_code() != 3) {
                    ADD_FAILURE() << "expected cached NXDOMAIN response";
                }
                nxdomain_done->set_value();
            });
        });
    ASSERT_EQ(nxdomain_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(nxdomain_stats->exchanges.load(), 1);
    nxdomain_service.stop();

    auto servfail_stats = std::make_shared<FakeTransportStats>();
    auto servfail_factory = [endpoint, servfail_stats](clash_native::runtime::AsioRuntime &owner,
                                                       clash_native::dns::DnsUpstreamConfig) {
        return std::make_shared<FakeDnsTransport>(owner.serialized_executor(),
                                                  boost::asio::ip::make_address("192.0.2.21"),
                                                  servfail_stats, true, false, 2);
    };
    clash_native::dns::DnsQueryService servfail_service(
        runtime, {{endpoint, std::chrono::milliseconds(500)}, {}, nullptr, servfail_factory});
    auto servfail_done = std::make_shared<std::promise<void>>();
    auto servfail_future = servfail_done->get_future();
    servfail_service.query(
        nxdomain_query(0x2001), [servfail_done, &servfail_service, nxdomain_query](auto first) {
            if (!first || first.value().response_code() != 2) {
                ADD_FAILURE() << "expected SERVFAIL response";
                servfail_done->set_value();
                return;
            }
            servfail_service.query(nxdomain_query(0x2002), [servfail_done](auto second) {
                if (!second || second.value().response_code() != 2) {
                    ADD_FAILURE() << "expected second SERVFAIL response";
                }
                servfail_done->set_value();
            });
        });
    ASSERT_EQ(servfail_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(servfail_stats->exchanges.load(), 2);
    servfail_service.stop();
    runtime.stop();
}

TEST(DnsQueryServiceTest, EvictsLeastRecentlyUsedEntriesAtTheConfiguredCapacity) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto stats = std::make_shared<FakeTransportStats>();
    clash_native::dns::DnsTransportFactory factory;
    auto config = fake_config(stats, stats, true, &factory);
    config.cache_capacity = 1;
    clash_native::dns::DnsQueryService service(runtime, std::move(config));
    runtime.start();

    const auto make_query = [](std::string name, std::uint16_t id) {
        const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
            {std::move(name), clash_native::dns::DnsRecordType::a, 1}, id);
        if (!encoded) {
            return clash_native::dns::DnsPacket{};
        }
        const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
        return packet ? packet.value() : clash_native::dns::DnsPacket{};
    };

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    service.query(
        make_query("first-cache.example", 0x3001), [done, &service, make_query](auto first) {
            ASSERT_TRUE(first) << (first ? "" : first.error().context);
            service.query(make_query("second-cache.example", 0x3002), [done, &service,
                                                                       make_query](auto second) {
                ASSERT_TRUE(second) << (second ? "" : second.error().context);
                service.query(make_query("first-cache.example", 0x3003), [done](auto third) {
                    ASSERT_TRUE(third) << (third ? "" : third.error().context);
                    done->set_value();
                });
            });
        });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(stats->exchanges.load(), 3);
    EXPECT_EQ(service.cache_size(), 1U);
    service.stop();
    runtime.stop();
}

TEST(ExchangeSessionTest, ReusesHttp11ConnectionForQueuedExchanges) {
    namespace asio = boost::asio;
    namespace http = boost::beast::http;
    using tcp = asio::ip::tcp;

    asio::io_context context;
    tcp::acceptor acceptor(context, {asio::ip::address_v4::loopback(), 0});
    tcp::socket client(context);
    client.connect(acceptor.local_endpoint());
    tcp::socket peer(context);
    acceptor.accept(peer);

    auto server_result = std::make_shared<std::promise<std::vector<std::string>>>();
    auto server_future = server_result->get_future();
    std::thread server_thread([peer = std::move(peer), server_result]() mutable {
        try {
            std::vector<std::string> targets;
            for (int index = 0; index < 2; ++index) {
                boost::beast::flat_buffer buffer;
                http::request<http::vector_body<std::uint8_t>> request;
                boost::system::error_code error;
                http::read(peer, buffer, request, error);
                if (error) {
                    throw boost::system::system_error(error);
                }
                targets.emplace_back(request.target());

                http::response<http::string_body> response{http::status::ok, 11};
                response.keep_alive(true);
                response.body() = index == 0 ? "first" : "second";
                response.prepare_payload();
                http::write(peer, response, error);
                if (error) {
                    throw boost::system::system_error(error);
                }
            }
            server_result->set_value(std::move(targets));
        } catch (...) {
            server_result->set_exception(std::current_exception());
        }
    });

    auto session = clash_native::transport::make_http1_exchange_session(
        std::make_unique<clash_native::net::TcpStream>(std::move(client)));
    std::array<std::optional<clash_native::core::Result<clash_native::io::ExchangeResponse>>, 2>
        results;
    for (std::size_t index = 0; index < results.size(); ++index) {
        clash_native::io::ExchangeRequest request;
        request.method = "POST";
        request.scheme = "http";
        request.authority = "localhost";
        request.target = index == 0 ? "/first" : "/second";
        request.keep_alive = true;
        struct ExchangeReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::optional<clash_native::core::Result<clash_native::io::ExchangeResponse>> *slot;
            void set_value(clash_native::io::ExchangeResponse response) && noexcept {
                *slot = std::move(response);
            }
            void set_error(std::exception_ptr error) && noexcept {
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const clash_native::core::Error &failure) {
                    *slot = clash_native::core::fail(failure);
                } catch (...) {
                    *slot = clash_native::core::fail(clash_native::core::Error{
                        clash_native::core::ErrorCode::transport_io, "exchange failed"});
                }
            }
            void set_stopped() && noexcept {
                *slot = clash_native::core::fail(clash_native::core::Error{
                    clash_native::core::ErrorCode::cancelled, "exchange stopped"});
            }
        };
        clash_native::async::start_with_receiver(
            session->exchange(std::move(request),
                              std::chrono::steady_clock::now() + std::chrono::seconds(5)),
            ExchangeReceiver{&results[index]});
    }
    context.run();
    session->stop();
    server_thread.join();

    ASSERT_EQ(server_future.wait_for(std::chrono::seconds(0)), std::future_status::ready);
    const auto targets = server_future.get();
    ASSERT_EQ(targets.size(), 2U);
    EXPECT_EQ(targets[0], "/first");
    EXPECT_EQ(targets[1], "/second");
    for (std::size_t index = 0; index < results.size(); ++index) {
        ASSERT_TRUE(results[index].has_value());
        ASSERT_TRUE(*results[index]) << results[index]->error().context;
        EXPECT_EQ(results[index]->value().status, 200U);
        const std::string expected = index == 0 ? "first" : "second";
        EXPECT_EQ(
            std::string(results[index]->value().body.begin(), results[index]->value().body.end()),
            expected);
    }
}

TEST(DnsTransportTest, ReusesTcpSessionAndDispatchesOutOfOrderResponses) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    PersistentTcpDnsServer server(runtime.serialized_executor());
    server.start();
    runtime.start();

    const auto endpoint = server.endpoint();
    clash_native::dns::DnsUpstreamConfig config;
    config.endpoint = {endpoint.address(), endpoint.port()};
    config.tcp_endpoint = endpoint;
    config.prefer_tcp = true;
    const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);

    const auto make_query = [](std::string name, std::uint16_t id) {
        const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
            {std::move(name), clash_native::dns::DnsRecordType::a, 1}, id);
        EXPECT_TRUE(encoded);
        const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
        EXPECT_TRUE(query);
        return query.value();
    };
    auto first_done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto second_done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto first_future = first_done->get_future();
    auto second_future = second_done->get_future();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    const auto first_query = make_query("first.example", 0x1111);
    const auto second_query = make_query("second.example", 0x2222);
    boost::asio::post(runtime.serialized_executor(), [transport, first_query, second_query,
                                                      deadline, first_done, second_done] {
        transport->exchange(
            {first_query, deadline},
            [first_done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                first_done->set_value(std::move(result));
            });
        transport->exchange(
            {second_query, deadline},
            [second_done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                second_done->set_value(std::move(result));
            });
    });

    const auto first_status = first_future.wait_for(std::chrono::seconds(3));
    const auto second_status = second_future.wait_for(std::chrono::seconds(3));
    ASSERT_EQ(first_status, std::future_status::ready)
        << "connections=" << server.connection_count() << " queries=" << server.query_count();
    ASSERT_EQ(second_status, std::future_status::ready)
        << "connections=" << server.connection_count() << " queries=" << server.query_count();
    const auto first = first_future.get();
    const auto second = second_future.get();
    ASSERT_TRUE(first) << (first ? "" : first.error().context);
    ASSERT_TRUE(second) << (second
                                ? ""
                                : second.error().context +
                                      " connections=" + std::to_string(server.connection_count()) +
                                      " queries=" + std::to_string(server.query_count()) +
                                      " responses=" + std::to_string(server.responses_written()) +
                                      " response_ids=" +
                                      std::to_string(server.first_response_id()) + "," +
                                      std::to_string(server.second_response_id()));
    ASSERT_EQ(first.value().answers.size(), 1U);
    ASSERT_EQ(second.value().answers.size(), 1U);
    EXPECT_EQ(first.value().answers.front().rdata, (std::vector<std::uint8_t>{192, 0, 2, 31}));
    EXPECT_EQ(second.value().answers.front().rdata, (std::vector<std::uint8_t>{192, 0, 2, 32}));
    EXPECT_EQ(server.connection_count(), 1);
    EXPECT_EQ(server.query_count(), 2);

    transport->stop();
    server.stop();
    runtime.stop();
}

TEST(DnsTransportTest, TimesOutWhenAnUpstreamReturnsAQueryInsteadOfAResponse) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    boost::asio::ip::udp::socket server(runtime.serialized_executor(),
                                        {boost::asio::ip::address_v4::loopback(), 0});
    const auto endpoint = server.local_endpoint();
    auto request_buffer = std::make_shared<std::array<std::uint8_t, 65535>>();
    auto sender = std::make_shared<boost::asio::ip::udp::endpoint>();
    server.async_receive_from(
        boost::asio::buffer(*request_buffer), *sender,
        [&server, request_buffer, sender](const boost::system::error_code &error,
                                          std::size_t size) {
            if (error) {
                return;
            }
            auto response = std::make_shared<std::vector<std::uint8_t>>(
                request_buffer->begin(), request_buffer->begin() + size);
            server.async_send_to(boost::asio::buffer(*response), *sender,
                                 [response](const boost::system::error_code &, std::size_t) {});
        });
    runtime.start();

    clash_native::dns::DnsUpstreamConfig config;
    config.endpoint = endpoint;
    config.timeout = std::chrono::milliseconds(500);
    const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);
    const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
        {"query-instead-of-response.example", clash_native::dns::DnsRecordType::a, 1}, 0x3456);
    ASSERT_TRUE(encoded);
    const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
    ASSERT_TRUE(query);

    auto done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto future = done->get_future();
    transport->exchange(
        {query.value(), std::chrono::steady_clock::now() + std::chrono::milliseconds(250)},
        [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
            done->set_value(std::move(result));
        });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    const auto result = future.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::timeout);

    transport->stop();
    boost::system::error_code ignored;
    server.close(ignored);
    runtime.stop();
}

TEST(DnsTransportTest, UsesTheConfiguredDialerForPlainTcp) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    runtime.start();
    auto calls = std::make_shared<std::atomic_int>(0);
    auto closed = std::make_shared<std::atomic_bool>(false);
    auto dialer = std::make_shared<ProbeDnsDialer>(runtime.serialized_executor(), calls, closed);

    clash_native::dns::DnsUpstreamConfig config;
    config.endpoint = {boost::asio::ip::address_v4::loopback(), 1};
    config.prefer_tcp = true;
    config.dialer = dialer;
    const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);
    const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
        {"dialer.example", clash_native::dns::DnsRecordType::a, 1}, 0x4567);
    ASSERT_TRUE(encoded);
    const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
    ASSERT_TRUE(query);

    auto done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto future = done->get_future();
    transport->exchange({query.value(), std::chrono::steady_clock::now() + std::chrono::seconds(1)},
                        [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                            done->set_value(std::move(result));
                        });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    const auto result = future.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::transport_io);
    EXPECT_EQ(*calls, 1);
    EXPECT_TRUE(closed->load(std::memory_order_acquire));

    transport->stop();
    runtime.stop();
}

TEST(DnsTransportTest, ExchangesOverDotWithTlsAndTcpFraming) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto server = DotDnsTestServer::create(runtime.serialized_executor());
    ASSERT_NE(server, nullptr);
    server->start();
    runtime.start();

    clash_native::dns::DnsUpstreamConfig config;
    config.endpoint = {boost::asio::ip::address_v4::loopback(), 53};
    config.tcp_endpoint = server->endpoint();
    config.mode = clash_native::dns::DnsTransportMode::dot;
    config.server_name = "localhost";
    config.verify_peer = false;
    auto dialer_calls = std::make_shared<std::atomic_int>(0);
    config.dialer = std::make_shared<CountingDnsDialer>(
        clash_native::dns::make_direct_dns_upstream_dialer(runtime), dialer_calls);
    const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);

    const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
        {"dot.example", clash_native::dns::DnsRecordType::a, 1}, 0x1234);
    ASSERT_TRUE(encoded);
    const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
    ASSERT_TRUE(query);

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    transport->exchange({query.value(), std::chrono::steady_clock::now() + std::chrono::seconds(2)},
                        [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                            ASSERT_TRUE(result) << (result ? "" : result.error().context);
                            ASSERT_EQ(result.value().answers.size(), 1U);
                            ASSERT_EQ(result.value().answers.front().rdata.size(), 4U);
                            EXPECT_EQ(result.value().answers.front().rdata[0], 203);
                            EXPECT_EQ(result.value().answers.front().rdata[1], 0);
                            EXPECT_EQ(result.value().answers.front().rdata[2], 113);
                            EXPECT_EQ(result.value().answers.front().rdata[3], 9);
                            done->set_value();
                        });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_EQ(dialer_calls->load(), 1);
    transport->stop();
    server->stop();
    runtime.stop();
}

TEST(DnsTransportTest, RejectsUntrustedDotCertificate) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto server = DotDnsTestServer::create(runtime.serialized_executor());
    ASSERT_NE(server, nullptr);
    server->start();
    runtime.start();

    clash_native::dns::DnsUpstreamConfig config;
    config.endpoint = {boost::asio::ip::address_v4::loopback(), 53};
    config.tcp_endpoint = server->endpoint();
    config.mode = clash_native::dns::DnsTransportMode::dot;
    config.server_name = "localhost";
    config.verify_peer = true;
    const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);

    const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
        {"dot-untrusted.example", clash_native::dns::DnsRecordType::a, 1}, 0x1244);
    ASSERT_TRUE(encoded);
    const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
    ASSERT_TRUE(query);

    auto done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto future = done->get_future();
    transport->exchange({query.value(), std::chrono::steady_clock::now() + std::chrono::seconds(2)},
                        [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                            done->set_value(std::move(result));
                        });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    const auto result = future.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::carrier_handshake);
    EXPECT_EQ(server->query_count(), 0);

    transport->stop();
    server->stop();
    runtime.stop();
}

TEST(DnsTransportTest, ReusesDotTlsSessionForMultipleExchanges) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto server = DotDnsTestServer::create(runtime.serialized_executor());
    ASSERT_NE(server, nullptr);
    server->start();
    runtime.start();

    clash_native::dns::DnsUpstreamConfig config;
    config.endpoint = {boost::asio::ip::address_v4::loopback(), 53};
    config.tcp_endpoint = server->endpoint();
    config.mode = clash_native::dns::DnsTransportMode::dot;
    config.server_name = "localhost";
    config.verify_peer = false;
    const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);

    const auto make_query = [](std::string name, std::uint16_t id) {
        const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
            {std::move(name), clash_native::dns::DnsRecordType::a, 1}, id);
        EXPECT_TRUE(encoded);
        const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
        EXPECT_TRUE(query);
        return query.value();
    };
    const auto first_query = make_query("dot-first.example", 0x1101);
    const auto second_query = make_query("dot-second.example", 0x1102);
    auto first_done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto second_done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto first_future = first_done->get_future();
    auto second_future = second_done->get_future();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    boost::asio::post(runtime.serialized_executor(), [transport, first_query, second_query,
                                                      deadline, first_done, second_done] {
        transport->exchange(
            {first_query, deadline},
            [first_done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                first_done->set_value(std::move(result));
            });
        transport->exchange(
            {second_query, deadline},
            [second_done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                second_done->set_value(std::move(result));
            });
    });

    const auto first_status = first_future.wait_for(std::chrono::seconds(3));
    const auto second_status = second_future.wait_for(std::chrono::seconds(3));
    ASSERT_EQ(first_status, std::future_status::ready)
        << "connections=" << server->connection_count() << " queries=" << server->query_count();
    ASSERT_EQ(second_status, std::future_status::ready)
        << "connections=" << server->connection_count() << " queries=" << server->query_count();
    const auto first = first_future.get();
    const auto second = second_future.get();
    ASSERT_TRUE(first) << (first ? "" : first.error().context);
    ASSERT_TRUE(second) << (second ? "" : second.error().context);
    EXPECT_EQ(server->connection_count(), 1);
    EXPECT_EQ(server->query_count(), 2);

    transport->stop();
    server->stop();
    runtime.stop();
}

TEST(DnsTransportTest, ExchangesOverDoh1WithContentLengthAndChunkedResponses) {
    for (const bool chunked : {false, true}) {
        auto &runtime = clash_native::runtime::AsioRuntime::instance();
        auto server = Doh1DnsTestServer::create(runtime.serialized_executor(),
                                                "application/dns-message", 200, chunked);
        ASSERT_NE(server, nullptr);
        server->start();
        runtime.start();

        clash_native::dns::DnsUpstreamConfig config;
        config.endpoint = {boost::asio::ip::address_v4::loopback(), 443};
        config.tcp_endpoint = server->endpoint();
        config.mode = clash_native::dns::DnsTransportMode::doh1;
        config.server_name = "localhost";
        config.doh_path = "/dns-query";
        config.verify_peer = false;
        const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);

        const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
            {"doh1.example", clash_native::dns::DnsRecordType::a, 1}, 0x5410);
        ASSERT_TRUE(encoded);
        const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
        ASSERT_TRUE(query);
        auto done = std::make_shared<
            std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
        auto future = done->get_future();
        transport->exchange(
            {query.value(), std::chrono::steady_clock::now() + std::chrono::seconds(3)},
            [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                done->set_value(std::move(result));
            });

        ASSERT_EQ(future.wait_for(std::chrono::seconds(4)), std::future_status::ready);
        const auto result = future.get();
        ASSERT_TRUE(result) << (result ? "" : result.error().context);
        ASSERT_EQ(result.value().answers.size(), 1U);
        EXPECT_EQ(result.value().answers.front().rdata,
                  (std::vector<std::uint8_t>{203, 0, 113, 10}));
        EXPECT_TRUE(server->request_valid());
        EXPECT_EQ(server->query_count(), 1);

        transport->stop();
        server->stop();
        runtime.stop();
    }
}

TEST(DnsTransportTest, RejectsInvalidDoh1StatusAndContentType) {
    const std::array<std::pair<std::string, int>, 2> invalid_responses = {
        std::pair{"application/dns-message", 502}, std::pair{"text/plain", 200}};
    for (const auto &[content_type, status_code] : invalid_responses) {
        auto &runtime = clash_native::runtime::AsioRuntime::instance();
        auto server =
            Doh1DnsTestServer::create(runtime.serialized_executor(), content_type, status_code);
        ASSERT_NE(server, nullptr);
        server->start();
        runtime.start();

        clash_native::dns::DnsUpstreamConfig config;
        config.endpoint = {boost::asio::ip::address_v4::loopback(), 443};
        config.tcp_endpoint = server->endpoint();
        config.mode = clash_native::dns::DnsTransportMode::doh1;
        config.server_name = "localhost";
        config.verify_peer = false;
        const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);
        const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
            {"doh1-invalid.example", clash_native::dns::DnsRecordType::a, 1}, 0x5411);
        ASSERT_TRUE(encoded);
        const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
        ASSERT_TRUE(query);
        auto done = std::make_shared<
            std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
        auto future = done->get_future();
        transport->exchange(
            {query.value(), std::chrono::steady_clock::now() + std::chrono::seconds(3)},
            [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                done->set_value(std::move(result));
            });

        ASSERT_EQ(future.wait_for(std::chrono::seconds(4)), std::future_status::ready);
        const auto result = future.get();
        ASSERT_FALSE(result);
        EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::protocol_framing);
        EXPECT_EQ(server->query_count(), 1);

        transport->stop();
        server->stop();
        runtime.stop();
    }
}

TEST(DnsTransportTest, RejectsUntrustedDoh1Certificate) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto server = Doh1DnsTestServer::create(runtime.serialized_executor());
    ASSERT_NE(server, nullptr);
    server->start();
    runtime.start();

    clash_native::dns::DnsUpstreamConfig config;
    config.endpoint = {boost::asio::ip::address_v4::loopback(), 443};
    config.tcp_endpoint = server->endpoint();
    config.mode = clash_native::dns::DnsTransportMode::doh1;
    config.server_name = "localhost";
    config.verify_peer = true;
    const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);
    const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
        {"doh1-untrusted.example", clash_native::dns::DnsRecordType::a, 1}, 0x5412);
    ASSERT_TRUE(encoded);
    const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
    ASSERT_TRUE(query);
    auto done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto future = done->get_future();
    transport->exchange({query.value(), std::chrono::steady_clock::now() + std::chrono::seconds(3)},
                        [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                            done->set_value(std::move(result));
                        });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(4)), std::future_status::ready);
    const auto result = future.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::carrier_handshake);
    EXPECT_EQ(server->query_count(), 0);

    transport->stop();
    server->stop();
    runtime.stop();
}

TEST(DnsTransportTest, ExchangesOverDoh2WithHttp2AndDnsMediaType) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto server = Doh2DnsTestServer::create(runtime.serialized_executor());
    ASSERT_NE(server, nullptr);
    server->start();
    runtime.start();

    clash_native::dns::DnsUpstreamConfig config;
    config.endpoint = {boost::asio::ip::address_v4::loopback(), 443};
    config.tcp_endpoint = server->endpoint();
    config.mode = clash_native::dns::DnsTransportMode::doh2;
    config.server_name = "localhost";
    config.doh_path = "/dns-query";
    config.verify_peer = false;
    auto dialer_calls = std::make_shared<std::atomic_int>(0);
    config.dialer = std::make_shared<CountingDnsDialer>(
        clash_native::dns::make_direct_dns_upstream_dialer(runtime), dialer_calls);
    const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);

    const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
        {"doh2.example", clash_native::dns::DnsRecordType::a, 1}, 0x2345);
    ASSERT_TRUE(encoded);
    const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
    ASSERT_TRUE(query);

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    transport->exchange({query.value(), std::chrono::steady_clock::now() + std::chrono::seconds(2)},
                        [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                            ASSERT_TRUE(result) << (result ? "" : result.error().context);
                            ASSERT_EQ(result.value().answers.size(), 1U);
                            ASSERT_EQ(result.value().answers.front().rdata.size(), 4U);
                            EXPECT_EQ(result.value().answers.front().rdata[0], 203);
                            EXPECT_EQ(result.value().answers.front().rdata[1], 0);
                            EXPECT_EQ(result.value().answers.front().rdata[2], 113);
                            EXPECT_EQ(result.value().answers.front().rdata[3], 10);
                            done->set_value();
                        });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_EQ(dialer_calls->load(), 1);
    transport->stop();
    server->stop();
    runtime.stop();
}

TEST(DnsTransportTest, RejectsUntrustedDoh2Certificate) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto server = Doh2DnsTestServer::create(runtime.serialized_executor());
    ASSERT_NE(server, nullptr);
    server->start();
    runtime.start();

    clash_native::dns::DnsUpstreamConfig config;
    config.endpoint = {boost::asio::ip::address_v4::loopback(), 443};
    config.tcp_endpoint = server->endpoint();
    config.mode = clash_native::dns::DnsTransportMode::doh2;
    config.server_name = "localhost";
    config.doh_path = "/dns-query";
    config.verify_peer = true;
    const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);

    const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
        {"doh2-untrusted.example", clash_native::dns::DnsRecordType::a, 1}, 0x2355);
    ASSERT_TRUE(encoded);
    const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
    ASSERT_TRUE(query);

    auto done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto future = done->get_future();
    transport->exchange({query.value(), std::chrono::steady_clock::now() + std::chrono::seconds(2)},
                        [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                            done->set_value(std::move(result));
                        });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    const auto result = future.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::carrier_handshake);
    EXPECT_EQ(server->query_count(), 0);

    transport->stop();
    server->stop();
    runtime.stop();
}

TEST(DnsTransportTest, MultiplexesDoh2ExchangesOnOneHttp2Session) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto server = Doh2DnsTestServer::create(runtime.serialized_executor());
    ASSERT_NE(server, nullptr);
    server->start();
    runtime.start();

    clash_native::dns::DnsUpstreamConfig config;
    config.endpoint = {boost::asio::ip::address_v4::loopback(), 443};
    config.tcp_endpoint = server->endpoint();
    config.mode = clash_native::dns::DnsTransportMode::doh2;
    config.server_name = "localhost";
    config.doh_path = "/dns-query";
    config.verify_peer = false;
    const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);

    const auto make_query = [](std::string name, std::uint16_t id) {
        const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
            {std::move(name), clash_native::dns::DnsRecordType::a, 1}, id);
        EXPECT_TRUE(encoded);
        const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
        EXPECT_TRUE(query);
        return query.value();
    };
    const auto first_query = make_query("doh2-first.example", 0x2201);
    const auto second_query = make_query("doh2-second.example", 0x2202);
    auto first_done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto second_done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto first_future = first_done->get_future();
    auto second_future = second_done->get_future();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    boost::asio::post(runtime.serialized_executor(), [transport, first_query, second_query,
                                                      deadline, first_done, second_done] {
        transport->exchange(
            {first_query, deadline},
            [first_done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                first_done->set_value(std::move(result));
            });
        transport->exchange(
            {second_query, deadline},
            [second_done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                second_done->set_value(std::move(result));
            });
    });

    ASSERT_EQ(first_future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(second_future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    const auto first = first_future.get();
    const auto second = second_future.get();
    ASSERT_TRUE(first) << (first ? "" : first.error().context);
    ASSERT_TRUE(second) << (second ? "" : second.error().context);
    EXPECT_EQ(server->connection_count(), 1);
    EXPECT_EQ(server->query_count(), 2);

    transport->stop();
    server->stop();
    runtime.stop();
}

TEST(DnsTransportTest, FailsWhenQuicDnsUpstreamIsUnavailable) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    runtime.start();

    clash_native::dns::DnsUpstreamConfig config;
    config.endpoint = {boost::asio::ip::address_v4::loopback(), 853};
    config.mode = clash_native::dns::DnsTransportMode::doq;
    const auto transport = clash_native::dns::make_asio_dns_transport(runtime, config);
    const auto encoded = clash_native::dns::DnsMessageCodec::encode_query_packet(
        {"quic.example", clash_native::dns::DnsRecordType::a, 1}, 0x3301);
    ASSERT_TRUE(encoded);
    const auto query = clash_native::dns::DnsMessageCodec::decode_packet(encoded.value());
    ASSERT_TRUE(query);

    auto done =
        std::make_shared<std::promise<clash_native::core::Result<clash_native::dns::DnsPacket>>>();
    auto future = done->get_future();
    transport->exchange({query.value(), std::chrono::steady_clock::now() + std::chrono::seconds(1)},
                        [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                            done->set_value(std::move(result));
                        });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    const auto result = future.get();
    ASSERT_FALSE(result);
    EXPECT_TRUE(result.error().code == clash_native::core::ErrorCode::timeout ||
                result.error().code == clash_native::core::ErrorCode::transport_io)
        << result.error().context;

    transport->stop();
    runtime.stop();
}
