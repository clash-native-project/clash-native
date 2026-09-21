#include <clash_native/transport/shadowsocks/shadow_tls_v3.hpp>

#include "transport/builtin_ca_bundle.hpp"

#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_messages.h>
#include <botan/tls_policy.h>
#include <botan/tls_server_info.h>
#include <botan/tls_session_id.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/x509cert.h>

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <openssl/digest.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kTlsHeaderSize = 5;
constexpr std::size_t kTlsHmacSize = 4;
constexpr std::size_t kTlsRandomSize = 32;
constexpr std::size_t kTlsSessionIdSize = 32;
constexpr std::size_t kMaxTlsPlaintext = 16384;
constexpr std::size_t kTlsRecordBufferSize = 16 * 1024;
constexpr std::uint8_t kHandshakeRecord = 22;
constexpr std::uint8_t kApplicationRecord = 23;
constexpr auto kHandshakeTimeout = std::chrono::seconds(10);

core::Error v3_error(core::ErrorCode code, std::string message) {
    return {code, std::move(message), {}};
}

core::Error v3_io_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

core::Error v3_exception(std::string context, const std::exception &exception) {
    context.append(": ");
    context.append(exception.what());
    return v3_error(core::ErrorCode::carrier_handshake, std::move(context));
}

std::vector<std::uint8_t> hmac_sha1(std::string_view key, std::span<const std::uint8_t> data) {
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> output{};
    unsigned int output_size = 0;
    if (!HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
              output.data(), &output_size)) {
        return {};
    }
    return {output.begin(), output.begin() + output_size};
}

std::array<std::uint8_t, 32> sha256(std::span<const std::uint8_t> data) {
    std::array<std::uint8_t, 32> output{};
    SHA256(data.data(), data.size(), output.data());
    return output;
}

std::vector<std::uint8_t> concat(std::string_view first, std::span<const std::uint8_t> second) {
    std::vector<std::uint8_t> result;
    result.reserve(first.size() + second.size());
    result.insert(result.end(), first.begin(), first.end());
    result.insert(result.end(), second.begin(), second.end());
    return result;
}

std::vector<std::uint8_t> handshake_wire(std::uint8_t type, std::span<const std::uint8_t> body) {
    if (body.size() > 0xFFFFFFU) {
        return {};
    }
    std::vector<std::uint8_t> wire;
    wire.reserve(4 + body.size());
    wire.push_back(type);
    wire.push_back(static_cast<std::uint8_t>((body.size() >> 16) & 0xFFU));
    wire.push_back(static_cast<std::uint8_t>((body.size() >> 8) & 0xFFU));
    wire.push_back(static_cast<std::uint8_t>(body.size() & 0xFFU));
    wire.insert(wire.end(), body.begin(), body.end());
    return wire;
}

void xor_with_key(std::span<std::uint8_t> data, std::span<const std::uint8_t> key) {
    for (std::size_t index = 0; index < data.size(); ++index) {
        data[index] ^= key[index % key.size()];
    }
}

class V3Policy final : public Botan::TLS::Text_Policy {
  public:
    V3Policy() : Botan::TLS::Text_Policy("") {}

    bool allow_tls12() const override { return false; }
    bool allow_tls13() const override { return true; }

    std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override {
        return {Botan::TLS::Group_Params::X25519};
    }

    std::vector<Botan::TLS::Group_Params> key_exchange_groups_to_offer() const override {
        return key_exchange_groups();
    }

    std::vector<std::string> allowed_key_exchange_methods() const override { return {"ECDH"}; }

    bool negotiate_encrypt_then_mac() const override { return false; }
    bool require_extended_master_secret() const override { return false; }
};

class V3Credentials final : public Botan::Credentials_Manager {
  public:
    explicit V3Credentials(bool verify_peer) {
        if (!verify_peer) {
            return;
        }
        roots_ = std::make_unique<Botan::Certificate_Store_In_Memory>();
        const auto pem = clash_native::transport::detail::builtin_ca_bundle_pem();
        constexpr std::string_view begin_marker = "-----BEGIN CERTIFICATE-----";
        constexpr std::string_view end_marker = "-----END CERTIFICATE-----";
        std::size_t offset = 0;
        while (true) {
            const auto begin = pem.find(begin_marker, offset);
            if (begin == std::string_view::npos) {
                break;
            }
            const auto end = pem.find(end_marker, begin + begin_marker.size());
            if (end == std::string_view::npos) {
                throw std::runtime_error("Shadow-TLS v3 embedded CA bundle is malformed");
            }
            const auto block_end = end + end_marker.size();
            Botan::DataSource_Memory source(pem.substr(begin, block_end - begin));
            roots_->add_certificate(Botan::X509_Certificate(source));
            offset = block_end;
        }
        if (!roots_ || roots_->all_subjects().empty()) {
            throw std::runtime_error("Shadow-TLS v3 embedded CA bundle is empty");
        }
    }

    std::vector<Botan::Certificate_Store *>
    trusted_certificate_authorities(const std::string &, const std::string &) override {
        return roots_ ? std::vector<Botan::Certificate_Store *>{roots_.get()}
                      : std::vector<Botan::Certificate_Store *>{};
    }

    std::vector<Botan::X509_Certificate> find_cert_chain(
        const std::vector<std::string> &, const std::vector<Botan::AlgorithmIdentifier> &,
        const std::vector<Botan::X509_DN> &, const std::string &, const std::string &) override {
        return {};
    }

    std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate &,
                                                        const std::string &,
                                                        const std::string &) override {
        return {};
    }

  private:
    std::unique_ptr<Botan::Certificate_Store_In_Memory> roots_;
};

class V3Callbacks final : public Botan::TLS::Callbacks {
  public:
    using EmitHandler = std::function<void(std::span<const std::uint8_t>)>;
    using RecordHandler = std::function<void(std::span<const std::uint8_t>)>;

    V3Callbacks(std::string password, EmitHandler emit, RecordHandler record)
        : password_(std::move(password)), emit_(std::move(emit)), record_(std::move(record)) {}

    void tls_emit_data(std::span<const std::uint8_t> data) override {
        if (emit_) {
            emit_(data);
        }
    }

    void tls_record_received(std::uint64_t, std::span<const std::uint8_t> data) override {
        if (record_) {
            record_(data);
        }
    }

    void tls_alert(Botan::TLS::Alert alert) override { last_alert_ = alert.type_string(); }

    void tls_modify_client_hello_random(std::vector<std::uint8_t> &random,
                                        const Botan::TLS::Client_Hello &hello) override {
        if (random.size() != kTlsRandomSize) {
            throw Botan::TLS::TLS_Exception(
                Botan::TLS::Alert::IllegalParameter,
                "Shadow-TLS v3 ClientHello random has an invalid length");
        }
        // Botan exposes the session ID through a const accessor, although the
        // callback runs before the ClientHello enters the transcript. Mutating
        // the underlying strong value here keeps the authenticated bytes and
        // Botan's transcript in sync.
        auto &session_id = const_cast<Botan::TLS::Session_ID &>(hello.session_id()).get();
        if (session_id.size() != kTlsSessionIdSize) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::IllegalParameter,
                                            "Shadow-TLS v3 requires a 32-byte session ID");
        }
        auto hello_wire = handshake_wire(1, hello.serialize());
        if (hello_wire.size() < 39 + kTlsSessionIdSize || hello_wire[38] != kTlsSessionIdSize) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::DecodeError,
                                            "Shadow-TLS v3 ClientHello has no 32-byte session ID");
        }
        std::copy(random.begin(), random.end(), hello_wire.begin() + 6);
        std::fill(session_id.end() - static_cast<std::ptrdiff_t>(kTlsHmacSize), session_id.end(),
                  0);
        std::fill(hello_wire.begin() + 39 + kTlsSessionIdSize - kTlsHmacSize,
                  hello_wire.begin() + 39 + kTlsSessionIdSize, 0);
        const auto digest = hmac_sha1(password_, hello_wire);
        if (digest.size() < kTlsHmacSize) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::InternalError,
                                            "Shadow-TLS v3 ClientHello authentication failed");
        }
        std::copy_n(digest.begin(), kTlsHmacSize,
                    session_id.end() - static_cast<std::ptrdiff_t>(kTlsHmacSize));
    }

    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate> &,
                               const std::vector<std::optional<Botan::OCSP::Response>> &,
                               const std::vector<Botan::Certificate_Store *> &, Botan::Usage_Type,
                               std::string_view, const Botan::TLS::Policy &) override {
        // Botan performs the chain and hostname validation using the embedded
        // trust store supplied by V3Credentials when verification is enabled.
    }

    const std::string &last_alert() const noexcept { return last_alert_; }

  private:
    std::string password_;
    EmitHandler emit_;
    RecordHandler record_;
    std::string last_alert_;
};

bool verify_chain(std::string_view password, const std::vector<std::uint8_t> &chain,
                  std::span<const std::uint8_t> frame, bool append_digest,
                  std::vector<std::uint8_t> *updated_chain) {
    if (frame.size() < kTlsHeaderSize + kTlsHmacSize || frame[0] != kApplicationRecord ||
        frame[1] != 0x03 || frame[2] != 0x03) {
        return false;
    }
    const auto payload = frame.subspan(kTlsHeaderSize + kTlsHmacSize);
    std::vector<std::uint8_t> input = chain;
    input.insert(input.end(), payload.begin(), payload.end());
    const auto digest = hmac_sha1(password, input);
    if (digest.size() < kTlsHmacSize || !std::equal(digest.begin(), digest.begin() + kTlsHmacSize,
                                                    frame.begin() + kTlsHeaderSize)) {
        return false;
    }
    if (updated_chain) {
        updated_chain->assign(input.begin(), input.end());
        if (append_digest) {
            updated_chain->insert(updated_chain->end(), frame.begin() + kTlsHeaderSize,
                                  frame.begin() + kTlsHeaderSize + kTlsHmacSize);
        }
    }
    return true;
}

class ShadowTlsV3Stream final : public core::StreamHandle,
                                public std::enable_shared_from_this<ShadowTlsV3Stream> {
  public:
    static std::shared_ptr<ShadowTlsV3Stream>
    create(std::unique_ptr<core::StreamHandle> lower, std::string password,
           std::vector<std::uint8_t> server_random, std::vector<std::uint8_t> bridge_chain,
           std::vector<std::uint8_t> pending_plain, std::vector<std::uint8_t> initial_wire) {
        return std::shared_ptr<ShadowTlsV3Stream>(new ShadowTlsV3Stream(
            std::move(lower), std::move(password), std::move(server_random),
            std::move(bridge_chain), std::move(pending_plain), std::move(initial_wire)));
    }

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        if (read_handler_) {
            post_read(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_read(std::move(handler), {}, 0);
            return;
        }
        read_buffer_ = buffer;
        read_handler_ = std::move(handler);
        if (deliver_pending()) {
            return;
        }
        read_frame_header();
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        if (write_handler_ || closed_) {
            post_write(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_write(std::move(handler), {}, 0);
            return;
        }
        write_handler_ = std::move(handler);
        write_size_ = buffer.size();
        write_wire_.clear();
        const auto *bytes = static_cast<const std::uint8_t *>(buffer.data());
        for (std::size_t offset = 0; offset < buffer.size();) {
            const auto size = std::min(kMaxTlsPlaintext, buffer.size() - offset);
            const auto payload = std::span<const std::uint8_t>(bytes + offset, size);
            std::vector<std::uint8_t> input = write_chain_;
            input.insert(input.end(), payload.begin(), payload.end());
            const auto digest = hmac_sha1(password_, input);
            if (digest.size() < kTlsHmacSize) {
                finish_write(boost::asio::error::fault);
                return;
            }
            write_chain_ = std::move(input);
            write_chain_.insert(write_chain_.end(), digest.begin(), digest.begin() + kTlsHmacSize);
            write_wire_.insert(write_wire_.end(),
                               {kApplicationRecord, 0x03, 0x03,
                                static_cast<std::uint8_t>((size + kTlsHmacSize) >> 8),
                                static_cast<std::uint8_t>(size + kTlsHmacSize)});
            write_wire_.insert(write_wire_.end(), digest.begin(), digest.begin() + kTlsHmacSize);
            write_wire_.insert(write_wire_.end(), payload.begin(), payload.end());
            offset += size;
        }
        auto self = shared_from_this();
        lower_->async_write(boost::asio::buffer(write_wire_),
                            [self](const boost::system::error_code &error, std::size_t) {
                                self->finish_write(error);
                            });
    }

    boost::asio::any_io_executor executor() noexcept override { return lower_->executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        return lower_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        if (closed_) {
            error = boost::asio::error::operation_aborted;
            return;
        }
        shutdown_requested_ = true;
        error.clear();
        maybe_shutdown();
    }

    void close() noexcept override {
        if (closed_) {
            return;
        }
        closed_ = true;
        lower_->close();
        finish_read(boost::asio::error::operation_aborted, 0);
        finish_write(boost::asio::error::operation_aborted);
    }

  private:
    ShadowTlsV3Stream(std::unique_ptr<core::StreamHandle> lower, std::string password,
                      std::vector<std::uint8_t> server_random,
                      std::vector<std::uint8_t> bridge_chain,
                      std::vector<std::uint8_t> pending_plain,
                      std::vector<std::uint8_t> initial_wire)
        : lower_(std::move(lower)), password_(std::move(password)),
          server_random_(std::move(server_random)), bridge_chain_(std::move(bridge_chain)),
          pending_plain_(std::move(pending_plain)), initial_wire_(std::move(initial_wire)) {
        read_chain_ = server_random_;
        read_chain_.push_back('S');
        write_chain_ = server_random_;
        write_chain_.push_back('C');
    }

    void post_read(ReadHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(executor(), [handler = std::move(handler), error, size]() mutable {
            handler(error, size);
        });
    }

    void post_write(WriteHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(executor(), [handler = std::move(handler), error, size]() mutable {
            handler(error, size);
        });
    }

    bool deliver_pending() {
        if (!read_handler_ || pending_offset_ >= pending_plain_.size()) {
            return false;
        }
        const auto size = std::min(read_buffer_.size(), pending_plain_.size() - pending_offset_);
        std::memcpy(read_buffer_.data(), pending_plain_.data() + pending_offset_, size);
        pending_offset_ += size;
        if (pending_offset_ == pending_plain_.size()) {
            pending_plain_.clear();
            pending_offset_ = 0;
        }
        auto handler = std::move(read_handler_);
        post_read(std::move(handler), {}, size);
        return true;
    }

    void read_exact(boost::asio::mutable_buffer buffer, std::size_t offset,
                    std::function<void(const boost::system::error_code &)> handler) {
        if (offset == buffer.size()) {
            boost::asio::post(executor(),
                              [handler = std::move(handler)]() mutable { handler({}); });
            return;
        }
        if (initial_offset_ < initial_wire_.size()) {
            const auto available = initial_wire_.size() - initial_offset_;
            const auto amount = std::min(available, buffer.size() - offset);
            std::memcpy(static_cast<std::uint8_t *>(buffer.data()) + offset,
                        initial_wire_.data() + initial_offset_, amount);
            initial_offset_ += amount;
            read_exact(buffer, offset + amount, std::move(handler));
            return;
        }
        auto self = shared_from_this();
        lower_->async_read_some(
            boost::asio::mutable_buffer(static_cast<std::uint8_t *>(buffer.data()) + offset,
                                        buffer.size() - offset),
            [self, buffer, offset, handler = std::move(handler)](
                const boost::system::error_code &error, std::size_t size) mutable {
                if (error) {
                    handler(error);
                } else if (size == 0) {
                    handler(boost::asio::error::eof);
                } else {
                    self->read_exact(buffer, offset + size, std::move(handler));
                }
            });
    }

    void read_frame_header() {
        auto header = std::make_shared<std::array<std::uint8_t, kTlsHeaderSize>>();
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(*header), 0,
                   [self, header](const boost::system::error_code &error) {
                       if (error) {
                           self->finish_read(error, 0);
                           return;
                       }
                       const auto size =
                           (static_cast<std::size_t>((*header)[3]) << 8) | (*header)[4];
                       if (size == 0 || size > 0xffff) {
                           self->finish_read(boost::asio::error::fault, 0);
                           return;
                       }
                       self->read_payload_.resize(size);
                       self->read_frame_payload(*header);
                   });
    }

    void read_frame_payload(std::array<std::uint8_t, kTlsHeaderSize> header) {
        auto self = shared_from_this();
        read_exact(boost::asio::buffer(read_payload_), 0,
                   [self, header](const boost::system::error_code &error) {
                       if (error) {
                           self->finish_read(error, 0);
                           return;
                       }
                       std::vector<std::uint8_t> frame;
                       frame.reserve(kTlsHeaderSize + self->read_payload_.size());
                       frame.insert(frame.end(), header.begin(), header.end());
                       frame.insert(frame.end(), self->read_payload_.begin(),
                                    self->read_payload_.end());
                       self->handle_frame(std::move(frame));
                   });
    }

    void handle_frame(std::vector<std::uint8_t> frame) {
        if (frame[0] == kApplicationRecord && !bridge_chain_.empty()) {
            std::vector<std::uint8_t> next;
            if (verify_chain(password_, bridge_chain_, frame, false, &next)) {
                bridge_chain_ = std::move(next);
                read_frame_header();
                return;
            }
            bridge_chain_.clear();
        }
        if (frame[0] != kApplicationRecord ||
            !verify_chain(password_, read_chain_, frame, true, &read_chain_)) {
            finish_read(boost::asio::error::fault, 0);
            return;
        }
        pending_plain_.assign(frame.begin() + kTlsHeaderSize + kTlsHmacSize, frame.end());
        pending_offset_ = 0;
        (void)deliver_pending();
    }

    void finish_read(const boost::system::error_code &error, std::size_t size) {
        auto handler = std::move(read_handler_);
        if (handler) {
            handler(error, size);
        }
    }

    void finish_write(const boost::system::error_code &error) {
        auto handler = std::move(write_handler_);
        const auto size = error ? 0 : write_size_;
        write_size_ = 0;
        if (handler) {
            handler(error, size);
        }
        maybe_shutdown();
    }

    void maybe_shutdown() {
        if (!shutdown_requested_ || write_handler_ || closed_) {
            return;
        }
        shutdown_requested_ = false;
        boost::system::error_code ignored;
        lower_->shutdown_send(ignored);
    }

    std::unique_ptr<core::StreamHandle> lower_;
    std::string password_;
    std::vector<std::uint8_t> server_random_;
    std::vector<std::uint8_t> bridge_chain_;
    std::vector<std::uint8_t> read_chain_;
    std::vector<std::uint8_t> write_chain_;
    std::vector<std::uint8_t> pending_plain_;
    std::size_t pending_offset_ = 0;
    std::vector<std::uint8_t> initial_wire_;
    std::size_t initial_offset_ = 0;
    std::vector<std::uint8_t> read_payload_;
    boost::asio::mutable_buffer read_buffer_;
    ReadHandler read_handler_;
    WriteHandler write_handler_;
    std::vector<std::uint8_t> write_wire_;
    std::size_t write_size_ = 0;
    bool shutdown_requested_ = false;
    bool closed_ = false;
};

template <typename T> class SharedStreamAdapter final : public core::StreamHandle {
  public:
    explicit SharedStreamAdapter(std::shared_ptr<T> stream) : stream_(std::move(stream)) {}

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        stream_->async_read_some(buffer, std::move(handler));
    }
    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        stream_->async_write(buffer, std::move(handler));
    }
    boost::asio::any_io_executor executor() noexcept override { return stream_->executor(); }
    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        return stream_->local_endpoint(error);
    }
    void shutdown_send(boost::system::error_code &error) noexcept override {
        stream_->shutdown_send(error);
    }
    void close() noexcept override { stream_->close(); }

  private:
    std::shared_ptr<T> stream_;
};

class ShadowTlsV3OpenOperation final
    : public std::enable_shared_from_this<ShadowTlsV3OpenOperation> {
  public:
    ShadowTlsV3OpenOperation(std::unique_ptr<core::StreamHandle> stream,
                             ShadowTlsClientOptions options, ShadowTlsOpenHandler handler)
        : stream_(std::move(stream)), options_(std::move(options)), handler_(std::move(handler)),
          timer_(stream_->executor()) {}

    void start() {
        if (!stream_ || options_.host.empty() || options_.password.empty()) {
            finish(core::fail(v3_error(core::ErrorCode::configuration,
                                       "Shadow-TLS v3 host and password are required")));
            return;
        }
        timer_.expires_after(kHandshakeTimeout);
        timer_.async_wait([self = shared_from_this()](const boost::system::error_code &error) {
            if (!error && !self->completed_) {
                self->finish(core::fail(
                    v3_error(core::ErrorCode::timeout, "Shadow-TLS v3 TLS handshake timed out")));
            }
        });
        try {
            rng_ = std::make_shared<Botan::AutoSeeded_RNG>();
            callbacks_ = std::make_shared<V3Callbacks>(
                options_.password,
                [self = shared_from_this()](std::span<const std::uint8_t> data) {
                    self->emit_tls(data);
                },
                [self = shared_from_this()](std::span<const std::uint8_t> data) {
                    self->pending_plain_.insert(self->pending_plain_.end(), data.begin(),
                                                data.end());
                });
            policy_ = std::make_shared<V3Policy>();
            credentials_ = std::make_shared<V3Credentials>(!options_.skip_cert_verify);
            session_manager_ = std::make_shared<Botan::TLS::Session_Manager_Noop>();
            Botan::TLS::Server_Information info(options_.host);
            auto alpn = options_.alpn_protocols;
            if (alpn.empty()) {
                alpn = {"h2", "http/1.1"};
            }
            tls_client_ = std::make_unique<Botan::TLS::Client>(
                callbacks_, session_manager_, credentials_, policy_, rng_, info,
                Botan::TLS::Protocol_Version::TLS_V13, alpn);
            read_wire();
            start_tls_write();
        } catch (const std::exception &exception) {
            finish(core::fail(
                v3_exception("failed to initialize Shadow-TLS v3 TLS client", exception)));
        } catch (...) {
            finish(core::fail(v3_error(core::ErrorCode::carrier_handshake,
                                       "failed to initialize Shadow-TLS v3 TLS client")));
        }
    }

  private:
    void emit_tls(std::span<const std::uint8_t> data) {
        if (completed_) {
            return;
        }
        tls_write_queue_.emplace_back(data.begin(), data.end());
        start_tls_write();
        maybe_open();
    }

    void start_tls_write() {
        if (completed_ || tls_write_in_progress_ || tls_write_queue_.empty()) {
            return;
        }
        tls_write_in_progress_ = true;
        tls_write_current_ = std::move(tls_write_queue_.front());
        tls_write_queue_.erase(tls_write_queue_.begin());
        auto self = shared_from_this();
        stream_->async_write(boost::asio::buffer(tls_write_current_),
                             [self](const boost::system::error_code &error, std::size_t) {
                                 self->tls_write_in_progress_ = false;
                                 self->tls_write_current_.clear();
                                 if (error) {
                                     self->finish(core::fail(v3_io_error(
                                         "failed to write Shadow-TLS v3 TLS record", error)));
                                     return;
                                 }
                                 self->start_tls_write();
                                 self->maybe_open();
                             });
    }

    void read_wire() {
        if (completed_ || read_in_progress_ || handshake_complete_) {
            return;
        }
        read_in_progress_ = true;
        auto self = shared_from_this();
        stream_->async_read_some(
            boost::asio::buffer(read_temp_),
            [self](const boost::system::error_code &error, std::size_t size) {
                self->read_in_progress_ = false;
                if (error) {
                    self->finish(
                        core::fail(v3_io_error("failed to read Shadow-TLS v3 TLS record", error)));
                    return;
                }
                if (size == 0) {
                    self->finish(core::fail(v3_error(core::ErrorCode::transport_io,
                                                     "Shadow-TLS v3 handshake reached EOF")));
                    return;
                }
                self->input_.insert(self->input_.end(), self->read_temp_.begin(),
                                    self->read_temp_.begin() + static_cast<std::ptrdiff_t>(size));
                try {
                    self->process_input();
                } catch (const std::exception &exception) {
                    self->finish(
                        core::fail(v3_exception("Shadow-TLS v3 handshake failed", exception)));
                    return;
                } catch (...) {
                    self->finish(core::fail(v3_error(core::ErrorCode::carrier_handshake,
                                                     "Shadow-TLS v3 handshake failed")));
                    return;
                }
                if (!self->handshake_complete_) {
                    self->read_wire();
                }
            });
    }

    void process_input() {
        while (!handshake_complete_) {
            if (input_.size() < kTlsHeaderSize) {
                return;
            }
            const auto size = (static_cast<std::size_t>(input_[3]) << 8) | input_[4];
            if (size == 0 || size > 0xffff) {
                throw std::runtime_error("invalid Shadow-TLS v3 TLS record length");
            }
            const auto frame_size = kTlsHeaderSize + size;
            if (input_.size() < frame_size) {
                return;
            }
            std::vector<std::uint8_t> frame(
                input_.begin(), input_.begin() + static_cast<std::ptrdiff_t>(frame_size));
            input_.erase(input_.begin(), input_.begin() + static_cast<std::ptrdiff_t>(frame_size));
            process_frame(frame);
        }
    }

    void process_frame(std::vector<std::uint8_t> &frame) {
        if (frame[0] == kHandshakeRecord && frame.size() >= 5 + 1 + 3 + 2 + kTlsRandomSize &&
            frame[5] == 2 && server_random_.empty()) {
            server_random_.assign(frame.begin() + 5 + 1 + 3 + 2,
                                  frame.begin() + 5 + 1 + 3 + 2 + kTlsRandomSize);
            bridge_chain_ = server_random_;
            read_key_ = sha256(concat(options_.password, server_random_));
        }
        if (frame[0] == kApplicationRecord && !bridge_chain_.empty()) {
            if (frame.size() < kTlsHeaderSize + kTlsHmacSize) {
                throw std::runtime_error("invalid Shadow-TLS v3 authenticated TLS record");
            }
            std::vector<std::uint8_t> next;
            if (!verify_chain(options_.password, bridge_chain_, frame, false, &next)) {
                throw std::runtime_error("Shadow-TLS v3 bridge HMAC mismatch");
            }
            const auto payload =
                std::span<std::uint8_t>(frame).subspan(kTlsHeaderSize + kTlsHmacSize);
            bridge_chain_ = std::move(next);
            xor_with_key(payload, read_key_);
            std::vector<std::uint8_t> decoded;
            decoded.reserve(kTlsHeaderSize + payload.size());
            decoded.insert(decoded.end(), frame.begin(), frame.begin() + kTlsHeaderSize);
            decoded.insert(decoded.end(), payload.begin(), payload.end());
            frame = std::move(decoded);
            frame[3] = static_cast<std::uint8_t>(payload.size() >> 8);
            frame[4] = static_cast<std::uint8_t>(payload.size());
            authorized_ = true;
        }
        tls_client_->received_data(frame);
        if (tls_client_->is_handshake_complete()) {
            handshake_complete_ = true;
            maybe_open();
        }
    }

    void maybe_open() {
        if (completed_ || !handshake_complete_ || !authorized_ || server_random_.size() != 32 ||
            tls_write_in_progress_ || !tls_write_queue_.empty()) {
            return;
        }
        (void)timer_.cancel();
        completed_ = true;
        auto lower = std::move(stream_);
        auto stream = ShadowTlsV3Stream::create(std::move(lower), options_.password,
                                                std::move(server_random_), std::move(bridge_chain_),
                                                std::move(pending_plain_), std::move(input_));
        auto handler = std::move(handler_);
        if (handler) {
            handler(core::Result<std::unique_ptr<core::StreamHandle>>(
                std::make_unique<SharedStreamAdapter<ShadowTlsV3Stream>>(std::move(stream))));
        }
    }

    void finish(core::Result<std::unique_ptr<core::StreamHandle>> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        (void)timer_.cancel();
        if (!result && stream_) {
            stream_->close();
            stream_.reset();
        }
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    std::unique_ptr<core::StreamHandle> stream_;
    ShadowTlsClientOptions options_;
    ShadowTlsOpenHandler handler_;
    boost::asio::steady_timer timer_;
    std::shared_ptr<Botan::RandomNumberGenerator> rng_;
    std::shared_ptr<V3Callbacks> callbacks_;
    std::shared_ptr<V3Policy> policy_;
    std::shared_ptr<V3Credentials> credentials_;
    std::shared_ptr<Botan::TLS::Session_Manager> session_manager_;
    std::unique_ptr<Botan::TLS::Client> tls_client_;
    std::vector<std::uint8_t> input_;
    std::vector<std::uint8_t> read_temp_ = std::vector<std::uint8_t>(kTlsRecordBufferSize);
    std::vector<std::vector<std::uint8_t>> tls_write_queue_;
    std::vector<std::uint8_t> tls_write_current_;
    std::vector<std::uint8_t> pending_plain_;
    std::vector<std::uint8_t> server_random_;
    std::vector<std::uint8_t> bridge_chain_;
    std::array<std::uint8_t, 32> read_key_{};
    bool tls_write_in_progress_ = false;
    bool read_in_progress_ = false;
    bool handshake_complete_ = false;
    bool authorized_ = false;
    bool completed_ = false;
};

} // namespace

void async_open_shadow_tls_v3(std::unique_ptr<core::StreamHandle> stream,
                              ShadowTlsClientOptions options, ShadowTlsOpenHandler handler) {
    if (!stream || !handler) {
        if (stream) {
            stream->close();
        }
        if (handler) {
            handler(core::fail(v3_error(core::ErrorCode::configuration,
                                        "Shadow-TLS v3 requires a stream and completion handler")));
        }
        return;
    }
    std::make_shared<ShadowTlsV3OpenOperation>(std::move(stream), std::move(options),
                                               std::move(handler))
        ->start();
}

} // namespace clash_native::transport::shadowsocks
