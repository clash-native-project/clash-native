#include <clash_native/transport/proxy/gun_stream.hpp>

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include <stdexec/execution.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/errc.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace clash_native::transport::proxy::gun {

namespace {

// Bridges one exchange pull/push back into a legacy (error, size) handler.
struct BodyReadBridge {
    using receiver_concept = stdexec::receiver_tag;
    std::function<void(const boost::system::error_code &, std::size_t)> handler;
    void set_value(std::optional<std::size_t> size) && noexcept {
        auto callback = std::move(handler);
        if (size) {
            callback({}, *size);
        } else {
            callback(boost::asio::error::eof, 0);
        }
    }
    void set_error(std::exception_ptr error) && noexcept {
        auto callback = std::move(handler);
        callback(net::unpack_error(std::move(error)), 0);
    }
    void set_stopped() && noexcept {
        auto callback = std::move(handler);
        callback(boost::asio::error::operation_aborted, 0);
    }
};

constexpr std::size_t kMaxFramePayload = 8 * 1024 * 1024;
// Caps queued request bytes; writers park past this until the session drains.
constexpr std::size_t kRequestQueueCapacity = 256 * 1024;

boost::system::error_code protocol_error() {
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

// Producer request body: gun writes push framed bytes, the HTTP/2 session
// pulls them as flow control allows. EOF (finish) ends the request stream
// while the response keeps flowing.
class GunRequestBody final : public io::ExchangeBodyStream,
                             public std::enable_shared_from_this<GunRequestBody> {
  public:
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
    using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    struct QueuedWrite {
        std::shared_ptr<std::vector<std::uint8_t>> bytes;
        WriteHandler handler;
        std::size_t size = 0;
        std::size_t offset = 0;
    };

    explicit GunRequestBody(boost::asio::any_io_executor executor) : executor_(executor) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
            [self = shared_from_this(), buffer](auto terminal) mutable {
                self->read_some(buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{size});
                    return;
                }
                if (error == boost::asio::error::eof) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{});
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(std::move(receiver), std::make_exception_ptr(core::Error{
                                                            core::ErrorCode::transport_io,
                                                            "gun request read failed", error}));
            })};
    }

    std::vector<io::ExchangeField> trailers() const override { return {}; }

    void cancel() noexcept override { close(); }

    void write(std::shared_ptr<std::vector<std::uint8_t>> bytes, WriteHandler handler) {
        const auto self = shared_from_this();
        boost::asio::post(
            executor_, [self, bytes = std::move(bytes), handler = std::move(handler)]() mutable {
                if (self->closed_) {
                    handler(boost::asio::error::operation_aborted, 0);
                    return;
                }
                const auto size = bytes->size();
                // Past capacity the write parks in overflow until pump_reads
                // drains the active queue below the gate.
                if (self->queued_bytes_ + size > kRequestQueueCapacity) {
                    self->overflow_.push_back({std::move(bytes), std::move(handler), size, 0});
                    return;
                }
                self->queued_bytes_ += size;
                self->writes_.push_back({std::move(bytes), std::move(handler), size, 0});
                self->pump_reads();
            });
    }

    void finish() {
        const auto self = shared_from_this();
        boost::asio::post(executor_, [self] {
            if (self->closed_ || self->eof_) {
                return;
            }
            self->eof_ = true;
            self->pump_reads();
        });
    }

    void close() {
        const auto self = shared_from_this();
        boost::asio::post(executor_, [self] {
            if (self->closed_) {
                return;
            }
            self->closed_ = true;
            if (self->read_handler_) {
                auto handler = std::move(self->read_handler_);
                self->read_buffer_ = {};
                boost::asio::post(self->executor_, [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::operation_aborted, 0);
                });
            }
            const auto abort = [executor = self->executor_](QueuedWrite pending) {
                boost::asio::post(executor, [handler = std::move(pending.handler)]() mutable {
                    handler(boost::asio::error::operation_aborted, 0);
                });
            };
            while (!self->writes_.empty()) {
                auto pending = std::move(self->writes_.front());
                self->writes_.pop_front();
                abort(std::move(pending));
            }
            while (!self->overflow_.empty()) {
                auto pending = std::move(self->overflow_.front());
                self->overflow_.pop_front();
                abort(std::move(pending));
            }
        });
    }

  private:
    void read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        const auto self = shared_from_this();
        boost::asio::post(executor_, [self, buffer, handler = std::move(handler)]() mutable {
            if (self->closed_) {
                handler(boost::asio::error::operation_aborted, 0);
                return;
            }
            if (buffer.size() == 0) {
                handler({}, 0);
                return;
            }
            if (self->read_handler_) {
                handler(boost::asio::error::already_started, 0);
                return;
            }
            self->read_buffer_ = buffer;
            self->read_handler_ = std::move(handler);
            self->pump_reads();
        });
    }

    // Moves queued writes into the parked read; parks the read on an empty
    // queue, ends it on EOF, and admits overflow writes as bytes drain.
    void pump_reads() {
        if (!read_handler_ || closed_) {
            return;
        }
        while (!writes_.empty()) {
            auto &front = writes_.front();
            const auto space = read_buffer_.size() - delivered_;
            const auto amount = std::min(space, front.bytes->size() - front.offset);
            if (amount == 0) {
                break;
            }
            std::memcpy(static_cast<std::uint8_t *>(read_buffer_.data()) + delivered_,
                        front.bytes->data() + front.offset, amount);
            delivered_ += amount;
            front.offset += amount;
            queued_bytes_ -= amount;
            if (front.offset == front.bytes->size()) {
                auto pending = std::move(writes_.front());
                writes_.pop_front();
                const auto executor = executor_;
                boost::asio::post(executor, [handler = std::move(pending.handler),
                                             size = pending.size]() mutable { handler({}, size); });
            }
        }
        admit_overflow();
        if (delivered_ > 0 && (writes_.empty() || delivered_ == read_buffer_.size())) {
            auto handler = std::move(read_handler_);
            const auto size = delivered_;
            delivered_ = 0;
            read_buffer_ = {};
            const auto executor = executor_;
            boost::asio::post(
                executor, [handler = std::move(handler), size]() mutable { handler({}, size); });
            return;
        }
        if (writes_.empty() && eof_) {
            auto handler = std::move(read_handler_);
            read_buffer_ = {};
            const auto executor = executor_;
            boost::asio::post(executor, [handler = std::move(handler)]() mutable {
                handler(boost::asio::error::eof, 0);
            });
        }
    }

    void admit_overflow() {
        while (!overflow_.empty() &&
               queued_bytes_ + overflow_.front().bytes->size() <= kRequestQueueCapacity) {
            auto pending = std::move(overflow_.front());
            overflow_.pop_front();
            queued_bytes_ += pending.bytes->size();
            writes_.push_back(std::move(pending));
        }
    }

    boost::asio::any_io_executor executor_;
    std::deque<QueuedWrite> writes_;
    std::deque<QueuedWrite> overflow_;
    std::size_t queued_bytes_ = 0;
    boost::asio::mutable_buffer read_buffer_;
    std::size_t delivered_ = 0;
    ReadHandler read_handler_;
    bool eof_ = false;
    bool closed_ = false;
};

class GunStreamState final : public std::enable_shared_from_this<GunStreamState> {
  public:
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
    using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    GunStreamState(std::shared_ptr<GunRequestBody> request_body,
                   boost::asio::any_io_executor executor)
        : request_body_(std::move(request_body)), executor_(std::move(executor)) {}

    // Attaches the response body once the head arrives; resumes a
    // parked read if any.
    void attach_response_body(std::shared_ptr<io::ExchangeBodyStream> body) {
        response_body_ = std::move(body);
        if (read_in_progress_ && receive_handler_) {
            read_frame_prefix();
        }
    }

    // Poisons the stream: pending and future reads/writes fail.
    void poison(core::Error error) {
        (void)error;
        poisoned_ = true;
        request_body_->close();
        if (response_body_) {
            response_body_->cancel();
        }
        if (read_in_progress_) {
            read_in_progress_ = false;
            auto handler = std::move(receive_handler_);
            if (handler) {
                post_read_result(std::move(handler), protocol_error(), 0);
            }
        }
    }

    boost::asio::any_io_executor executor() noexcept { return executor_; }

    void send(boost::asio::const_buffer buffer, WriteHandler handler) {
        if (closed_) {
            post_write_result(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (poisoned_) {
            post_write_result(std::move(handler), protocol_error(), 0);
            return;
        }
        if (buffer.size() > kMaxFramePayload) {
            post_write_result(std::move(handler), protocol_error(), 0);
            return;
        }
        const auto *data = static_cast<const std::uint8_t *>(buffer.data());
        auto frame =
            std::make_shared<std::vector<std::uint8_t>>(encode_frame({data, buffer.size()}));
        const auto size = buffer.size();
        request_body_->write(std::move(frame),
                             [handler = std::move(handler),
                              size](const boost::system::error_code &error, std::size_t) mutable {
                                 if (error) {
                                     handler(error, 0);
                                 } else {
                                     handler({}, size);
                                 }
                             });
    }

    void receive(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        if (closed_) {
            post_read_result(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (poisoned_) {
            post_read_result(std::move(handler), protocol_error(), 0);
            return;
        }
        if (read_in_progress_) {
            post_read_result(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_read_result(std::move(handler), {}, 0);
            return;
        }
        read_in_progress_ = true;
        output_buffer_ = buffer;
        receive_handler_ = std::move(handler);
        // The response body arrives with the head, after our first
        // writes; park until attach_response_body resumes us.
        if (!response_body_) {
            return;
        }
        if (remain_ > 0) {
            read_remainder();
            return;
        }
        read_frame_prefix();
    }

    void shutdown_send() {
        if (closed_) {
            return;
        }
        request_body_->finish();
    }

    void close() {
        if (closed_) {
            return;
        }
        closed_ = true;
        // Body cancels wind the exchange down; no per-exchange cancel exists
        // in the io:: vocabulary (late terminals drop at the shells).
        request_body_->close();
        if (response_body_) {
            response_body_->cancel();
        }
        if (read_in_progress_) {
            read_in_progress_ = false;
            auto handler = std::move(receive_handler_);
            const auto executor = executor_;
            boost::asio::post(executor, [handler = std::move(handler)]() mutable {
                handler(boost::asio::error::operation_aborted, 0);
            });
        }
    }

  private:
    void post_write_result(WriteHandler handler, const boost::system::error_code &error,
                           std::size_t size) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            handler(error, size);
        });
    }

    void post_read_result(ReadHandler handler, const boost::system::error_code &error,
                          std::size_t size) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            handler(error, size);
        });
    }

    void read_exact(std::shared_ptr<std::vector<std::uint8_t>> buffer, std::size_t offset,
                    std::function<void(const boost::system::error_code &)> completion) {
        auto self = shared_from_this();
        auto read_buffer =
            boost::asio::mutable_buffer(buffer->data() + offset, buffer->size() - offset);
        std::function<void(const boost::system::error_code &, std::size_t)> pull =
            [self, buffer = std::move(buffer), offset, completion = std::move(completion)](
                const boost::system::error_code &error, std::size_t size) mutable {
                if (error) {
                    completion(error);
                    return;
                }
                if (size == 0) {
                    completion(boost::asio::error::eof);
                    return;
                }
                const auto next = offset + size;
                if (next == buffer->size()) {
                    completion({});
                    return;
                }
                self->read_exact(std::move(buffer), next, std::move(completion));
            };
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = response_body_->async_read_some(read_buffer);
        async::start_with_receiver(std::move(sender), BodyReadBridge{std::move(pull)});
    }

    // Delivers the parked remainder first, like gun's remain handling.
    void read_remainder() {
        const auto amount = std::min(output_buffer_.size(), remain_);
        auto chunk = std::make_shared<std::vector<std::uint8_t>>(amount);
        auto self = shared_from_this();
        read_exact(chunk, 0, [self, chunk](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0);
                return;
            }
            self->remain_ -= chunk->size();
            std::memcpy(self->output_buffer_.data(), chunk->data(), chunk->size());
            self->finish_receive({}, chunk->size());
        });
    }

    void read_frame_prefix() {
        auto prefix = std::make_shared<std::vector<std::uint8_t>>(kFramePrefixSize);
        auto self = shared_from_this();
        read_exact(prefix, 0, [self, prefix](const boost::system::error_code &error) {
            if (error == boost::asio::error::eof) {
                self->finish_receive(boost::asio::error::eof, 0);
                return;
            }
            if (error) {
                self->finish_receive(error, 0);
                return;
            }
            // 0x00 | u32be length | 0x0A, then a uvarint payload length.
            if ((*prefix)[0] != 0x00 || (*prefix)[5] != 0x0a) {
                self->finish_receive(protocol_error(), 0);
                return;
            }
            self->read_frame_length(0, 0);
        });
    }

    // Accumulates the uvarint payload length one byte at a time (at most
    // ten bytes); a set continuation on the tenth byte is corrupt.
    void read_frame_length(std::uint64_t value, std::size_t shift) {
        auto byte = std::make_shared<std::vector<std::uint8_t>>(1);
        auto self = shared_from_this();
        read_exact(byte, 0, [self, byte, value, shift](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(protocol_error(), 0);
                return;
            }
            const auto next = value | (static_cast<std::uint64_t>((*byte)[0] & 0x7f) << shift);
            if (((*byte)[0] & 0x80) == 0) {
                self->read_frame_payload(next);
                return;
            }
            if (shift >= 63) {
                self->finish_receive(protocol_error(), 0);
                return;
            }
            self->read_frame_length(next, shift + 7);
        });
    }

    void read_frame_payload(std::uint64_t payload_size) {
        if (payload_size > kMaxFramePayload) {
            finish_receive(protocol_error(), 0);
            return;
        }
        remain_ = static_cast<std::size_t>(payload_size);
        read_remainder();
    }

    void finish_receive(const boost::system::error_code &error, std::size_t size) {
        read_in_progress_ = false;
        auto handler = std::move(receive_handler_);
        if (handler) {
            handler(error, size);
        }
    }

    std::shared_ptr<io::ExchangeBodyStream> response_body_;
    std::shared_ptr<GunRequestBody> request_body_;
    boost::asio::any_io_executor executor_;
    boost::asio::mutable_buffer output_buffer_;
    ReadHandler receive_handler_;
    std::size_t remain_ = 0;
    bool read_in_progress_ = false;
    bool closed_ = false;
    bool poisoned_ = false;
};

class GunStreamHandle final : public io::StreamHandle {
  public:
    explicit GunStreamHandle(std::shared_ptr<GunStreamState> state) : state_(std::move(state)) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
            [state = state_, buffer](auto terminal) mutable {
                state->receive(buffer, [terminal = std::move(terminal)](
                                           const boost::system::error_code &error,
                                           std::size_t size) mutable { terminal(error, size); });
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{size});
                    return;
                }
                if (error == boost::asio::error::eof) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{});
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(std::move(receiver), std::make_exception_ptr(core::Error{
                                                            core::ErrorCode::transport_io,
                                                            "gun stream read failed", error}));
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        return io::AnySender<std::size_t>{async::callback_sender<Signatures>(
            [state = state_, buffer](auto terminal) mutable {
                state->send(buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), size);
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(std::move(receiver), std::make_exception_ptr(core::Error{
                                                            core::ErrorCode::transport_io,
                                                            "gun stream write failed", error}));
            })};
    }

    boost::asio::any_io_executor executor() noexcept override { return state_->executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        error = boost::asio::error::operation_not_supported;
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        error.clear();
        state_->shutdown_send();
    }

    void close() noexcept override { state_->close(); }

  private:
    std::shared_ptr<GunStreamState> state_;
};

} // namespace

std::size_t uvarint_length(std::uint64_t value) noexcept {
    std::size_t length = 1;
    while (value >= 0x80) {
        value >>= 7;
        ++length;
    }
    return length;
}

std::vector<std::uint8_t> encode_frame(std::span<const std::uint8_t> payload) {
    const auto varlen = uvarint_length(payload.size());
    std::vector<std::uint8_t> frame;
    frame.reserve(kFramePrefixSize + varlen + payload.size());
    frame.push_back(0x00);
    const auto total = static_cast<std::uint32_t>(1 + varlen + payload.size());
    frame.push_back(static_cast<std::uint8_t>(total >> 24));
    frame.push_back(static_cast<std::uint8_t>(total >> 16));
    frame.push_back(static_cast<std::uint8_t>(total >> 8));
    frame.push_back(static_cast<std::uint8_t>(total));
    frame.push_back(0x0a);
    auto value = static_cast<std::uint64_t>(payload.size());
    do {
        auto byte = static_cast<std::uint8_t>(value & 0x7f);
        value >>= 7;
        if (value != 0) {
            byte |= 0x80;
        }
        frame.push_back(byte);
    } while (value != 0);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

void async_open_gun_stream(std::shared_ptr<io::ExchangeSession> session, GunStreamOptions options,
                           GunStreamHandler handler) {
    if (!session) {
        handler(core::fail(
            {core::ErrorCode::configuration, "gun stream requires an exchange session"}));
        return;
    }
    if (!options.executor) {
        handler(core::fail({core::ErrorCode::configuration, "gun stream requires an executor"}));
        return;
    }
    const auto service = options.service_name.empty() ? "GunService" : options.service_name;
    const auto target = service.front() == '/' ? service : "/" + service + "/Tun";
    // Eager open: the handle is delivered before start() returns so the
    // caller can write immediately; the head resolves in the background
    // and attaches (or poisons) the shared state. The handler fires
    // exactly once, with the eager handle.
    struct Opener : public std::enable_shared_from_this<Opener> {
        std::shared_ptr<io::ExchangeSession> session;
        GunStreamOptions options;
        GunStreamHandler handler;
        io::ExchangeRequest head;
        std::shared_ptr<GunRequestBody> request_body;
        std::shared_ptr<GunStreamState> state;
        struct OpenBridge {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<Opener> opener;
            void set_value(io::StreamingExchangeResponse response) && noexcept {
                auto self = std::move(opener);
                if (response.response.status != 200) {
                    self->state->poison({core::ErrorCode::protocol_framing,
                                         "gun handshake saw unexpected HTTP status"});
                    return;
                }
                self->state->attach_response_body(std::move(response.body));
            }
            void set_error(std::exception_ptr error) && noexcept {
                auto self = std::move(opener);
                core::Error failure{core::ErrorCode::transport_io, "gun handshake failed"};
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const core::Error &open_failure) {
                    failure = open_failure;
                } catch (...) {
                }
                self->state->poison(failure);
            }
            void set_stopped() && noexcept {
                auto self = std::move(opener);
                self->state->poison({core::ErrorCode::cancelled, "gun handshake cancelled"});
            }
        };
        void start() {
            auto self = shared_from_this();
            request_body = std::make_shared<GunRequestBody>(options.executor);
            state = std::make_shared<GunStreamState>(request_body, options.executor);
            handler(std::unique_ptr<io::StreamHandle>(std::make_unique<GunStreamHandle>(state)));
            io::StreamingExchangeRequest streaming;
            streaming.request = std::move(head);
            streaming.body = request_body;
            streaming.content_length = std::nullopt;
            streaming.head_deadline_only = true;
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = session->exchange_streaming(std::move(streaming), options.deadline);
            async::start_with_receiver(std::move(sender), OpenBridge{self});
        }
    };
    io::ExchangeRequest head;
    head.method = "POST";
    head.scheme = "https";
    head.authority = options.host;
    head.target = target;
    head.headers.push_back({"content-type", "application/grpc"});
    head.headers.push_back(
        {"user-agent", options.user_agent.empty() ? "grpc-go/1.36.0" : options.user_agent});
    head.keep_alive = true;
    auto opener = std::make_shared<Opener>();
    opener->session = std::move(session);
    opener->options = std::move(options);
    opener->handler = std::move(handler);
    opener->head = std::move(head);
    opener->start();
}

} // namespace clash_native::transport::proxy::gun
