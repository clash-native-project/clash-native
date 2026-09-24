#include <clash_native/transport/proxy/gun_client.hpp>

#include <clash_native/async/bridge.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/io/sender.hpp>

#include <stdexec/execution.hpp>

#include <exception>
#include <memory>
#include <mutex>
#include <utility>

namespace clash_native::transport::proxy::gun {

GunClient::GunClient(GunClientOptions options, SessionMaker maker)
    : options_(std::move(options)), maker_(std::move(maker)) {
    if (options_.max_connections == 0 && options_.min_streams == 0 && options_.max_streams == 0) {
        options_.max_connections = 1;
    }
}

std::shared_ptr<GunClient::TransportEntry> GunClient::pick_transport() {
    std::lock_guard lock(mutex_);
    if (closed_) {
        return nullptr;
    }
    std::shared_ptr<TransportEntry> lightest;
    for (const auto &entry : transports_) {
        if (!lightest || entry->streams.load(std::memory_order_relaxed) <
                             lightest->streams.load(std::memory_order_relaxed)) {
            lightest = entry;
        }
    }
    if (!lightest) {
        lightest = std::make_shared<TransportEntry>();
        transports_.push_back(lightest);
        return lightest;
    }
    const auto streams = lightest->streams.load(std::memory_order_relaxed);
    if (streams == 0) {
        return lightest;
    }
    if (options_.max_connections > 0) {
        if (static_cast<int>(transports_.size()) >= options_.max_connections ||
            streams < options_.min_streams) {
            return lightest;
        }
    } else {
        if (options_.max_streams > 0 && streams < options_.max_streams) {
            return lightest;
        }
    }
    lightest = std::make_shared<TransportEntry>();
    transports_.push_back(lightest);
    return lightest;
}

io::AnySender<std::unique_ptr<io::StreamHandle>> GunClient::dial() {
    auto self = shared_from_this();
    auto entry = pick_transport();
    if (!entry) {
        return io::AnySender<std::unique_ptr<io::StreamHandle>>{
            stdexec::just_error(std::make_exception_ptr(
                core::Error{core::ErrorCode::cancelled, "gun client is closed"}))};
    }
    entry->streams.fetch_add(1, std::memory_order_relaxed);
    // Release the reservation if the open below never delivers a stream.
    struct Guard {
        std::shared_ptr<TransportEntry> entry;
        bool armed = true;
        ~Guard() {
            if (armed) {
                entry->streams.fetch_sub(1, std::memory_order_relaxed);
            }
        }
    };
    // NOTE: fill the shared guard in place; a Guard{entry} temporary
    // would run its armed destructor and release the reservation early.
    auto guard = std::make_shared<Guard>();
    guard->entry = entry;
    auto maker = maker_;
    auto options = options_.stream;
    options.deadline = std::chrono::steady_clock::now() + options_.open_timeout;
    // Callback open chain (no task: the dial path stays on plain shared
    // state): ensure the Transport session, then the Tun stream, and
    // deliver the in-band result through done exactly once.
    struct Open : public std::enable_shared_from_this<Open> {
        std::shared_ptr<TransportEntry> entry;
        GunClient::SessionMaker maker;
        gun::GunStreamOptions options;
        std::shared_ptr<Guard> guard;
        async::BridgeSender<core::Result<std::unique_ptr<io::StreamHandle>>>::Handler done;
        bool delivered = false;
        void start() {
            if (entry->session) {
                open_stream();
                return;
            }
            auto self = shared_from_this();
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = maker();
            async::start_with_receiver(std::move(sender), MakerReceiver{self});
        }
        struct MakerReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<Open> open;
            void set_value(std::shared_ptr<io::ExchangeSession> session) && noexcept {
                auto self = std::move(open);
                self->entry->session = std::move(session);
                self->open_stream();
            }
            void set_error(std::exception_ptr error) && noexcept {
                auto self = std::move(open);
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const core::Error &failure) {
                    self->finish(core::fail(failure));
                    return;
                } catch (...) {
                }
                self->finish(
                    core::fail({core::ErrorCode::transport_io, "gun session open failed"}));
            }
            void set_stopped() && noexcept {
                auto self = std::move(open);
                self->finish(
                    core::fail({core::ErrorCode::cancelled, "gun session open cancelled"}));
            }
        };
        void open_stream() {
            auto self = shared_from_this();
            gun::async_open_gun_stream(
                entry->session, options,
                [self](core::Result<std::unique_ptr<io::StreamHandle>> opened) mutable {
                    if (!opened) {
                        self->finish(core::fail(opened.error()));
                        return;
                    }
                    self->guard->armed = false;
                    self->finish(core::Result<std::unique_ptr<io::StreamHandle>>{
                        std::unique_ptr<io::StreamHandle>(std::make_unique<CountedStreamHandle>(
                            std::move(opened.value()), self->entry))});
                });
        }
        void finish(core::Result<std::unique_ptr<io::StreamHandle>> result) {
            if (delivered) {
                return;
            }
            delivered = true;
            done(std::move(result));
        }
    };
    auto open = std::make_shared<Open>();
    open->entry = entry;
    open->maker = std::move(maker);
    open->options = std::move(options);
    open->guard = std::move(guard);
    auto bridged = async::bridge_sender<core::Result<std::unique_ptr<io::StreamHandle>>>(
        [open](async::BridgeSender<core::Result<std::unique_ptr<io::StreamHandle>>>::Handler
                   done) mutable {
            // The bridge starter must be copyable: all state rides in
            // the shared open box; a second start after the move fails
            // fast instead of hanging.
            if (open->done) {
                auto late = std::move(done);
                late(core::fail({core::ErrorCode::cancelled, "gun dial restarted"}));
                using AbortFn =
                    async::BridgeSender<core::Result<std::unique_ptr<io::StreamHandle>>>::AbortFn;
                return AbortFn{[] {}};
            }
            open->done = std::move(done);
            open->start();
            using AbortFn =
                async::BridgeSender<core::Result<std::unique_ptr<io::StreamHandle>>>::AbortFn;
            return AbortFn{[] {}};
        });
    auto sender = std::move(bridged) |
                  stdexec::then([](core::Result<std::unique_ptr<io::StreamHandle>> result) {
                      if (!result) {
                          throw result.error();
                      }
                      return std::move(result.value());
                  });
    return io::AnySender<std::unique_ptr<io::StreamHandle>>{std::move(sender)};
}

void GunClient::close() noexcept {
    std::lock_guard lock(mutex_);
    closed_ = true;
    for (const auto &entry : transports_) {
        if (entry->session) {
            entry->session->stop();
        }
    }
    transports_.clear();
}

} // namespace clash_native::transport::proxy::gun
