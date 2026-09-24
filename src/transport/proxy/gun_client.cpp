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

exec::task<void> GunClient::run_open(std::shared_ptr<GunClient> client,
                                     std::shared_ptr<TransportEntry> entry, SessionMaker maker,
                                     gun::GunStreamOptions options,
                                     std::shared_ptr<DialGuard> guard, OpenHandler done) {
    OpenResult result = core::fail({core::ErrorCode::transport_io, "gun dial failed"});
    try {
        if (!entry->session) {
            auto session = co_await async::bridge_sender<
                core::Result<std::shared_ptr<io::ExchangeSession>>>(
                [maker](
                    async::BridgeSender<core::Result<std::shared_ptr<io::ExchangeSession>>>::Handler
                        open) mutable {
                    // The bridge starter must be copyable: drive the
                    // maker sender straight into the terminal.
                    struct MakerReceiver {
                        using receiver_concept = stdexec::receiver_tag;
                        async::BridgeSender<
                            core::Result<std::shared_ptr<io::ExchangeSession>>>::Handler open;
                        void set_value(std::shared_ptr<io::ExchangeSession> session) && noexcept {
                            auto terminal = std::move(open);
                            terminal(core::Result<std::shared_ptr<io::ExchangeSession>>{
                                std::move(session)});
                        }
                        void set_error(std::exception_ptr error) && noexcept {
                            auto terminal = std::move(open);
                            try {
                                std::rethrow_exception(std::move(error));
                            } catch (const core::Error &failure) {
                                terminal(core::fail(failure));
                                return;
                            } catch (...) {
                            }
                            terminal(core::fail(
                                {core::ErrorCode::transport_io, "gun session open failed"}));
                        }
                        void set_stopped() && noexcept {
                            auto terminal = std::move(open);
                            terminal(core::fail(
                                {core::ErrorCode::cancelled, "gun session open cancelled"}));
                        }
                    };
                    // NOTE: name the sender first; argument order is unspecified.
                    auto sender = maker();
                    async::start_with_receiver(std::move(sender), MakerReceiver{std::move(open)});
                    using AbortFn = async::BridgeSender<
                        core::Result<std::shared_ptr<io::ExchangeSession>>>::AbortFn;
                    return AbortFn{[] {}};
                });
            if (!session) {
                result = core::fail(session.error());
                done(std::move(result));
                co_return;
            }
            entry->session = std::move(session.value());
        }
        auto stream =
            co_await async::bridge_sender<OpenResult>([entry, options](OpenHandler open) mutable {
                gun::async_open_gun_stream(
                    entry->session, options,
                    [open](OpenResult opened) mutable { open(std::move(opened)); });
                using AbortFn = async::BridgeSender<OpenResult>::AbortFn;
                return AbortFn{[] {}};
            });
        if (stream) {
            guard->armed = false;
            result = OpenResult{std::unique_ptr<io::StreamHandle>(
                std::make_unique<CountedStreamHandle>(std::move(stream.value()), entry))};
        } else {
            result = core::fail(stream.error());
        }
    } catch (const core::Error &failure) {
        result = core::fail(failure);
    } catch (...) {
    }
    done(std::move(result));
    (void)client;
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
    // NOTE: fill the shared guard in place; a DialGuard{entry} temporary
    // would run its armed destructor and release the reservation early.
    auto guard = std::make_shared<DialGuard>();
    guard->entry = entry;
    auto maker = maker_;
    auto options = options_.stream;
    options.deadline = std::chrono::steady_clock::now() + options_.open_timeout;
    struct Shared {
        exec::async_scope scope;
    };
    auto shared = std::make_shared<Shared>();
    // Linear open chain as a named-function task spawned directly into
    // the shared scope (the run() shape): ensure the Transport session,
    // then the Tun stream, and deliver the in-band result through done
    // exactly once. Failures stay values; stop can only come from a
    // scope stop, which this client never requests.
    auto bridged = async::bridge_sender<core::Result<std::unique_ptr<io::StreamHandle>>>(
        [shared, self, entry, maker = std::move(maker), options = std::move(options),
         guard](async::BridgeSender<core::Result<std::unique_ptr<io::StreamHandle>>>::Handler
                    done) mutable {
            shared->scope.spawn(run_open(self, entry, std::move(maker), std::move(options),
                                         std::move(guard), std::move(done)));
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
