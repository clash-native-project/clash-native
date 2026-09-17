#include <clash_native/dns/bootstrap_resolver.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace clash_native::dns {

namespace {

core::Error resolution_error(std::string hostname, const boost::system::error_code &error) {
    return {core::ErrorCode::resolution, "bootstrap resolution failed for " + std::move(hostname),
            std::error_code(error.value(), std::system_category())};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "bootstrap resolution timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "bootstrap resolution was cancelled"};
}

class SystemBootstrapResolver final : public BootstrapResolver,
                                      public std::enable_shared_from_this<SystemBootstrapResolver> {
  public:
    explicit SystemBootstrapResolver(runtime::AsioRuntime &runtime)
        : runtime_(runtime), resolver_(runtime.context()) {}

    RequestId resolve(std::string hostname, std::chrono::steady_clock::time_point deadline,
                      Handler handler) override {
        const auto request_id = next_request_id_++;
        if (stopped_) {
            boost::asio::post(runtime_.context(), [handler = std::move(handler)]() mutable {
                if (handler) {
                    handler(core::fail(cancelled_error()));
                }
            });
            return request_id;
        }
        auto request = std::make_shared<Request>(runtime_.context());
        request->hostname = std::move(hostname);
        request->handler = std::move(handler);
        request->timer.expires_at(deadline);
        requests_.emplace(request_id, request);

        const auto self = shared_from_this();
        request->timer.async_wait([self, request_id](const boost::system::error_code &error) {
            if (!error) {
                self->complete(request_id, core::fail(timeout_error()));
            }
        });
        resolver_.async_resolve(
            request->hostname, "0",
            [self, request_id](const boost::system::error_code &error,
                               const boost::asio::ip::tcp::resolver::results_type &results) {
                const auto found = self->requests_.find(request_id);
                if (found == self->requests_.end()) {
                    return;
                }
                if (error) {
                    self->complete(request_id,
                                   core::fail(resolution_error(found->second->hostname, error)));
                    return;
                }

                std::vector<boost::asio::ip::address> addresses;
                for (const auto &entry : results) {
                    const auto address = entry.endpoint().address();
                    if (std::find(addresses.begin(), addresses.end(), address) == addresses.end()) {
                        addresses.push_back(address);
                    }
                }
                if (addresses.empty()) {
                    self->complete(request_id,
                                   core::fail({core::ErrorCode::resolution,
                                               "bootstrap resolution returned no addresses"}));
                    return;
                }
                self->complete(request_id, std::move(addresses));
            });
        return request_id;
    }

    void cancel(RequestId request_id) noexcept override {
        complete(request_id, core::fail(cancelled_error()));
    }

    void stop() noexcept override {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        resolver_.cancel();
        std::vector<RequestId> request_ids;
        request_ids.reserve(requests_.size());
        for (const auto &[request_id, request] : requests_) {
            request_ids.push_back(request_id);
        }
        for (const auto request_id : request_ids) {
            complete(request_id, core::fail(cancelled_error()));
        }
    }

  private:
    struct Request {
        explicit Request(boost::asio::io_context &context) : timer(context) {}

        std::string hostname;
        Handler handler;
        boost::asio::steady_timer timer;
    };

    void complete(RequestId request_id,
                  core::Result<std::vector<boost::asio::ip::address>> result) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end()) {
            return;
        }
        auto request = std::move(found->second);
        requests_.erase(found);
        request->timer.cancel();
        if (request->handler) {
            auto handler = std::move(request->handler);
            boost::asio::post(runtime_.context(),
                              [handler = std::move(handler), result = std::move(result)]() mutable {
                                  handler(std::move(result));
                              });
        }
    }

    runtime::AsioRuntime &runtime_;
    boost::asio::ip::tcp::resolver resolver_;
    std::unordered_map<RequestId, std::shared_ptr<Request>> requests_;
    RequestId next_request_id_ = 1;
    bool stopped_ = false;
};

} // namespace

std::shared_ptr<BootstrapResolver> make_system_bootstrap_resolver(runtime::AsioRuntime &runtime) {
    return std::make_shared<SystemBootstrapResolver>(runtime);
}

} // namespace clash_native::dns
