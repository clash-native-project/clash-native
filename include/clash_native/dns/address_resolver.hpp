#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_query_service.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace clash_native::dns {

class AddressResolver final {
  public:
    using RequestId = DnsQueryService::RequestId;
    using Handler = std::function<void(core::Result<DnsAnswer>)>;
    using CompletionScheduler = DnsQueryService::CompletionScheduler;

    explicit AddressResolver(DnsQueryService &query_service);
    ~AddressResolver();

    AddressResolver(const AddressResolver &) = delete;
    AddressResolver &operator=(const AddressResolver &) = delete;

    RequestId resolve(DnsQuestion question, Handler handler,
                      CompletionScheduler completion_scheduler = std::nullopt);
    void cancel(RequestId request_id) noexcept;

  private:
    class Operation;

    void complete(const std::shared_ptr<Operation> &operation, core::Result<DnsAnswer> result);

    DnsQueryService &query_service_;
    std::shared_ptr<std::atomic_bool> callback_gate_;
    std::unordered_map<RequestId, std::shared_ptr<Operation>> operations_;
    std::mutex operations_mutex_;
    std::atomic<RequestId> next_request_id_{1};
};

} // namespace clash_native::dns
