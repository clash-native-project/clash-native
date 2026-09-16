#include <clash_native/dns/address_resolver.hpp>

#include <clash_native/dns/dns_codec.hpp>

#include <algorithm>
#include <limits>
#include <utility>

namespace clash_native::dns {

namespace {

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "DNS address resolution was cancelled"};
}

DnsPacket make_query_packet(const DnsQuestion &question) {
    DnsPacket packet;
    packet.id = 0;
    packet.flags = 0x0100;
    packet.questions.push_back(question);
    const auto encoded = DnsMessageCodec::encode_query_packet(question, packet.id);
    if (encoded) {
        packet.wire = encoded.value();
    }
    return packet;
}

} // namespace

class AddressResolver::Operation final
    : public std::enable_shared_from_this<AddressResolver::Operation> {
  public:
    Operation(AddressResolver &owner, RequestId request_id, DnsQuestion question, Handler handler,
              CompletionScheduler completion_scheduler)
        : owner_(owner), request_id_(request_id), original_question_(question),
          current_question_(std::move(question)), handler_(std::move(handler)),
          completion_scheduler_(std::move(completion_scheduler)) {
        visited_names_.push_back(normalize_name(original_question_.name));
    }

    void start() { query_current(); }

    void cancel() {
        if (completed_) {
            return;
        }
        cancel_requested_.store(true, std::memory_order_release);
        const auto query_id = query_id_.load(std::memory_order_acquire);
        if (query_id != 0) {
            owner_.query_service_.cancel(query_id);
        }
    }

    Handler take_handler() { return std::move(handler_); }

    RequestId request_id() const noexcept { return request_id_; }

  private:
    void query_current() {
        if (completed_) {
            return;
        }
        const auto gate = owner_.callback_gate_;
        auto self = shared_from_this();
        const auto query_id = owner_.query_service_.query(
            make_query_packet(current_question_),
            [self, gate](core::Result<DnsPacket> result) mutable {
                if (gate->load(std::memory_order_acquire)) {
                    self->query_finished(std::move(result));
                }
            },
            completion_scheduler_);
        query_id_.store(query_id, std::memory_order_release);
        if (cancel_requested_.load(std::memory_order_acquire)) {
            owner_.query_service_.cancel(query_id);
        }
    }

    void query_finished(core::Result<DnsPacket> result) {
        query_id_.store(0, std::memory_order_release);
        if (completed_) {
            return;
        }
        if (cancel_requested_.load(std::memory_order_acquire)) {
            finish(core::fail(cancelled_error()));
            return;
        }
        if (!result) {
            finish(core::fail(result.error()));
            return;
        }

        auto answer = DnsMessageCodec::to_address_answer(result.value());
        if (!answer) {
            finish(core::fail(answer.error()));
            return;
        }
        if (!answer.value().addresses.empty()) {
            complete_answer(std::move(answer.value()));
            return;
        }
        if (answer.value().response_code != 0 ||
            current_question_.type != DnsRecordType::a &&
                current_question_.type != DnsRecordType::aaaa) {
            complete_answer(std::move(answer.value()));
            return;
        }

        const auto current_name = normalize_name(current_question_.name);
        const auto cname = std::find_if(
            result.value().answers.begin(), result.value().answers.end(),
            [&](const DnsResourceRecord &record) {
                return record.class_code == current_question_.class_code &&
                       record.type == static_cast<std::uint16_t>(DnsRecordType::cname) &&
                       normalize_name(record.name) == current_name && record.target_name;
            });
        if (cname == result.value().answers.end() || visited_names_.size() >= 8) {
            complete_answer(std::move(answer.value()));
            return;
        }

        const auto target_name = normalize_name(*cname->target_name);
        if (target_name.empty() || std::find(visited_names_.begin(), visited_names_.end(),
                                             target_name) != visited_names_.end()) {
            complete_answer(std::move(answer.value()));
            return;
        }
        visited_names_.push_back(target_name);
        cname_ttl_ = std::min(cname_ttl_, cname->ttl_seconds);
        current_question_.name = target_name;
        query_current();
    }

    void complete_answer(DnsAnswer answer) {
        answer.question = original_question_;
        if (!answer.addresses.empty() && cname_ttl_ != std::numeric_limits<std::uint32_t>::max()) {
            answer.ttl_seconds = std::min(answer.ttl_seconds, cname_ttl_);
        }
        finish(std::move(answer));
    }

    void finish(core::Result<DnsAnswer> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        owner_.complete(shared_from_this(), std::move(result));
    }

    AddressResolver &owner_;
    RequestId request_id_;
    DnsQuestion original_question_;
    DnsQuestion current_question_;
    Handler handler_;
    CompletionScheduler completion_scheduler_;
    std::vector<std::string> visited_names_;
    std::atomic<RequestId> query_id_{0};
    std::atomic_bool cancel_requested_{false};
    std::uint32_t cname_ttl_ = std::numeric_limits<std::uint32_t>::max();
    bool completed_ = false;
};

AddressResolver::AddressResolver(DnsQueryService &query_service)
    : query_service_(query_service), callback_gate_(std::make_shared<std::atomic_bool>(true)) {}

AddressResolver::~AddressResolver() { callback_gate_->store(false, std::memory_order_release); }

AddressResolver::RequestId AddressResolver::resolve(DnsQuestion question, Handler handler,
                                                    CompletionScheduler completion_scheduler) {
    const auto request_id = next_request_id_.fetch_add(1, std::memory_order_relaxed);
    auto operation =
        std::make_shared<Operation>(*this, request_id, std::move(question), std::move(handler),
                                    std::move(completion_scheduler));
    {
        std::lock_guard lock(operations_mutex_);
        operations_.emplace(request_id, operation);
    }
    operation->start();
    return request_id;
}

void AddressResolver::cancel(RequestId request_id) noexcept {
    std::shared_ptr<Operation> operation;
    {
        std::lock_guard lock(operations_mutex_);
        const auto found = operations_.find(request_id);
        if (found == operations_.end()) {
            return;
        }
        operation = found->second;
    }
    operation->cancel();
}

void AddressResolver::complete(const std::shared_ptr<Operation> &operation,
                               core::Result<DnsAnswer> result) {
    Handler handler;
    {
        std::lock_guard lock(operations_mutex_);
        const auto found = operations_.find(operation->request_id());
        if (found == operations_.end() || found->second != operation) {
            return;
        }
        handler = operation->take_handler();
        operations_.erase(found);
    }
    if (handler) {
        handler(std::move(result));
    }
}

} // namespace clash_native::dns
