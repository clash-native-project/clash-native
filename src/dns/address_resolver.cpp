#include <clash_native/dns/address_resolver.hpp>

#include <clash_native/dns/dns_codec.hpp>

#include <exec/task.hpp>

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

    void start() { scope_.spawn(run(shared_from_this())); }

    void cancel() {
        if (completed_) {
            return;
        }
        // Request stop so the in-flight query_sender await aborts; the
        // task's late finish drops on the completed_ guard.
        cancel_requested_.store(true, std::memory_order_release);
        try {
            scope_.request_stop();
        } catch (...) {
        }
        const auto query_id = query_id_.load(std::memory_order_acquire);
        if (query_id != 0) {
            owner_.query_service_.cancel(query_id);
        }
    }

    Handler take_handler() { return std::move(handler_); }

    CompletionScheduler take_scheduler() { return std::move(completion_scheduler_); }

    RequestId request_id() const noexcept { return request_id_; }

  private:
    // CNAME chain as one task: co_await each query_sender in turn and
    // follow CNAME targets inline. The task always ends with a value and
    // finish() drops late terminals on the completed_ guard.
    static exec::task<void> run(std::shared_ptr<Operation> self) {
        while (!self->completed_ && !self->cancel_requested_.load(std::memory_order_acquire)) {
            DnsPacket packet = make_query_packet(self->current_question_);
            core::Result<DnsPacket> result = core::fail(cancelled_error());
            try {
                // Stop from scope maps to cancelled inline: request_stop
                // unwinds the await as stopped, and the task must deliver
                // the terminal itself since nobody else will.
                auto sender = self->owner_.query_service_.query_sender(std::move(packet)) |
                              stdexec::stopped_as_optional();
                auto outcome = co_await std::move(sender);
                if (!outcome) {
                    result = core::fail(cancelled_error());
                } else {
                    result = std::move(*outcome);
                }
            } catch (const core::Error &failure) {
                result = core::fail(failure);
            } catch (...) {
                try {
                    std::rethrow_exception(std::current_exception());
                } catch (const core::Error &failure) {
                    result = core::fail(failure);
                } catch (...) {
                    result = core::fail(cancelled_error());
                }
            }
            self->query_id_.store(0, std::memory_order_release);
            if (self->completed_) {
                co_return;
            }
            if (self->cancel_requested_.load(std::memory_order_acquire)) {
                self->finish(core::fail(cancelled_error()));
                co_return;
            }
            if (!result) {
                self->finish(core::fail(result.error()));
                co_return;
            }
            auto answer = DnsMessageCodec::to_address_answer(result.value());
            if (!answer) {
                self->finish(core::fail(answer.error()));
                co_return;
            }
            if (!answer.value().addresses.empty()) {
                self->complete_answer(std::move(answer.value()));
                co_return;
            }
            if (answer.value().response_code != 0 ||
                self->current_question_.type != DnsRecordType::a &&
                    self->current_question_.type != DnsRecordType::aaaa) {
                self->complete_answer(std::move(answer.value()));
                co_return;
            }
            const auto current_name = normalize_name(self->current_question_.name);
            const auto cname = std::find_if(
                result.value().answers.begin(), result.value().answers.end(),
                [&](const DnsResourceRecord &record) {
                    return record.class_code == self->current_question_.class_code &&
                           record.type == static_cast<std::uint16_t>(DnsRecordType::cname) &&
                           normalize_name(record.name) == current_name && record.target_name;
                });
            if (cname == result.value().answers.end() || self->visited_names_.size() >= 8) {
                self->complete_answer(std::move(answer.value()));
                co_return;
            }
            const auto target_name = normalize_name(*cname->target_name);
            if (target_name.empty() ||
                std::find(self->visited_names_.begin(), self->visited_names_.end(), target_name) !=
                    self->visited_names_.end()) {
                self->complete_answer(std::move(answer.value()));
                co_return;
            }
            self->visited_names_.push_back(target_name);
            self->cname_ttl_ = std::min(self->cname_ttl_, cname->ttl_seconds);
            self->current_question_.name = target_name;
        }
        if (!self->completed_) {
            self->finish(core::fail(cancelled_error()));
        }
        co_return;
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
    // Owns this resolve's CNAME-chain task; cancel request_stops it so
    // the in-flight await aborts instead of leaking until upstream answers.
    exec::async_scope scope_;
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
    CompletionScheduler scheduler;
    {
        std::lock_guard lock(operations_mutex_);
        const auto found = operations_.find(operation->request_id());
        if (found == operations_.end() || found->second != operation) {
            return;
        }
        handler = operation->take_handler();
        scheduler = operation->take_scheduler();
        operations_.erase(found);
    }
    if (!handler) {
        return;
    }
    auto &runtime = query_service_.runtime();
    if (scheduler) {
        scheduler->post([handler = std::move(handler), result = std::move(result)]() mutable {
            handler(std::move(result));
        });
        return;
    }
    runtime.scheduler().post([handler = std::move(handler), result = std::move(result)]() mutable {
        handler(std::move(result));
    });
}

} // namespace clash_native::dns
