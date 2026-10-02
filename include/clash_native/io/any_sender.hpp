#pragma once

// Project-owned type-erased sender for handle operations.
//
// Replaces exec::any_sender for io::AnySender: the stock erasure keeps a
// 24-byte inline buffer, so every production sender (bridge senders 24-88
// bytes, use_sender chains 40-48 bytes, tunnel chains ~56 bytes) plus its
// operation state (concrete ops up to 232 bytes) spills to the heap: two
// allocations per relay op on top of the bridge's own Shared block. This
// erasure sizes its buffers from measured shapes (sender SBO 128, op SBO
// 320) so the whole relay path stays inline; oversized or
// not-nothrow-movable senders fall back to the heap with identical
// semantics.
//
// Supported surface (deliberately small):
// - AnySender<T>: move-only, constructible from any sender completing
//   set_value(T)/set_error(exception_ptr)/set_stopped, connect(&&) with any
//   receiver of that contract.
// - Receivers must present inplace_stop_token or never_stop_token (tasks,
//   sync_wait, and every test receiver do). Anything else is a compile
//   error: normalizing an exotic token would need the heap adaptation the
//   stock erasure does, which is exactly the cost being removed.
// - No scheduler/domain queries cross the erasure: no sender in this
//   library queries them from its receiver's environment, and task
//   coroutines read affinity from their own promise context. Completion
//   behavior stays unknown, exactly like the stock erasure, so co_await
//   lowering is unchanged.
//
// The receiver is never type-erased: the operation state is templated on
// the concrete receiver (like exec's _any_opstate), so its environment --
// stop token included -- reaches the inner sender through a thin thunk.
// Only the sender and its operation state are erased, behind two vtables.

#include <stdexec/execution.hpp>

#include <cstddef>
#include <exception>
#include <new>
#include <type_traits>
#include <utility>

namespace clash_native::io::detail {

// Inline capacity, from Linux probe sizes (see implementation log):
// largest production sender 88 bytes (datagram bridge), largest concrete
// op 232 bytes (use_sender read chain). Both get headroom: the sender
// buffer also holds the vtable pointer, the op buffer the thunk receiver.
inline constexpr std::size_t kAnySenderSboSize = 128;
inline constexpr std::size_t kAnyOpSboSize = 256;

enum class AnyTokenKind : unsigned char { kInplace, kNever };

// Erased receiver operations, built once per concrete receiver at the
// connect site. Set/error/stopped forward into the concrete receiver; the
// token crossing depends on the kind (see AnyInplaceThunk/AnyNeverThunk),
// so only the matching thunk's ops are ever instantiated for a receiver.
template <typename T> struct AnyRecvOps {
    void (*set_value)(void *, T);
    void (*set_error)(void *, std::exception_ptr);
    void (*set_stopped)(void *);
    stdexec::inplace_stop_token (*inplace_token)(void *);
};

template <typename T, typename R> const AnyRecvOps<T> *any_recv_ops_inplace() {
    static constexpr AnyRecvOps<T> kOps{
        [](void *obj, T value) {
            stdexec::set_value(std::move(*static_cast<R *>(obj)), std::move(value));
        },
        [](void *obj, std::exception_ptr error) {
            stdexec::set_error(std::move(*static_cast<R *>(obj)), std::move(error));
        },
        [](void *obj) { stdexec::set_stopped(std::move(*static_cast<R *>(obj))); },
        [](void *obj) -> stdexec::inplace_stop_token {
            return stdexec::get_stop_token(stdexec::get_env(*static_cast<const R *>(obj)));
        },
    };
    return &kOps;
}

template <typename T, typename R> const AnyRecvOps<T> *any_recv_ops_never() {
    static constexpr AnyRecvOps<T> kOps{
        [](void *obj, T value) {
            stdexec::set_value(std::move(*static_cast<R *>(obj)), std::move(value));
        },
        [](void *obj, std::exception_ptr error) {
            stdexec::set_error(std::move(*static_cast<R *>(obj)), std::move(error));
        },
        [](void *obj) { stdexec::set_stopped(std::move(*static_cast<R *>(obj))); },
        [](void *) -> stdexec::inplace_stop_token { return stdexec::inplace_stop_token{}; },
    };
    return &kOps;
}
// NOTE: completions are deliberately unqualified: the erased sender may
// invoke the wrapped receiver as an lvalue while plain senders invoke it
// as an rvalue; only unqualified overloads accept both.
template <typename T> struct AnyInplaceThunk {
    using receiver_concept = stdexec::receiver_tag;
    void *obj = nullptr;
    const AnyRecvOps<T> *ops = nullptr;

    struct Env {
        void *obj = nullptr;
        const AnyRecvOps<T> *ops = nullptr;
        auto query(stdexec::get_stop_token_t) const noexcept { return ops->inplace_token(obj); }
    };

    auto get_env() const noexcept { return Env{obj, ops}; }
    void set_value(T value) noexcept { ops->set_value(obj, std::move(value)); }
    void set_error(std::exception_ptr error) noexcept { ops->set_error(obj, std::move(error)); }
    void set_stopped() noexcept { ops->set_stopped(obj); }
};

// Thunk receiver for tokenless (never_stop_token) receivers. The inner
// sender's stop wiring becomes a no-op, which is unobservable: with no
// token nobody can request stop.
template <typename T> struct AnyNeverThunk {
    using receiver_concept = stdexec::receiver_tag;
    void *obj = nullptr;
    const AnyRecvOps<T> *ops = nullptr;

    struct Env {
        auto query(stdexec::get_stop_token_t) const noexcept { return stdexec::never_stop_token{}; }
    };

    auto get_env() const noexcept { return Env{}; }
    void set_value(T value) noexcept { ops->set_value(obj, std::move(value)); }
    void set_error(std::exception_ptr error) noexcept { ops->set_error(obj, std::move(error)); }
    void set_stopped() noexcept { ops->set_stopped(obj); }
};

struct AnyOpOps {
    void (*start)(void *);
    void (*destroy)(void *) noexcept;
};

template <typename Op> const AnyOpOps *any_op_ops_for() {
    using Bare = std::decay_t<Op>;
    static constexpr AnyOpOps kOps{
        [](void *op) { stdexec::start(*static_cast<Bare *>(op)); },
        [](void *op) noexcept { static_cast<Bare *>(op)->~Bare(); },
    };
    return &kOps;
}

template <typename T> struct AnySenderOps {
    void (*destroy)(void *self) noexcept;
    void (*move_to)(void *src, void *dst) noexcept;
    // Connects the held sender to a thunk receiver, building the opstate
    // inline when it is small and nothrow-movable, on the heap otherwise.
    const AnyOpOps *(*connect_op)(void *sender, void *op_buffer, void *receiver,
                                  const AnyRecvOps<T> *recv_ops, AnyTokenKind kind,
                                  void *&heap_out);
};

template <typename T, typename S, typename Thunk>
const AnyOpOps *connect_op_impl(S sender, void *op_buffer, void *receiver,
                                const AnyRecvOps<T> *recv_ops, Thunk thunk, void *&heap_out) {
    thunk.obj = receiver;
    thunk.ops = recv_ops;
    using Op = stdexec::connect_result_t<S, Thunk>;
    // Small ops connect directly into the op buffer and never relocate
    // (the AnySenderOp is itself immovable), so immovability is fine.
    // Only oversized ops take the heap, where the pointer stays put.
    if constexpr (sizeof(Op) <= kAnyOpSboSize) {
        new (op_buffer) Op(stdexec::connect(std::move(sender), std::move(thunk)));
        heap_out = nullptr;
    } else {
        heap_out = new Op(stdexec::connect(std::move(sender), std::move(thunk)));
    }
    return any_op_ops_for<Op>();
}

template <typename T, typename S> const AnySenderOps<T> *any_sender_ops_for() {
    static constexpr AnySenderOps<T> kOps{
        [](void *self) noexcept { static_cast<S *>(self)->~S(); },
        [](void *src, void *dst) noexcept {
            new (dst) S(std::move(*static_cast<S *>(src)));
            static_cast<S *>(src)->~S();
        },
        [](void *sender, void *op_buffer, void *receiver, const AnyRecvOps<T> *recv_ops,
           AnyTokenKind kind, void *&heap_out) -> const AnyOpOps * {
            S owned = std::move(*static_cast<S *>(sender));
            if (kind == AnyTokenKind::kInplace) {
                using Op = stdexec::connect_result_t<S, AnyInplaceThunk<T>>;
                return connect_op_impl(std::move(owned), op_buffer, receiver, recv_ops,
                                       AnyInplaceThunk<T>{}, heap_out);
            }
            using Op = stdexec::connect_result_t<S, AnyNeverThunk<T>>;
            return connect_op_impl(std::move(owned), op_buffer, receiver, recv_ops,
                                   AnyNeverThunk<T>{}, heap_out);
        },
    };
    return &kOps;
}

} // namespace clash_native::io::detail

namespace clash_native::io {

template <typename T> class AnySender;

// Operation state: connects the model sender through a thunk borrowing
// receiver_. Immovable by design: concrete opstates are frequently
// immovable (asio chains pin handler storage by address), so the state is
// connected directly into its final buffer and never relocated -- neither
// the AnySenderOp nor the inner op ever moves. Heap fallback is only for
// oversized ops; the pointer then stays put instead.
template <typename T, typename R> class AnySenderOp {
  public:
    using operation_state_concept = stdexec::operation_state_tag;

    AnySenderOp(const AnySenderOp &) = delete;
    AnySenderOp &operator=(const AnySenderOp &) = delete;
    AnySenderOp(AnySenderOp &&) = delete;
    AnySenderOp &operator=(AnySenderOp &&) = delete;

    ~AnySenderOp() {
        if (op_ops_ == nullptr) {
            return;
        }
        if (heap_ != nullptr) {
            op_ops_->destroy(heap_);
            ::operator delete(heap_);
        } else {
            op_ops_->destroy(op_buffer());
        }
    }

    void start() & noexcept { op_ops_->start(heap_ != nullptr ? heap_ : op_buffer()); }

  private:
    friend class AnySender<T>;

    // Built only by AnySender::connect: connects the model sender through
    // a thunk borrowing receiver_.
    AnySenderOp(const detail::AnySenderOps<T> *sender_ops, void *sender_ptr, R receiver,
                const detail::AnyRecvOps<T> *recv_ops, detail::AnyTokenKind kind)
        : receiver_(std::move(receiver)), op_ops_(nullptr), heap_(nullptr) {
        op_ops_ =
            sender_ops->connect_op(sender_ptr, op_buffer(), &receiver_, recv_ops, kind, heap_);
    }

    void *op_buffer() noexcept { return static_cast<void *>(op_storage_); }

    R receiver_;
    const detail::AnyOpOps *op_ops_ = nullptr;
    void *heap_ = nullptr;
    alignas(void *) unsigned char op_storage_[detail::kAnyOpSboSize];
};

template <typename T> class AnySender {
  public:
    using sender_concept = stdexec::sender_tag;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(T),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;

    AnySender() = delete;
    AnySender(const AnySender &) = delete;
    AnySender &operator=(const AnySender &) = delete;

    template <typename S>
        requires(!std::same_as<std::decay_t<S>, AnySender> && stdexec::sender<std::decay_t<S>>)
    AnySender(S &&sender) {
        using Bare = std::decay_t<S>;
        sender_ops_ = detail::any_sender_ops_for<T, Bare>();
        if constexpr (sizeof(Bare) <= detail::kAnySenderSboSize &&
                      alignof(Bare) <= alignof(void *) &&
                      std::is_nothrow_move_constructible_v<Bare>) {
            new (sender_buffer()) Bare(std::forward<S>(sender));
            heap_ = nullptr;
        } else {
            heap_ = new Bare(std::forward<S>(sender));
        }
    }

    AnySender(AnySender &&other) noexcept : sender_ops_(other.sender_ops_), heap_(other.heap_) {
        if (sender_ops_ != nullptr && heap_ == nullptr) {
            sender_ops_->move_to(other.sender_buffer(), sender_buffer());
        } else {
            other.heap_ = nullptr;
        }
        other.sender_ops_ = nullptr;
    }

    AnySender &operator=(AnySender &&other) noexcept {
        if (this != &other) {
            reset();
            sender_ops_ = other.sender_ops_;
            heap_ = other.heap_;
            if (sender_ops_ != nullptr && heap_ == nullptr) {
                sender_ops_->move_to(other.sender_buffer(), sender_buffer());
            } else {
                other.heap_ = nullptr;
            }
            other.sender_ops_ = nullptr;
        }
        return *this;
    }

    void reset() noexcept {
        if (sender_ops_ == nullptr) {
            return;
        }
        if (heap_ != nullptr) {
            sender_ops_->destroy(heap_);
            ::operator delete(heap_);
        } else {
            sender_ops_->destroy(sender_buffer());
        }
        sender_ops_ = nullptr;
        heap_ = nullptr;
    }

    ~AnySender() { reset(); }

    auto get_env() const noexcept { return stdexec::env<>{}; }

    template <stdexec::receiver_of<completion_signatures> R>
    AnySenderOp<T, std::decay_t<R>> connect(R &&receiver) && {
        using Tok = stdexec::stop_token_of_t<stdexec::env_of_t<std::decay_t<R>>>;
        if constexpr (std::is_convertible_v<Tok, stdexec::inplace_stop_token>) {
            return AnySenderOp<T, std::decay_t<R>>(
                sender_ops_, sender_ptr(), std::forward<R>(receiver),
                detail::any_recv_ops_inplace<T, std::decay_t<R>>(), detail::AnyTokenKind::kInplace);
        } else if constexpr (std::same_as<Tok, stdexec::never_stop_token>) {
            return AnySenderOp<T, std::decay_t<R>>(
                sender_ops_, sender_ptr(), std::forward<R>(receiver),
                detail::any_recv_ops_never<T, std::decay_t<R>>(), detail::AnyTokenKind::kNever);
        } else {
            static_assert(std::same_as<Tok, void>,
                          "AnySender receivers must present inplace_stop_token or "
                          "never_stop_token; normalizing an exotic token needs the heap "
                          "adaptation this erasure removes");
        }
    }

  private:
    void *sender_buffer() noexcept { return static_cast<void *>(sender_storage_); }
    void *sender_ptr() noexcept { return heap_ != nullptr ? heap_ : sender_buffer(); }

    const detail::AnySenderOps<T> *sender_ops_ = nullptr;
    void *heap_ = nullptr;
    alignas(void *) unsigned char sender_storage_[detail::kAnySenderSboSize];
};

} // namespace clash_native::io
