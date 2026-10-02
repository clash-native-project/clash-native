#pragma once

// Move-only type-erased callable for the sender bridges.
//
// std::move_only_function is a C++23 library feature; this project builds as
// C++20, so this header vendors a minimal fallback with the same call shape.
// When the toolchain provides __cpp_lib_move_only_function, this aliases the
// standard type instead.
//
// Supported surface (deliberately small):
// - move_only_function<R(Args...)>: default/nullptr construction, move-only,
//   bool conversion, reset(), swap(), and invocation.
// - Construction from any decayed callable invocable as R(Args...), including
//   move-only callables (e.g. lambdas capturing unique_ptr/shared state).
// - Empty invocation throws std::bad_function_call, matching std::function.
//
// Non-goals: allocator support, const-callable propagation, noexcept
// signatures, comparison operators. The call operator is intentionally
// non-const: aborters commonly mutate their captured state.

#include <cstddef>
#include <functional>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>
#include <version>

namespace clash_native::async {

#if defined(__cpp_lib_move_only_function)
template <typename Signature> using move_only_function = std::move_only_function<Signature>;
#else

template <typename Signature> class move_only_function;

// Vendored fallback with small-buffer storage: hot-path aborters capture
// one shared_ptr (16 bytes) or a shared_ptr plus a small id (24 bytes),
// so a 32-byte inline buffer keeps them heap-free. Larger or over-aligned
// callables fall back to the heap. Moves relocate: an SBO-held target moves
// into the destination buffer, a heap-held target transfers the pointer.
inline constexpr std::size_t kMoveOnlyFunctionSboSize = 32;

template <typename R, typename... Args> class move_only_function<R(Args...)> {
  public:
    using result_type = R;

    move_only_function() noexcept = default;
    move_only_function(std::nullptr_t) noexcept : move_only_function() {}

    move_only_function(move_only_function &&other) noexcept { move_from(std::move(other)); }

    move_only_function &operator=(move_only_function &&other) noexcept {
        if (this != &other) {
            reset();
            move_from(std::move(other));
        }
        return *this;
    }

    move_only_function(const move_only_function &) = delete;
    move_only_function &operator=(const move_only_function &) = delete;

    move_only_function &operator=(std::nullptr_t) noexcept {
        reset();
        return *this;
    }

    template <typename F>
        requires(!std::same_as<std::decay_t<F>, move_only_function> &&
                 std::is_invocable_r_v<R, F &, Args...>)
    move_only_function(F &&target) {
        emplace<std::decay_t<F>>(std::forward<F>(target));
    }

    template <typename F>
        requires(!std::same_as<std::decay_t<F>, move_only_function> &&
                 std::is_invocable_r_v<R, F &, Args...>)
    move_only_function &operator=(F &&target) {
        using Decayed = std::decay_t<F>;
        reset();
        emplace<Decayed>(std::forward<F>(target));
        return *this;
    }

    ~move_only_function() { reset(); }

    explicit operator bool() const noexcept { return ops_ != nullptr; }

    R operator()(Args... args) {
        if (ops_ == nullptr) {
            throw std::bad_function_call{};
        }
        return ops_->invoke(ptr(), std::forward<Args>(args)...);
    }

    void reset() noexcept {
        if (ops_ == nullptr) {
            return;
        }
        ops_->destroy(ptr());
        if (!sbo()) {
            operator delete(storage_.heap);
        }
        ops_ = nullptr;
    }

    void swap(move_only_function &other) noexcept {
        if (this == &other) {
            return;
        }
        move_only_function tmp(std::move(*this));
        move_from(std::move(other));
        other.move_from(std::move(tmp));
    }

    friend void swap(move_only_function &left, move_only_function &right) noexcept {
        left.swap(right);
    }

  private:
    struct Ops {
        R (*invoke)(void *, Args &&...);
        void (*move_to)(void *src, void *dst);
        void (*destroy)(void *ptr) noexcept;
    };

    template <typename F> static const Ops *ops_for() noexcept {
        static const Ops ops{
            [](void *ptr, Args &&...args) -> R {
                F &target = *static_cast<F *>(ptr);
                if constexpr (std::is_void_v<R>) {
                    std::invoke(target, std::forward<Args>(args)...);
                } else {
                    return std::invoke(target, std::forward<Args>(args)...);
                }
            },
            [](void *src, void *dst) { new (dst) F(std::move(*static_cast<F *>(src))); },
            [](void *ptr) noexcept { static_cast<F *>(ptr)->~F(); },
        };
        return &ops;
    }

    template <typename F, typename U> void emplace(U &&target) {
        if constexpr (sizeof(F) <= kMoveOnlyFunctionSboSize && alignof(F) <= alignof(void *)) {
            new (storage_.sbo) F(std::forward<U>(target));
            ops_ = ops_for<F>();
            sbo_ = true;
        } else {
            void *heap = operator new(sizeof(F));
            try {
                new (heap) F(std::forward<U>(target));
            } catch (...) {
                operator delete(heap);
                throw;
            }
            storage_.heap = heap;
            ops_ = ops_for<F>();
            sbo_ = false;
        }
    }

    void *ptr() noexcept { return sbo() ? static_cast<void *>(storage_.sbo) : storage_.heap; }

    bool sbo() const noexcept { return sbo_; }

    void move_from(move_only_function &&other) noexcept {
        if (other.ops_ == nullptr) {
            return;
        }
        ops_ = other.ops_;
        sbo_ = other.sbo_;
        if (other.sbo()) {
            ops_->move_to(other.ptr(), ptr());
            ops_->destroy(other.ptr());
        } else {
            storage_.heap = other.storage_.heap;
            other.storage_.heap = nullptr;
        }
        other.ops_ = nullptr;
    }

    union Storage {
        alignas(void *) unsigned char sbo[kMoveOnlyFunctionSboSize];
        void *heap;
    };

    Storage storage_{};
    const Ops *ops_ = nullptr;
    bool sbo_ = false;
};

#endif

// Aborter for the callback_sender bridge: aborts the underlying work after
// stop or destroy. Must be idempotent, callable from any thread, never block,
// and tolerate being invoked after the terminal already fired.
using CallbackAbortFn = move_only_function<void()>;

} // namespace clash_native::async
