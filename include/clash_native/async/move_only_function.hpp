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

#include <functional>
#include <memory>
#include <type_traits>
#include <utility>
#include <version>

namespace clash_native::async {

#if defined(__cpp_lib_move_only_function)
template <typename Signature> using move_only_function = std::move_only_function<Signature>;
#else

template <typename Signature> class move_only_function;

template <typename R, typename... Args> class move_only_function<R(Args...)> {
  public:
    using result_type = R;

    move_only_function() noexcept = default;
    move_only_function(std::nullptr_t) noexcept : move_only_function() {}

    move_only_function(move_only_function &&) noexcept = default;
    move_only_function &operator=(move_only_function &&) noexcept = default;

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
        using Decayed = std::decay_t<F>;
        ptr_ = std::make_unique<CallableImpl<Decayed>>(std::forward<F>(target));
    }

    template <typename F>
        requires(!std::same_as<std::decay_t<F>, move_only_function> &&
                 std::is_invocable_r_v<R, F &, Args...>)
    move_only_function &operator=(F &&target) {
        using Decayed = std::decay_t<F>;
        ptr_ = std::make_unique<CallableImpl<Decayed>>(std::forward<F>(target));
        return *this;
    }

    ~move_only_function() = default;

    explicit operator bool() const noexcept { return static_cast<bool>(ptr_); }

    R operator()(Args... args) {
        if (!ptr_) {
            throw std::bad_function_call{};
        }
        return ptr_->call(std::forward<Args>(args)...);
    }

    void reset() noexcept { ptr_.reset(); }

    void swap(move_only_function &other) noexcept { ptr_.swap(other.ptr_); }

    friend void swap(move_only_function &left, move_only_function &right) noexcept {
        left.swap(right);
    }

  private:
    struct CallableBase {
        virtual ~CallableBase() = default;
        virtual R call(Args... args) = 0;
    };

    template <typename F> struct CallableImpl final : CallableBase {
        explicit CallableImpl(F &&target) : target_(std::move(target)) {}

        template <typename U>
        explicit CallableImpl(U &&target) : target_(std::forward<U>(target)) {}

        R call(Args... args) override {
            if constexpr (std::is_void_v<R>) {
                std::invoke(target_, std::forward<Args>(args)...);
            } else {
                return std::invoke(target_, std::forward<Args>(args)...);
            }
        }

        F target_;
    };

    std::unique_ptr<CallableBase> ptr_;
};

#endif

// Aborter for the callback_sender bridge: aborts the underlying work after
// stop or destroy. Must be idempotent, callable from any thread, never block,
// and tolerate being invoked after the terminal already fired.
using CallbackAbortFn = move_only_function<void()>;

} // namespace clash_native::async
