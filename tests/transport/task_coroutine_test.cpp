// Regression pins for the coroutine-creation rule in docs/async-pitfalls.md:
// tasks must come from named functions or stored (named) lambdas. An
// immediately-invoked capturing lambda (`[xs]() -> stdexec::task<T> {...}()`)
// builds a corrupt frame on Windows clang-cl with this stdexec version, so
// that shape is banned and has no test here by construction.
#include <exec/async_scope.hpp>
#include <gtest/gtest.h>
#include <stdexec/execution.hpp>

namespace {
stdexec::task<void> named_setter(bool &flag) {
    flag = true;
    co_return;
}
stdexec::task<int> named_value(int n) { co_return n; }
} // namespace

TEST(TaskCoroutineTest, NamedFunctionSpawnRuns) {
    exec::async_scope scope;
    bool delivered = false;
    scope.spawn(named_setter(delivered));
    EXPECT_TRUE(delivered);
}

TEST(TaskCoroutineTest, NamedFunctionValueSurvives) {
    auto result = stdexec::sync_wait(named_value(42));
    ASSERT_TRUE(result);
    EXPECT_EQ(std::get<0>(*result), 42);
}

TEST(TaskCoroutineTest, StoredLambdaSpawnRuns) {
    exec::async_scope scope;
    bool delivered = false;
    auto make = [&]() -> stdexec::task<void> {
        delivered = true;
        co_return;
    };
    scope.spawn(make());
    EXPECT_TRUE(delivered);
}

TEST(TaskCoroutineTest, StoredLambdaValueSurvives) {
    int n = 42;
    auto make = [n]() -> stdexec::task<int> { co_return n; };
    auto result = stdexec::sync_wait(make());
    ASSERT_TRUE(result);
    EXPECT_EQ(std::get<0>(*result), 42);
}
