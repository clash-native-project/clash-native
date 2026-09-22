#include <clash_native/runtime/asio_runtime.hpp>

#include <gtest/gtest.h>

#include <boost/asio/post.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <mutex>
#include <set>
#include <thread>

using namespace std::chrono_literals;

TEST(AsioRuntimeTest, RunsPostedWork) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    std::promise<void> completion;
    auto future = completion.get_future();

    runtime.start();
    boost::asio::post(runtime.context(), [&completion] { completion.set_value(); });

    EXPECT_EQ(future.wait_for(1s), std::future_status::ready);
    runtime.stop();
}

TEST(AsioRuntimeTest, DrainsPostedWorkWhenStopping) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    std::promise<void> completion;
    auto future = completion.get_future();

    runtime.start();
    boost::asio::post(runtime.context(), [&completion] { completion.set_value(); });

    runtime.stop();

    EXPECT_EQ(future.wait_for(0s), std::future_status::ready);
}

TEST(AsioRuntimeTest, RunsOneIoContextWithMultipleWorkerThreads) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    runtime.set_worker_count(2);

    std::promise<void> second_worker_started;
    auto second_worker_started_future = second_worker_started.get_future();
    std::promise<void> release_workers;
    auto release_future = release_workers.get_future().share();
    std::atomic_int started{0};
    std::mutex thread_mutex;
    std::set<std::thread::id> thread_ids;

    runtime.start();
    for (int index = 0; index < 2; ++index) {
        boost::asio::post(runtime.context(), [&] {
            {
                std::lock_guard lock(thread_mutex);
                thread_ids.insert(std::this_thread::get_id());
            }
            if (started.fetch_add(1) == 1) {
                second_worker_started.set_value();
            }
            release_future.wait();
        });
    }

    const auto status = second_worker_started_future.wait_for(1s);
    release_workers.set_value();
    runtime.stop();
    runtime.set_worker_count(clash_native::runtime::AsioRuntime::kDefaultWorkerCount);

    EXPECT_EQ(status, std::future_status::ready);
    EXPECT_EQ(thread_ids.size(), 2U);
}

TEST(AsioRuntimeTest, RebuildsContextWhenWorkerCountChanges) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    runtime.set_worker_count(clash_native::runtime::AsioRuntime::kDefaultWorkerCount);
    auto *default_context = &runtime.context();

    runtime.set_worker_count(1);
    auto *single_worker_context = &runtime.context();

    EXPECT_NE(default_context, single_worker_context);

    runtime.start();
    std::promise<void> completion;
    auto future = completion.get_future();
    boost::asio::post(runtime.context(), [&completion] { completion.set_value(); });
    EXPECT_EQ(future.wait_for(1s), std::future_status::ready);
    runtime.stop();
    runtime.set_worker_count(clash_native::runtime::AsioRuntime::kDefaultWorkerCount);
}
