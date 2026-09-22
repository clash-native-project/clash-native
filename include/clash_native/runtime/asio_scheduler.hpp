#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <utility>

namespace clash_native::runtime {

class AsioScheduler {
  public:
    using Executor = boost::asio::io_context::executor_type;
    using SerializedExecutor = boost::asio::strand<Executor>;

    explicit AsioScheduler(Executor executor)
        : executor_(std::move(executor)), strand_(boost::asio::make_strand(executor_)) {}

    explicit AsioScheduler(SerializedExecutor strand) noexcept
        : executor_(strand.get_inner_executor()), strand_(std::move(strand)) {}

    Executor executor() const noexcept { return executor_; }
    SerializedExecutor serialized_executor() const noexcept { return strand_; }

    template <typename CompletionToken> void post(CompletionToken &&completion_token) const {
        boost::asio::post(strand_, std::forward<CompletionToken>(completion_token));
    }

  private:
    Executor executor_;
    SerializedExecutor strand_;
};

} // namespace clash_native::runtime
