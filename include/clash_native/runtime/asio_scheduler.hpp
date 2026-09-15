#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include <utility>

namespace clash_native::runtime {

class AsioScheduler {
  public:
    using Executor = boost::asio::io_context::executor_type;

    explicit AsioScheduler(Executor executor) noexcept : executor_(std::move(executor)) {}

    Executor executor() const noexcept { return executor_; }

    template <typename CompletionToken> void post(CompletionToken &&completion_token) const {
        boost::asio::post(executor_, std::forward<CompletionToken>(completion_token));
    }

  private:
    Executor executor_;
};

} // namespace clash_native::runtime
