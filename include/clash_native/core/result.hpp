#pragma once

#include <clash_native/core/error.hpp>

#include <tl/expected.hpp>

#include <utility>

namespace clash_native::core {

template <typename T> using Result = tl::expected<T, Error>;

using Status = Result<void>;

[[nodiscard]] inline tl::unexpected<Error> fail(Error error) {
    return tl::make_unexpected(std::move(error));
}

} // namespace clash_native::core
