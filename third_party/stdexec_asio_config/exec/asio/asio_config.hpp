#pragma once

// Local replacement for the CMake-generated exec/asio/asio_config.hpp.
//
// The vcpkg stdexec port installs the exec/asio adapter headers but not the
// generated asio_config.hpp they include (it is produced by stdexec's own
// CMake configure from asio_config.hpp.in). Until the port ships it, this
// file pins the Boost.Asio variant, matching this project's Asio provider.
// Keep in sync with the template at
// .tools/vcpkg/buildtrees/stdexec/src/<version>.clean/include/exec/asio/asio_config.hpp.in
// when upgrading stdexec. If vcpkg starts installing the file, this directory
// must be removed from the include path to avoid shadowing it.

#define STDEXEC_ASIO_USES_STANDALONE 0
#define STDEXEC_ASIO_USES_BOOST 1

#if STDEXEC_ASIO_USES_BOOST
#  include <boost/asio.hpp>
#  include <boost/system/errc.hpp>
#  include <boost/system/error_code.hpp>
#  include <boost/system/system_error.hpp>
#  define ASIOEXEC_ASIO_NAMESPACE boost::asio
#endif

namespace experimental::execution::asio {
#if STDEXEC_ASIO_USES_BOOST
namespace asio_impl = ::boost::asio;
using error_code = ::boost::system::error_code;
using error_condition = ::boost::system::error_condition;
namespace errc = ::boost::system::errc;
using system_error = ::boost::system::system_error;
#endif
} // namespace experimental::execution::asio

namespace exec = experimental::execution;
