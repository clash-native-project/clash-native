#pragma once

#include <clash_native/io/any_sender.hpp>

// io::AnySender is the project-owned type-erasure in any_sender.hpp (same
// contract the exec::any_sender alias used to provide: set_value(T) /
// set_error(exception_ptr) / set_stopped(), movable, connected directly to
// any receiver). Receivers must present inplace_stop_token or
// never_stop_token; no scheduler or domain queries cross the erasure.
