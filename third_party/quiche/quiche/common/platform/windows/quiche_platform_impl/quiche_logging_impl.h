// Copyright 2026 The clash-native authors.
//
// This file is part of the temporary Windows QUICHE build probe.

#ifndef QUICHE_COMMON_PLATFORM_WINDOWS_QUICHE_PLATFORM_IMPL_QUICHE_LOGGING_IMPL_H_
#define QUICHE_COMMON_PLATFORM_WINDOWS_QUICHE_PLATFORM_IMPL_QUICHE_LOGGING_IMPL_H_

#ifdef interface
#undef interface
#endif

// QUICHE's default logging implementation uses severity tokens in macro names.
// Windows headers define ERROR as 0, which changes QUICHE_LOG(ERROR) into
// QUICHE_LOG_IMPL_0. Keep the upstream implementation and provide the aliases
// required by the Windows preprocessor environment.
#include "../../default/quiche_platform_impl/quiche_logging_impl.h"

#define QUICHE_LOG_IMPL_0() ABSL_LOG_INTERNAL_LOG_IMPL(_ERROR)
#define QUICHE_PLOG_IMPL_0() ABSL_LOG_INTERNAL_PLOG_IMPL(_ERROR)
#define QUICHE_DLOG_IMPL_0() ABSL_LOG_INTERNAL_DLOG_IMPL(_ERROR)

#define QUICHE_LOG_IF_IMPL_0(condition) \
  ABSL_LOG_INTERNAL_LOG_IF_IMPL(_ERROR, condition)
#define QUICHE_PLOG_IF_IMPL_0(condition) \
  ABSL_LOG_INTERNAL_PLOG_IF_IMPL(_ERROR, condition)
#define QUICHE_DLOG_IF_IMPL_0(condition) \
  ABSL_LOG_INTERNAL_DLOG_IF_IMPL(_ERROR, condition)

#define QUICHE_LOG_FIRST_N_IMPL_0(n) \
  ABSL_LOG_INTERNAL_LOG_FIRST_N_IMPL(_ERROR, n)
#define QUICHE_PLOG_FIRST_N_IMPL_0(n) \
  ABSL_LOG_INTERNAL_PLOG_FIRST_N_IMPL(_ERROR, n)

#define QUICHE_LOG_EVERY_N_SEC_IMPL_0(seconds) \
  ABSL_LOG_INTERNAL_LOG_EVERY_N_SEC_IMPL(_ERROR, seconds)
#define QUICHE_DLOG_EVERY_N_SEC_IMPL_0(seconds) \
  ABSL_LOG_INTERNAL_DLOG_EVERY_N_SEC_IMPL(_ERROR, seconds)

#endif  // QUICHE_COMMON_PLATFORM_WINDOWS_QUICHE_PLATFORM_IMPL_QUICHE_LOGGING_IMPL_H_
