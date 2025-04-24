// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <sstream>

FMT_BEGIN_NAMESPACE

template <>
struct formatter<RFC1035::Name>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const RFC1035::Name& name, FormatContext& ctx)
  {
    return format_to(ctx.out(), "{}", (std::string)name);
  }
};

template <>
struct formatter<RFC1035::RDataFormat>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const RFC1035::RDataFormat& rdata, FormatContext& ctx)
  {
    return format_to(ctx.out(), "{}", (std::string)rdata);
  }
};

FMT_END_NAMESPACE
