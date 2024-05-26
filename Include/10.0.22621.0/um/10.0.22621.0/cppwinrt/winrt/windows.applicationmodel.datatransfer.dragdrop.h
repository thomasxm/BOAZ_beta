// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_DataTransfer_DragDrop_H
#define WINRT_Windows_ApplicationModel_DataTransfer_DragDrop_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.DataTransfer.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.DragDrop.2.h"
namespace winrt::impl
{
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer::DragDrop
{
    constexpr auto operator|(DragDropModifiers const left, DragDropModifiers const right) noexcept
    {
        return static_cast<DragDropModifiers>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DragDropModifiers& left, DragDropModifiers const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DragDropModifiers const left, DragDropModifiers const right) noexcept
    {
        return static_cast<DragDropModifiers>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DragDropModifiers& left, DragDropModifiers const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DragDropModifiers const value) noexcept
    {
        return static_cast<DragDropModifiers>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DragDropModifiers const left, DragDropModifiers const right) noexcept
    {
        return static_cast<DragDropModifiers>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DragDropModifiers& left, DragDropModifiers const right) noexcept
    {
        left = left ^ right;
        return left;
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
