// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_DataTransfer_DragDrop_0_H
#define WINRT_Windows_ApplicationModel_DataTransfer_DragDrop_0_H
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer::DragDrop
{
    enum class DragDropModifiers : uint32_t
    {
        None = 0,
        Shift = 0x1,
        Control = 0x2,
        Alt = 0x4,
        LeftButton = 0x8,
        MiddleButton = 0x10,
        RightButton = 0x20,
    };
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::DataTransfer::DragDrop::DragDropModifiers>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::DataTransfer::DragDrop::DragDropModifiers> = L"Windows.ApplicationModel.DataTransfer.DragDrop.DragDropModifiers";
}
#endif
