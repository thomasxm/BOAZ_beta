// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_WindowManagement_Preview_1_H
#define WINRT_Windows_UI_WindowManagement_Preview_1_H
#include "winrt/impl/Windows.UI.WindowManagement.Preview.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement::Preview
{
    struct __declspec(empty_bases) IWindowManagementPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowManagementPreview>
    {
        IWindowManagementPreview(std::nullptr_t = nullptr) noexcept {}
        IWindowManagementPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowManagementPreviewStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowManagementPreviewStatics>
    {
        IWindowManagementPreviewStatics(std::nullptr_t = nullptr) noexcept {}
        IWindowManagementPreviewStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
