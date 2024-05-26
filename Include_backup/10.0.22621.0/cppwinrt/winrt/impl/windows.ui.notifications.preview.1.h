// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Notifications_Preview_1_H
#define WINRT_Windows_UI_Notifications_Preview_1_H
#include "winrt/impl/Windows.UI.Notifications.Preview.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Notifications::Preview
{
    struct __declspec(empty_bases) IToastOcclusionManagerPreviewStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IToastOcclusionManagerPreviewStatics>
    {
        IToastOcclusionManagerPreviewStatics(std::nullptr_t = nullptr) noexcept {}
        IToastOcclusionManagerPreviewStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
