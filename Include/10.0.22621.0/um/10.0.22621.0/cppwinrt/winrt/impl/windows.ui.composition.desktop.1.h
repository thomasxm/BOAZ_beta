// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Composition_Desktop_1_H
#define WINRT_Windows_UI_Composition_Desktop_1_H
#include "winrt/impl/Windows.UI.Composition.Desktop.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Composition::Desktop
{
    struct __declspec(empty_bases) IDesktopWindowTarget :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDesktopWindowTarget>
    {
        IDesktopWindowTarget(std::nullptr_t = nullptr) noexcept {}
        IDesktopWindowTarget(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
