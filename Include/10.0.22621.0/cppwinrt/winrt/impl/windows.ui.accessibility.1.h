// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Accessibility_1_H
#define WINRT_Windows_UI_Accessibility_1_H
#include "winrt/impl/Windows.UI.Accessibility.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Accessibility
{
    struct __declspec(empty_bases) IScreenReaderPositionChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IScreenReaderPositionChangedEventArgs>
    {
        IScreenReaderPositionChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IScreenReaderPositionChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IScreenReaderService :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IScreenReaderService>
    {
        IScreenReaderService(std::nullptr_t = nullptr) noexcept {}
        IScreenReaderService(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
