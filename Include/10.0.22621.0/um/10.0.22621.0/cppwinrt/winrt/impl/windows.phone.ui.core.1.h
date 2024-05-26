// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Phone_UI_Core_1_H
#define WINRT_Windows_Phone_UI_Core_1_H
#include "winrt/impl/Windows.Phone.UI.Core.0.h"
WINRT_EXPORT namespace winrt::Windows::Phone::UI::Core
{
    struct __declspec(empty_bases) ICoreSelectionChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreSelectionChangedEventArgs>
    {
        ICoreSelectionChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICoreSelectionChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreTextChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreTextChangedEventArgs>
    {
        ICoreTextChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICoreTextChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowKeyboardInput :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowKeyboardInput>
    {
        ICoreWindowKeyboardInput(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowKeyboardInput(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IKeyboardInputBuffer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKeyboardInputBuffer>
    {
        IKeyboardInputBuffer(std::nullptr_t = nullptr) noexcept {}
        IKeyboardInputBuffer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
