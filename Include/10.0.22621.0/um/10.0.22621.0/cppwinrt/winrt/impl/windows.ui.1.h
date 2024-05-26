// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_1_H
#define WINRT_Windows_UI_1_H
#include "winrt/impl/Windows.UI.0.h"
WINRT_EXPORT namespace winrt::Windows::UI
{
    struct __declspec(empty_bases) IColorHelper :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IColorHelper>
    {
        IColorHelper(std::nullptr_t = nullptr) noexcept {}
        IColorHelper(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IColorHelperStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IColorHelperStatics>
    {
        IColorHelperStatics(std::nullptr_t = nullptr) noexcept {}
        IColorHelperStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IColorHelperStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IColorHelperStatics2>
    {
        IColorHelperStatics2(std::nullptr_t = nullptr) noexcept {}
        IColorHelperStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IColors :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IColors>
    {
        IColors(std::nullptr_t = nullptr) noexcept {}
        IColors(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IColorsStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IColorsStatics>
    {
        IColorsStatics(std::nullptr_t = nullptr) noexcept {}
        IColorsStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUIContentRoot :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUIContentRoot>
    {
        IUIContentRoot(std::nullptr_t = nullptr) noexcept {}
        IUIContentRoot(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUIContext :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUIContext>
    {
        IUIContext(std::nullptr_t = nullptr) noexcept {}
        IUIContext(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
