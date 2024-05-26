// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Resources_1_H
#define WINRT_Windows_UI_Xaml_Resources_1_H
#include "winrt/impl/Windows.UI.Xaml.Resources.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Resources
{
    struct __declspec(empty_bases) ICustomXamlResourceLoader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomXamlResourceLoader>
    {
        ICustomXamlResourceLoader(std::nullptr_t = nullptr) noexcept {}
        ICustomXamlResourceLoader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomXamlResourceLoaderFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomXamlResourceLoaderFactory>
    {
        ICustomXamlResourceLoaderFactory(std::nullptr_t = nullptr) noexcept {}
        ICustomXamlResourceLoaderFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomXamlResourceLoaderOverrides :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomXamlResourceLoaderOverrides>
    {
        ICustomXamlResourceLoaderOverrides(std::nullptr_t = nullptr) noexcept {}
        ICustomXamlResourceLoaderOverrides(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomXamlResourceLoaderStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomXamlResourceLoaderStatics>
    {
        ICustomXamlResourceLoaderStatics(std::nullptr_t = nullptr) noexcept {}
        ICustomXamlResourceLoaderStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
