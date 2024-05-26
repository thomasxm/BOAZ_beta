// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_1_H
#define WINRT_Windows_Web_1_H
#include "winrt/impl/Windows.Web.0.h"
WINRT_EXPORT namespace winrt::Windows::Web
{
    struct __declspec(empty_bases) IUriToStreamResolver :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUriToStreamResolver>
    {
        IUriToStreamResolver(std::nullptr_t = nullptr) noexcept {}
        IUriToStreamResolver(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebErrorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebErrorStatics>
    {
        IWebErrorStatics(std::nullptr_t = nullptr) noexcept {}
        IWebErrorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
