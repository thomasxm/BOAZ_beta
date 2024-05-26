// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_1_H
#define WINRT_Windows_Management_1_H
#include "winrt/impl/Windows.Management.0.h"
WINRT_EXPORT namespace winrt::Windows::Management
{
    struct __declspec(empty_bases) IMdmAlert :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMdmAlert>
    {
        IMdmAlert(std::nullptr_t = nullptr) noexcept {}
        IMdmAlert(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMdmSession :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMdmSession>
    {
        IMdmSession(std::nullptr_t = nullptr) noexcept {}
        IMdmSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMdmSessionManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMdmSessionManagerStatics>
    {
        IMdmSessionManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IMdmSessionManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
