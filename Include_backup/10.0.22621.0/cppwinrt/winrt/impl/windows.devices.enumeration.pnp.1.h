// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Enumeration_Pnp_1_H
#define WINRT_Windows_Devices_Enumeration_Pnp_1_H
#include "winrt/impl/Windows.Devices.Enumeration.Pnp.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration::Pnp
{
    struct __declspec(empty_bases) IPnpObject :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPnpObject>
    {
        IPnpObject(std::nullptr_t = nullptr) noexcept {}
        IPnpObject(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPnpObjectStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPnpObjectStatics>
    {
        IPnpObjectStatics(std::nullptr_t = nullptr) noexcept {}
        IPnpObjectStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPnpObjectUpdate :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPnpObjectUpdate>
    {
        IPnpObjectUpdate(std::nullptr_t = nullptr) noexcept {}
        IPnpObjectUpdate(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPnpObjectWatcher :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPnpObjectWatcher>
    {
        IPnpObjectWatcher(std::nullptr_t = nullptr) noexcept {}
        IPnpObjectWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
