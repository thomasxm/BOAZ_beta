// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_1_H
#define WINRT_Windows_Networking_1_H
#include "winrt/impl/Windows.Networking.0.h"
WINRT_EXPORT namespace winrt::Windows::Networking
{
    struct __declspec(empty_bases) IEndpointPair :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEndpointPair>
    {
        IEndpointPair(std::nullptr_t = nullptr) noexcept {}
        IEndpointPair(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEndpointPairFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEndpointPairFactory>
    {
        IEndpointPairFactory(std::nullptr_t = nullptr) noexcept {}
        IEndpointPairFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHostName :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHostName>
    {
        IHostName(std::nullptr_t = nullptr) noexcept {}
        IHostName(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHostNameFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHostNameFactory>
    {
        IHostNameFactory(std::nullptr_t = nullptr) noexcept {}
        IHostNameFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHostNameStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHostNameStatics>
    {
        IHostNameStatics(std::nullptr_t = nullptr) noexcept {}
        IHostNameStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
