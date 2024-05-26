// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Portable_1_H
#define WINRT_Windows_Devices_Portable_1_H
#include "winrt/impl/Windows.Devices.Portable.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Portable
{
    struct __declspec(empty_bases) IServiceDeviceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IServiceDeviceStatics>
    {
        IServiceDeviceStatics(std::nullptr_t = nullptr) noexcept {}
        IServiceDeviceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageDeviceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageDeviceStatics>
    {
        IStorageDeviceStatics(std::nullptr_t = nullptr) noexcept {}
        IStorageDeviceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
