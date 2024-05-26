// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Background_1_H
#define WINRT_Windows_Devices_Background_1_H
#include "winrt/impl/Windows.Devices.Background.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Background
{
    struct __declspec(empty_bases) IDeviceServicingDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeviceServicingDetails>
    {
        IDeviceServicingDetails(std::nullptr_t = nullptr) noexcept {}
        IDeviceServicingDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDeviceUseDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeviceUseDetails>
    {
        IDeviceUseDetails(std::nullptr_t = nullptr) noexcept {}
        IDeviceUseDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
