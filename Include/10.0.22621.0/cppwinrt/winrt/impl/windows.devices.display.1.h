// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Display_1_H
#define WINRT_Windows_Devices_Display_1_H
#include "winrt/impl/Windows.Devices.Display.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Display
{
    struct __declspec(empty_bases) IDisplayMonitor :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDisplayMonitor>
    {
        IDisplayMonitor(std::nullptr_t = nullptr) noexcept {}
        IDisplayMonitor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDisplayMonitor2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDisplayMonitor2>
    {
        IDisplayMonitor2(std::nullptr_t = nullptr) noexcept {}
        IDisplayMonitor2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDisplayMonitorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDisplayMonitorStatics>
    {
        IDisplayMonitorStatics(std::nullptr_t = nullptr) noexcept {}
        IDisplayMonitorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
