// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Lights_2_H
#define WINRT_Windows_Devices_Lights_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Devices.Lights.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Lights
{
    struct __declspec(empty_bases) Lamp : winrt::Windows::Devices::Lights::ILamp
    {
        Lamp(std::nullptr_t) noexcept {}
        Lamp(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::ILamp(ptr, take_ownership_from_abi) {}
        static auto GetDeviceSelector();
        static auto FromIdAsync(param::hstring const& deviceId);
        static auto GetDefaultAsync();
    };
    struct __declspec(empty_bases) LampArray : winrt::Windows::Devices::Lights::ILampArray,
        impl::require<LampArray, winrt::Windows::Devices::Lights::ILampArray2>
    {
        LampArray(std::nullptr_t) noexcept {}
        LampArray(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::ILampArray(ptr, take_ownership_from_abi) {}
        static auto GetDeviceSelector();
        static auto FromIdAsync(param::hstring const& deviceId);
    };
    struct __declspec(empty_bases) LampAvailabilityChangedEventArgs : winrt::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs
    {
        LampAvailabilityChangedEventArgs(std::nullptr_t) noexcept {}
        LampAvailabilityChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LampInfo : winrt::Windows::Devices::Lights::ILampInfo
    {
        LampInfo(std::nullptr_t) noexcept {}
        LampInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::ILampInfo(ptr, take_ownership_from_abi) {}
    };
}
#endif
