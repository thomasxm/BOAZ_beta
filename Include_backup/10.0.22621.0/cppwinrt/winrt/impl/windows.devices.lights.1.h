// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Lights_1_H
#define WINRT_Windows_Devices_Lights_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.Lights.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Lights
{
    struct __declspec(empty_bases) ILamp :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILamp>,
        impl::require<winrt::Windows::Devices::Lights::ILamp, winrt::Windows::Foundation::IClosable>
    {
        ILamp(std::nullptr_t = nullptr) noexcept {}
        ILamp(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILampArray :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILampArray>
    {
        ILampArray(std::nullptr_t = nullptr) noexcept {}
        ILampArray(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILampArray2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILampArray2>
    {
        ILampArray2(std::nullptr_t = nullptr) noexcept {}
        ILampArray2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILampArrayStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILampArrayStatics>
    {
        ILampArrayStatics(std::nullptr_t = nullptr) noexcept {}
        ILampArrayStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILampAvailabilityChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILampAvailabilityChangedEventArgs>
    {
        ILampAvailabilityChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ILampAvailabilityChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILampInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILampInfo>
    {
        ILampInfo(std::nullptr_t = nullptr) noexcept {}
        ILampInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILampStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILampStatics>
    {
        ILampStatics(std::nullptr_t = nullptr) noexcept {}
        ILampStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
