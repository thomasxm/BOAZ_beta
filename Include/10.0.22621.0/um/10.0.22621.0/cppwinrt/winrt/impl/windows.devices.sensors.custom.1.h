// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Sensors_Custom_1_H
#define WINRT_Windows_Devices_Sensors_Custom_1_H
#include "winrt/impl/Windows.Devices.Sensors.Custom.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Sensors::Custom
{
    struct __declspec(empty_bases) ICustomSensor :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomSensor>
    {
        ICustomSensor(std::nullptr_t = nullptr) noexcept {}
        ICustomSensor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomSensor2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomSensor2>
    {
        ICustomSensor2(std::nullptr_t = nullptr) noexcept {}
        ICustomSensor2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomSensorReading :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomSensorReading>
    {
        ICustomSensorReading(std::nullptr_t = nullptr) noexcept {}
        ICustomSensorReading(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomSensorReading2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomSensorReading2>
    {
        ICustomSensorReading2(std::nullptr_t = nullptr) noexcept {}
        ICustomSensorReading2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomSensorReadingChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomSensorReadingChangedEventArgs>
    {
        ICustomSensorReadingChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICustomSensorReadingChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomSensorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomSensorStatics>
    {
        ICustomSensorStatics(std::nullptr_t = nullptr) noexcept {}
        ICustomSensorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
