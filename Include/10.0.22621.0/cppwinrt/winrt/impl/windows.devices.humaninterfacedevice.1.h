// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_HumanInterfaceDevice_1_H
#define WINRT_Windows_Devices_HumanInterfaceDevice_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.HumanInterfaceDevice.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::HumanInterfaceDevice
{
    struct __declspec(empty_bases) IHidBooleanControl :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidBooleanControl>
    {
        IHidBooleanControl(std::nullptr_t = nullptr) noexcept {}
        IHidBooleanControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHidBooleanControlDescription :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidBooleanControlDescription>
    {
        IHidBooleanControlDescription(std::nullptr_t = nullptr) noexcept {}
        IHidBooleanControlDescription(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHidBooleanControlDescription2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidBooleanControlDescription2>
    {
        IHidBooleanControlDescription2(std::nullptr_t = nullptr) noexcept {}
        IHidBooleanControlDescription2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHidCollection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidCollection>
    {
        IHidCollection(std::nullptr_t = nullptr) noexcept {}
        IHidCollection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHidDevice :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidDevice>,
        impl::require<winrt::Windows::Devices::HumanInterfaceDevice::IHidDevice, winrt::Windows::Foundation::IClosable>
    {
        IHidDevice(std::nullptr_t = nullptr) noexcept {}
        IHidDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHidDeviceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidDeviceStatics>
    {
        IHidDeviceStatics(std::nullptr_t = nullptr) noexcept {}
        IHidDeviceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHidFeatureReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidFeatureReport>
    {
        IHidFeatureReport(std::nullptr_t = nullptr) noexcept {}
        IHidFeatureReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHidInputReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidInputReport>
    {
        IHidInputReport(std::nullptr_t = nullptr) noexcept {}
        IHidInputReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHidInputReportReceivedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidInputReportReceivedEventArgs>
    {
        IHidInputReportReceivedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IHidInputReportReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHidNumericControl :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidNumericControl>
    {
        IHidNumericControl(std::nullptr_t = nullptr) noexcept {}
        IHidNumericControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHidNumericControlDescription :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidNumericControlDescription>
    {
        IHidNumericControlDescription(std::nullptr_t = nullptr) noexcept {}
        IHidNumericControlDescription(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHidOutputReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHidOutputReport>
    {
        IHidOutputReport(std::nullptr_t = nullptr) noexcept {}
        IHidOutputReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
