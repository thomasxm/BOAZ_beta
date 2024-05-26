// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_HumanInterfaceDevice_2_H
#define WINRT_Windows_Devices_HumanInterfaceDevice_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Devices.HumanInterfaceDevice.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::HumanInterfaceDevice
{
    struct __declspec(empty_bases) HidBooleanControl : winrt::Windows::Devices::HumanInterfaceDevice::IHidBooleanControl
    {
        HidBooleanControl(std::nullptr_t) noexcept {}
        HidBooleanControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::HumanInterfaceDevice::IHidBooleanControl(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HidBooleanControlDescription : winrt::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription,
        impl::require<HidBooleanControlDescription, winrt::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription2>
    {
        HidBooleanControlDescription(std::nullptr_t) noexcept {}
        HidBooleanControlDescription(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HidCollection : winrt::Windows::Devices::HumanInterfaceDevice::IHidCollection
    {
        HidCollection(std::nullptr_t) noexcept {}
        HidCollection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::HumanInterfaceDevice::IHidCollection(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HidDevice : winrt::Windows::Devices::HumanInterfaceDevice::IHidDevice
    {
        HidDevice(std::nullptr_t) noexcept {}
        HidDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::HumanInterfaceDevice::IHidDevice(ptr, take_ownership_from_abi) {}
        static auto GetDeviceSelector(uint16_t usagePage, uint16_t usageId);
        static auto GetDeviceSelector(uint16_t usagePage, uint16_t usageId, uint16_t vendorId, uint16_t productId);
        static auto FromIdAsync(param::hstring const& deviceId, winrt::Windows::Storage::FileAccessMode const& accessMode);
    };
    struct __declspec(empty_bases) HidFeatureReport : winrt::Windows::Devices::HumanInterfaceDevice::IHidFeatureReport
    {
        HidFeatureReport(std::nullptr_t) noexcept {}
        HidFeatureReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::HumanInterfaceDevice::IHidFeatureReport(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HidInputReport : winrt::Windows::Devices::HumanInterfaceDevice::IHidInputReport
    {
        HidInputReport(std::nullptr_t) noexcept {}
        HidInputReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::HumanInterfaceDevice::IHidInputReport(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HidInputReportReceivedEventArgs : winrt::Windows::Devices::HumanInterfaceDevice::IHidInputReportReceivedEventArgs
    {
        HidInputReportReceivedEventArgs(std::nullptr_t) noexcept {}
        HidInputReportReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::HumanInterfaceDevice::IHidInputReportReceivedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HidNumericControl : winrt::Windows::Devices::HumanInterfaceDevice::IHidNumericControl
    {
        HidNumericControl(std::nullptr_t) noexcept {}
        HidNumericControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::HumanInterfaceDevice::IHidNumericControl(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HidNumericControlDescription : winrt::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription
    {
        HidNumericControlDescription(std::nullptr_t) noexcept {}
        HidNumericControlDescription(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HidOutputReport : winrt::Windows::Devices::HumanInterfaceDevice::IHidOutputReport
    {
        HidOutputReport(std::nullptr_t) noexcept {}
        HidOutputReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::HumanInterfaceDevice::IHidOutputReport(ptr, take_ownership_from_abi) {}
    };
}
#endif
