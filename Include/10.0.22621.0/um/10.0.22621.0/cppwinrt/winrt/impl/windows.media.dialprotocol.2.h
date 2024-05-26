// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_DialProtocol_2_H
#define WINRT_Windows_Media_DialProtocol_2_H
#include "winrt/impl/Windows.Devices.Enumeration.1.h"
#include "winrt/impl/Windows.Media.DialProtocol.1.h"
WINRT_EXPORT namespace winrt::Windows::Media::DialProtocol
{
    struct __declspec(empty_bases) DialApp : winrt::Windows::Media::DialProtocol::IDialApp
    {
        DialApp(std::nullptr_t) noexcept {}
        DialApp(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::DialProtocol::IDialApp(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DialAppStateDetails : winrt::Windows::Media::DialProtocol::IDialAppStateDetails
    {
        DialAppStateDetails(std::nullptr_t) noexcept {}
        DialAppStateDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::DialProtocol::IDialAppStateDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DialDevice : winrt::Windows::Media::DialProtocol::IDialDevice,
        impl::require<DialDevice, winrt::Windows::Media::DialProtocol::IDialDevice2>
    {
        DialDevice(std::nullptr_t) noexcept {}
        DialDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::DialProtocol::IDialDevice(ptr, take_ownership_from_abi) {}
        static auto GetDeviceSelector(param::hstring const& appName);
        static auto FromIdAsync(param::hstring const& value);
        static auto DeviceInfoSupportsDialAsync(winrt::Windows::Devices::Enumeration::DeviceInformation const& device);
    };
    struct __declspec(empty_bases) DialDevicePicker : winrt::Windows::Media::DialProtocol::IDialDevicePicker
    {
        DialDevicePicker(std::nullptr_t) noexcept {}
        DialDevicePicker(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::DialProtocol::IDialDevicePicker(ptr, take_ownership_from_abi) {}
        DialDevicePicker();
    };
    struct __declspec(empty_bases) DialDevicePickerFilter : winrt::Windows::Media::DialProtocol::IDialDevicePickerFilter
    {
        DialDevicePickerFilter(std::nullptr_t) noexcept {}
        DialDevicePickerFilter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::DialProtocol::IDialDevicePickerFilter(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DialDeviceSelectedEventArgs : winrt::Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs
    {
        DialDeviceSelectedEventArgs(std::nullptr_t) noexcept {}
        DialDeviceSelectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DialDisconnectButtonClickedEventArgs : winrt::Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs
    {
        DialDisconnectButtonClickedEventArgs(std::nullptr_t) noexcept {}
        DialDisconnectButtonClickedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DialReceiverApp : winrt::Windows::Media::DialProtocol::IDialReceiverApp,
        impl::require<DialReceiverApp, winrt::Windows::Media::DialProtocol::IDialReceiverApp2>
    {
        DialReceiverApp(std::nullptr_t) noexcept {}
        DialReceiverApp(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::DialProtocol::IDialReceiverApp(ptr, take_ownership_from_abi) {}
        [[nodiscard]] static auto Current();
    };
}
#endif
