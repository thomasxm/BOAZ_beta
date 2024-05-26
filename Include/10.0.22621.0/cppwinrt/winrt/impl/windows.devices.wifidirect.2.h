// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_WiFiDirect_2_H
#define WINRT_Windows_Devices_WiFiDirect_2_H
#include "winrt/impl/Windows.Devices.Enumeration.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Devices.WiFiDirect.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::WiFiDirect
{
    struct __declspec(empty_bases) WiFiDirectAdvertisement : winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement,
        impl::require<WiFiDirectAdvertisement, winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement2>
    {
        WiFiDirectAdvertisement(std::nullptr_t) noexcept {}
        WiFiDirectAdvertisement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WiFiDirectAdvertisementPublisher : winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher
    {
        WiFiDirectAdvertisementPublisher(std::nullptr_t) noexcept {}
        WiFiDirectAdvertisementPublisher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher(ptr, take_ownership_from_abi) {}
        WiFiDirectAdvertisementPublisher();
    };
    struct __declspec(empty_bases) WiFiDirectAdvertisementPublisherStatusChangedEventArgs : winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisherStatusChangedEventArgs
    {
        WiFiDirectAdvertisementPublisherStatusChangedEventArgs(std::nullptr_t) noexcept {}
        WiFiDirectAdvertisementPublisherStatusChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisherStatusChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WiFiDirectConnectionListener : winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener
    {
        WiFiDirectConnectionListener(std::nullptr_t) noexcept {}
        WiFiDirectConnectionListener(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener(ptr, take_ownership_from_abi) {}
        WiFiDirectConnectionListener();
    };
    struct __declspec(empty_bases) WiFiDirectConnectionParameters : winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters,
        impl::require<WiFiDirectConnectionParameters, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters2, winrt::Windows::Devices::Enumeration::IDevicePairingSettings>
    {
        WiFiDirectConnectionParameters(std::nullptr_t) noexcept {}
        WiFiDirectConnectionParameters(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters(ptr, take_ownership_from_abi) {}
        WiFiDirectConnectionParameters();
        static auto GetDevicePairingKinds(winrt::Windows::Devices::WiFiDirect::WiFiDirectConfigurationMethod const& configurationMethod);
    };
    struct __declspec(empty_bases) WiFiDirectConnectionRequest : winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequest
    {
        WiFiDirectConnectionRequest(std::nullptr_t) noexcept {}
        WiFiDirectConnectionRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequest(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WiFiDirectConnectionRequestedEventArgs : winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequestedEventArgs
    {
        WiFiDirectConnectionRequestedEventArgs(std::nullptr_t) noexcept {}
        WiFiDirectConnectionRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WiFiDirectDevice : winrt::Windows::Devices::WiFiDirect::IWiFiDirectDevice
    {
        WiFiDirectDevice(std::nullptr_t) noexcept {}
        WiFiDirectDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::WiFiDirect::IWiFiDirectDevice(ptr, take_ownership_from_abi) {}
        static auto GetDeviceSelector();
        static auto FromIdAsync(param::hstring const& deviceId);
        static auto GetDeviceSelector(winrt::Windows::Devices::WiFiDirect::WiFiDirectDeviceSelectorType const& type);
        static auto FromIdAsync(param::hstring const& deviceId, winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionParameters const& connectionParameters);
    };
    struct __declspec(empty_bases) WiFiDirectInformationElement : winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElement
    {
        WiFiDirectInformationElement(std::nullptr_t) noexcept {}
        WiFiDirectInformationElement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElement(ptr, take_ownership_from_abi) {}
        WiFiDirectInformationElement();
        static auto CreateFromBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer);
        static auto CreateFromDeviceInformation(winrt::Windows::Devices::Enumeration::DeviceInformation const& deviceInformation);
    };
    struct __declspec(empty_bases) WiFiDirectLegacySettings : winrt::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings
    {
        WiFiDirectLegacySettings(std::nullptr_t) noexcept {}
        WiFiDirectLegacySettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings(ptr, take_ownership_from_abi) {}
    };
}
#endif
