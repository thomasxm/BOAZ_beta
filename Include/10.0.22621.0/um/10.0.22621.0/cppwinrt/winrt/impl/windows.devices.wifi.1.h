// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_WiFi_1_H
#define WINRT_Windows_Devices_WiFi_1_H
#include "winrt/impl/Windows.Devices.WiFi.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::WiFi
{
    struct __declspec(empty_bases) IWiFiAdapter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiAdapter>
    {
        IWiFiAdapter(std::nullptr_t = nullptr) noexcept {}
        IWiFiAdapter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWiFiAdapter2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiAdapter2>
    {
        IWiFiAdapter2(std::nullptr_t = nullptr) noexcept {}
        IWiFiAdapter2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWiFiAdapterStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiAdapterStatics>
    {
        IWiFiAdapterStatics(std::nullptr_t = nullptr) noexcept {}
        IWiFiAdapterStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWiFiAvailableNetwork :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiAvailableNetwork>
    {
        IWiFiAvailableNetwork(std::nullptr_t = nullptr) noexcept {}
        IWiFiAvailableNetwork(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWiFiConnectionResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiConnectionResult>
    {
        IWiFiConnectionResult(std::nullptr_t = nullptr) noexcept {}
        IWiFiConnectionResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWiFiNetworkReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiNetworkReport>
    {
        IWiFiNetworkReport(std::nullptr_t = nullptr) noexcept {}
        IWiFiNetworkReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWiFiOnDemandHotspotConnectTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiOnDemandHotspotConnectTriggerDetails>
    {
        IWiFiOnDemandHotspotConnectTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IWiFiOnDemandHotspotConnectTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWiFiOnDemandHotspotConnectionResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiOnDemandHotspotConnectionResult>
    {
        IWiFiOnDemandHotspotConnectionResult(std::nullptr_t = nullptr) noexcept {}
        IWiFiOnDemandHotspotConnectionResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWiFiOnDemandHotspotNetwork :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiOnDemandHotspotNetwork>
    {
        IWiFiOnDemandHotspotNetwork(std::nullptr_t = nullptr) noexcept {}
        IWiFiOnDemandHotspotNetwork(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWiFiOnDemandHotspotNetworkProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiOnDemandHotspotNetworkProperties>
    {
        IWiFiOnDemandHotspotNetworkProperties(std::nullptr_t = nullptr) noexcept {}
        IWiFiOnDemandHotspotNetworkProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWiFiOnDemandHotspotNetworkStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiOnDemandHotspotNetworkStatics>
    {
        IWiFiOnDemandHotspotNetworkStatics(std::nullptr_t = nullptr) noexcept {}
        IWiFiOnDemandHotspotNetworkStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWiFiWpsConfigurationResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWiFiWpsConfigurationResult>
    {
        IWiFiWpsConfigurationResult(std::nullptr_t = nullptr) noexcept {}
        IWiFiWpsConfigurationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
