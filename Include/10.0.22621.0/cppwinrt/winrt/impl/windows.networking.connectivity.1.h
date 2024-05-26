// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_Connectivity_1_H
#define WINRT_Windows_Networking_Connectivity_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Networking.Connectivity.0.h"
WINRT_EXPORT namespace winrt::Windows::Networking::Connectivity
{
    struct __declspec(empty_bases) IAttributedNetworkUsage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAttributedNetworkUsage>
    {
        IAttributedNetworkUsage(std::nullptr_t = nullptr) noexcept {}
        IAttributedNetworkUsage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICellularApnContext :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICellularApnContext>
    {
        ICellularApnContext(std::nullptr_t = nullptr) noexcept {}
        ICellularApnContext(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICellularApnContext2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICellularApnContext2>
    {
        ICellularApnContext2(std::nullptr_t = nullptr) noexcept {}
        ICellularApnContext2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionCost :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionCost>
    {
        IConnectionCost(std::nullptr_t = nullptr) noexcept {}
        IConnectionCost(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionCost2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionCost2>
    {
        IConnectionCost2(std::nullptr_t = nullptr) noexcept {}
        IConnectionCost2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionProfile :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionProfile>
    {
        IConnectionProfile(std::nullptr_t = nullptr) noexcept {}
        IConnectionProfile(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionProfile2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionProfile2>
    {
        IConnectionProfile2(std::nullptr_t = nullptr) noexcept {}
        IConnectionProfile2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionProfile3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionProfile3>
    {
        IConnectionProfile3(std::nullptr_t = nullptr) noexcept {}
        IConnectionProfile3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionProfile4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionProfile4>
    {
        IConnectionProfile4(std::nullptr_t = nullptr) noexcept {}
        IConnectionProfile4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionProfile5 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionProfile5>
    {
        IConnectionProfile5(std::nullptr_t = nullptr) noexcept {}
        IConnectionProfile5(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionProfile6 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionProfile6>
    {
        IConnectionProfile6(std::nullptr_t = nullptr) noexcept {}
        IConnectionProfile6(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionProfileFilter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionProfileFilter>
    {
        IConnectionProfileFilter(std::nullptr_t = nullptr) noexcept {}
        IConnectionProfileFilter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionProfileFilter2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionProfileFilter2>
    {
        IConnectionProfileFilter2(std::nullptr_t = nullptr) noexcept {}
        IConnectionProfileFilter2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionProfileFilter3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionProfileFilter3>
    {
        IConnectionProfileFilter3(std::nullptr_t = nullptr) noexcept {}
        IConnectionProfileFilter3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectionSession :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionSession>,
        impl::require<winrt::Windows::Networking::Connectivity::IConnectionSession, winrt::Windows::Foundation::IClosable>
    {
        IConnectionSession(std::nullptr_t = nullptr) noexcept {}
        IConnectionSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectivityInterval :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectivityInterval>
    {
        IConnectivityInterval(std::nullptr_t = nullptr) noexcept {}
        IConnectivityInterval(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IConnectivityManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectivityManagerStatics>
    {
        IConnectivityManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IConnectivityManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDataPlanStatus :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDataPlanStatus>
    {
        IDataPlanStatus(std::nullptr_t = nullptr) noexcept {}
        IDataPlanStatus(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDataPlanUsage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDataPlanUsage>
    {
        IDataPlanUsage(std::nullptr_t = nullptr) noexcept {}
        IDataPlanUsage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDataUsage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDataUsage>
    {
        IDataUsage(std::nullptr_t = nullptr) noexcept {}
        IDataUsage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IIPInformation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IIPInformation>
    {
        IIPInformation(std::nullptr_t = nullptr) noexcept {}
        IIPInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILanIdentifier :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILanIdentifier>
    {
        ILanIdentifier(std::nullptr_t = nullptr) noexcept {}
        ILanIdentifier(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILanIdentifierData :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILanIdentifierData>
    {
        ILanIdentifierData(std::nullptr_t = nullptr) noexcept {}
        ILanIdentifierData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INetworkAdapter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INetworkAdapter>
    {
        INetworkAdapter(std::nullptr_t = nullptr) noexcept {}
        INetworkAdapter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INetworkInformationStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INetworkInformationStatics>
    {
        INetworkInformationStatics(std::nullptr_t = nullptr) noexcept {}
        INetworkInformationStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INetworkInformationStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INetworkInformationStatics2>
    {
        INetworkInformationStatics2(std::nullptr_t = nullptr) noexcept {}
        INetworkInformationStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INetworkItem :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INetworkItem>
    {
        INetworkItem(std::nullptr_t = nullptr) noexcept {}
        INetworkItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INetworkSecuritySettings :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INetworkSecuritySettings>
    {
        INetworkSecuritySettings(std::nullptr_t = nullptr) noexcept {}
        INetworkSecuritySettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INetworkStateChangeEventDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INetworkStateChangeEventDetails>
    {
        INetworkStateChangeEventDetails(std::nullptr_t = nullptr) noexcept {}
        INetworkStateChangeEventDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INetworkStateChangeEventDetails2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INetworkStateChangeEventDetails2>
    {
        INetworkStateChangeEventDetails2(std::nullptr_t = nullptr) noexcept {}
        INetworkStateChangeEventDetails2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INetworkUsage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INetworkUsage>
    {
        INetworkUsage(std::nullptr_t = nullptr) noexcept {}
        INetworkUsage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProviderNetworkUsage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProviderNetworkUsage>
    {
        IProviderNetworkUsage(std::nullptr_t = nullptr) noexcept {}
        IProviderNetworkUsage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProxyConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProxyConfiguration>
    {
        IProxyConfiguration(std::nullptr_t = nullptr) noexcept {}
        IProxyConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRoutePolicy :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRoutePolicy>
    {
        IRoutePolicy(std::nullptr_t = nullptr) noexcept {}
        IRoutePolicy(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRoutePolicyFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRoutePolicyFactory>
    {
        IRoutePolicyFactory(std::nullptr_t = nullptr) noexcept {}
        IRoutePolicyFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWlanConnectionProfileDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWlanConnectionProfileDetails>
    {
        IWlanConnectionProfileDetails(std::nullptr_t = nullptr) noexcept {}
        IWlanConnectionProfileDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWwanConnectionProfileDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWwanConnectionProfileDetails>
    {
        IWwanConnectionProfileDetails(std::nullptr_t = nullptr) noexcept {}
        IWwanConnectionProfileDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWwanConnectionProfileDetails2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWwanConnectionProfileDetails2>
    {
        IWwanConnectionProfileDetails2(std::nullptr_t = nullptr) noexcept {}
        IWwanConnectionProfileDetails2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
