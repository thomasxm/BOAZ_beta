// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_Proximity_1_H
#define WINRT_Windows_Networking_Proximity_1_H
#include "winrt/impl/Windows.Networking.Proximity.0.h"
WINRT_EXPORT namespace winrt::Windows::Networking::Proximity
{
    struct __declspec(empty_bases) IConnectionRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IConnectionRequestedEventArgs>
    {
        IConnectionRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IConnectionRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPeerFinderStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPeerFinderStatics>
    {
        IPeerFinderStatics(std::nullptr_t = nullptr) noexcept {}
        IPeerFinderStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPeerFinderStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPeerFinderStatics2>
    {
        IPeerFinderStatics2(std::nullptr_t = nullptr) noexcept {}
        IPeerFinderStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPeerInformation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPeerInformation>
    {
        IPeerInformation(std::nullptr_t = nullptr) noexcept {}
        IPeerInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPeerInformation3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPeerInformation3>
    {
        IPeerInformation3(std::nullptr_t = nullptr) noexcept {}
        IPeerInformation3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPeerInformationWithHostAndService :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPeerInformationWithHostAndService>
    {
        IPeerInformationWithHostAndService(std::nullptr_t = nullptr) noexcept {}
        IPeerInformationWithHostAndService(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPeerWatcher :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPeerWatcher>
    {
        IPeerWatcher(std::nullptr_t = nullptr) noexcept {}
        IPeerWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProximityDevice :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProximityDevice>
    {
        IProximityDevice(std::nullptr_t = nullptr) noexcept {}
        IProximityDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProximityDeviceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProximityDeviceStatics>
    {
        IProximityDeviceStatics(std::nullptr_t = nullptr) noexcept {}
        IProximityDeviceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProximityMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProximityMessage>
    {
        IProximityMessage(std::nullptr_t = nullptr) noexcept {}
        IProximityMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITriggeredConnectionStateChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITriggeredConnectionStateChangedEventArgs>
    {
        ITriggeredConnectionStateChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ITriggeredConnectionStateChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
