// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Bluetooth_Background_2_H
#define WINRT_Windows_Devices_Bluetooth_Background_2_H
#include "winrt/impl/Windows.Devices.Bluetooth.Background.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Background
{
    struct __declspec(empty_bases) BluetoothLEAdvertisementPublisherTriggerDetails : winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails,
        impl::require<BluetoothLEAdvertisementPublisherTriggerDetails, winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails2>
    {
        BluetoothLEAdvertisementPublisherTriggerDetails(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementPublisherTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BluetoothLEAdvertisementWatcherTriggerDetails : winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails
    {
        BluetoothLEAdvertisementWatcherTriggerDetails(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementWatcherTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) GattCharacteristicNotificationTriggerDetails : winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails,
        impl::require<GattCharacteristicNotificationTriggerDetails, winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2>
    {
        GattCharacteristicNotificationTriggerDetails(std::nullptr_t) noexcept {}
        GattCharacteristicNotificationTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) GattServiceProviderConnection : winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection
    {
        GattServiceProviderConnection(std::nullptr_t) noexcept {}
        GattServiceProviderConnection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection(ptr, take_ownership_from_abi) {}
        [[nodiscard]] static auto AllServices();
    };
    struct __declspec(empty_bases) GattServiceProviderTriggerDetails : winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails
    {
        GattServiceProviderTriggerDetails(std::nullptr_t) noexcept {}
        GattServiceProviderTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RfcommConnectionTriggerDetails : winrt::Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails
    {
        RfcommConnectionTriggerDetails(std::nullptr_t) noexcept {}
        RfcommConnectionTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RfcommInboundConnectionInformation : winrt::Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation
    {
        RfcommInboundConnectionInformation(std::nullptr_t) noexcept {}
        RfcommInboundConnectionInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RfcommOutboundConnectionInformation : winrt::Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation
    {
        RfcommOutboundConnectionInformation(std::nullptr_t) noexcept {}
        RfcommOutboundConnectionInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation(ptr, take_ownership_from_abi) {}
    };
}
#endif
