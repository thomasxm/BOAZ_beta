// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Bluetooth_Advertisement_2_H
#define WINRT_Windows_Devices_Bluetooth_Advertisement_2_H
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Devices.Bluetooth.Advertisement.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Advertisement
{
    struct __declspec(empty_bases) BluetoothLEAdvertisement : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement
    {
        BluetoothLEAdvertisement(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement(ptr, take_ownership_from_abi) {}
        BluetoothLEAdvertisement();
    };
    struct __declspec(empty_bases) BluetoothLEAdvertisementBytePattern : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern
    {
        BluetoothLEAdvertisementBytePattern(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementBytePattern(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern(ptr, take_ownership_from_abi) {}
        BluetoothLEAdvertisementBytePattern();
        BluetoothLEAdvertisementBytePattern(uint8_t dataType, int16_t offset, winrt::Windows::Storage::Streams::IBuffer const& data);
    };
    struct __declspec(empty_bases) BluetoothLEAdvertisementDataSection : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection
    {
        BluetoothLEAdvertisementDataSection(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementDataSection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection(ptr, take_ownership_from_abi) {}
        BluetoothLEAdvertisementDataSection();
        BluetoothLEAdvertisementDataSection(uint8_t dataType, winrt::Windows::Storage::Streams::IBuffer const& data);
    };
    struct BluetoothLEAdvertisementDataTypes
    {
        BluetoothLEAdvertisementDataTypes() = delete;
        [[nodiscard]] static auto Flags();
        [[nodiscard]] static auto IncompleteService16BitUuids();
        [[nodiscard]] static auto CompleteService16BitUuids();
        [[nodiscard]] static auto IncompleteService32BitUuids();
        [[nodiscard]] static auto CompleteService32BitUuids();
        [[nodiscard]] static auto IncompleteService128BitUuids();
        [[nodiscard]] static auto CompleteService128BitUuids();
        [[nodiscard]] static auto ShortenedLocalName();
        [[nodiscard]] static auto CompleteLocalName();
        [[nodiscard]] static auto TxPowerLevel();
        [[nodiscard]] static auto PeripheralConnectionIntervalRange();
        [[nodiscard]] static auto ServiceSolicitation16BitUuids();
        [[nodiscard]] static auto ServiceSolicitation32BitUuids();
        [[nodiscard]] static auto ServiceSolicitation128BitUuids();
        [[nodiscard]] static auto ServiceData16BitUuids();
        [[nodiscard]] static auto ServiceData32BitUuids();
        [[nodiscard]] static auto ServiceData128BitUuids();
        [[nodiscard]] static auto PublicTargetAddress();
        [[nodiscard]] static auto RandomTargetAddress();
        [[nodiscard]] static auto Appearance();
        [[nodiscard]] static auto AdvertisingInterval();
        [[nodiscard]] static auto ManufacturerSpecificData();
    };
    struct __declspec(empty_bases) BluetoothLEAdvertisementFilter : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter
    {
        BluetoothLEAdvertisementFilter(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementFilter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter(ptr, take_ownership_from_abi) {}
        BluetoothLEAdvertisementFilter();
    };
    struct __declspec(empty_bases) BluetoothLEAdvertisementPublisher : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher,
        impl::require<BluetoothLEAdvertisementPublisher, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2>
    {
        BluetoothLEAdvertisementPublisher(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementPublisher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher(ptr, take_ownership_from_abi) {}
        BluetoothLEAdvertisementPublisher();
        explicit BluetoothLEAdvertisementPublisher(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const& advertisement);
    };
    struct __declspec(empty_bases) BluetoothLEAdvertisementPublisherStatusChangedEventArgs : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs,
        impl::require<BluetoothLEAdvertisementPublisherStatusChangedEventArgs, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2>
    {
        BluetoothLEAdvertisementPublisherStatusChangedEventArgs(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementPublisherStatusChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BluetoothLEAdvertisementReceivedEventArgs : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs,
        impl::require<BluetoothLEAdvertisementReceivedEventArgs, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2>
    {
        BluetoothLEAdvertisementReceivedEventArgs(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BluetoothLEAdvertisementWatcher : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher,
        impl::require<BluetoothLEAdvertisementWatcher, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher2>
    {
        BluetoothLEAdvertisementWatcher(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher(ptr, take_ownership_from_abi) {}
        BluetoothLEAdvertisementWatcher();
        explicit BluetoothLEAdvertisementWatcher(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const& advertisementFilter);
    };
    struct __declspec(empty_bases) BluetoothLEAdvertisementWatcherStoppedEventArgs : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs
    {
        BluetoothLEAdvertisementWatcherStoppedEventArgs(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementWatcherStoppedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BluetoothLEManufacturerData : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData
    {
        BluetoothLEManufacturerData(std::nullptr_t) noexcept {}
        BluetoothLEManufacturerData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData(ptr, take_ownership_from_abi) {}
        BluetoothLEManufacturerData();
        BluetoothLEManufacturerData(uint16_t companyId, winrt::Windows::Storage::Streams::IBuffer const& data);
    };
}
#endif
