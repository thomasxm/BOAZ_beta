// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Bluetooth_Rfcomm_2_H
#define WINRT_Windows_Devices_Bluetooth_Rfcomm_2_H
#include "winrt/impl/Windows.Devices.Bluetooth.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Devices.Bluetooth.Rfcomm.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Rfcomm
{
    struct __declspec(empty_bases) RfcommDeviceService : winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService,
        impl::require<RfcommDeviceService, winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService2, winrt::Windows::Foundation::IClosable, winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService3>
    {
        RfcommDeviceService(std::nullptr_t) noexcept {}
        RfcommDeviceService(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService(ptr, take_ownership_from_abi) {}
        static auto FromIdAsync(param::hstring const& deviceId);
        static auto GetDeviceSelector(winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId);
        static auto GetDeviceSelectorForBluetoothDevice(winrt::Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice);
        static auto GetDeviceSelectorForBluetoothDevice(winrt::Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice, winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode);
        static auto GetDeviceSelectorForBluetoothDeviceAndServiceId(winrt::Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice, winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId);
        static auto GetDeviceSelectorForBluetoothDeviceAndServiceId(winrt::Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice, winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId, winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode);
    };
    struct __declspec(empty_bases) RfcommDeviceServicesResult : winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServicesResult
    {
        RfcommDeviceServicesResult(std::nullptr_t) noexcept {}
        RfcommDeviceServicesResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServicesResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RfcommServiceId : winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceId
    {
        RfcommServiceId(std::nullptr_t) noexcept {}
        RfcommServiceId(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceId(ptr, take_ownership_from_abi) {}
        static auto FromUuid(winrt::guid const& uuid);
        static auto FromShortId(uint32_t shortId);
        [[nodiscard]] static auto SerialPort();
        [[nodiscard]] static auto ObexObjectPush();
        [[nodiscard]] static auto ObexFileTransfer();
        [[nodiscard]] static auto PhoneBookAccessPce();
        [[nodiscard]] static auto PhoneBookAccessPse();
        [[nodiscard]] static auto GenericFileTransfer();
    };
    struct __declspec(empty_bases) RfcommServiceProvider : winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider,
        impl::require<RfcommServiceProvider, winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider2>
    {
        RfcommServiceProvider(std::nullptr_t) noexcept {}
        RfcommServiceProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider(ptr, take_ownership_from_abi) {}
        using winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider::StartAdvertising;
        using impl::consume_t<RfcommServiceProvider, winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider2>::StartAdvertising;
        static auto CreateAsync(winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId);
    };
}
#endif
