// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Spi_2_H
#define WINRT_Windows_Devices_Spi_2_H
#include "winrt/impl/Windows.Devices.Spi.Provider.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Devices.Spi.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Spi
{
    struct __declspec(empty_bases) SpiBusInfo : winrt::Windows::Devices::Spi::ISpiBusInfo
    {
        SpiBusInfo(std::nullptr_t) noexcept {}
        SpiBusInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Spi::ISpiBusInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpiConnectionSettings : winrt::Windows::Devices::Spi::ISpiConnectionSettings
    {
        SpiConnectionSettings(std::nullptr_t) noexcept {}
        SpiConnectionSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Spi::ISpiConnectionSettings(ptr, take_ownership_from_abi) {}
        explicit SpiConnectionSettings(int32_t chipSelectLine);
    };
    struct __declspec(empty_bases) SpiController : winrt::Windows::Devices::Spi::ISpiController
    {
        SpiController(std::nullptr_t) noexcept {}
        SpiController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Spi::ISpiController(ptr, take_ownership_from_abi) {}
        static auto GetDefaultAsync();
        static auto GetControllersAsync(winrt::Windows::Devices::Spi::Provider::ISpiProvider const& provider);
    };
    struct __declspec(empty_bases) SpiDevice : winrt::Windows::Devices::Spi::ISpiDevice
    {
        SpiDevice(std::nullptr_t) noexcept {}
        SpiDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Spi::ISpiDevice(ptr, take_ownership_from_abi) {}
        static auto GetDeviceSelector();
        static auto GetDeviceSelector(param::hstring const& friendlyName);
        static auto GetBusInfo(param::hstring const& busId);
        static auto FromIdAsync(param::hstring const& busId, winrt::Windows::Devices::Spi::SpiConnectionSettings const& settings);
    };
}
#endif
