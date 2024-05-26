// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_I2c_Provider_1_H
#define WINRT_Windows_Devices_I2c_Provider_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.I2c.Provider.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::I2c::Provider
{
    struct __declspec(empty_bases) II2cControllerProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<II2cControllerProvider>
    {
        II2cControllerProvider(std::nullptr_t = nullptr) noexcept {}
        II2cControllerProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) II2cDeviceProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<II2cDeviceProvider>,
        impl::require<winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider, winrt::Windows::Foundation::IClosable>
    {
        II2cDeviceProvider(std::nullptr_t = nullptr) noexcept {}
        II2cDeviceProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) II2cProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<II2cProvider>
    {
        II2cProvider(std::nullptr_t = nullptr) noexcept {}
        II2cProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProviderI2cConnectionSettings :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProviderI2cConnectionSettings>
    {
        IProviderI2cConnectionSettings(std::nullptr_t = nullptr) noexcept {}
        IProviderI2cConnectionSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
