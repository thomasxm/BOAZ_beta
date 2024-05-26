// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Adc_2_H
#define WINRT_Windows_Devices_Adc_2_H
#include "winrt/impl/Windows.Devices.Adc.Provider.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Devices.Adc.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Adc
{
    struct __declspec(empty_bases) AdcChannel : winrt::Windows::Devices::Adc::IAdcChannel
    {
        AdcChannel(std::nullptr_t) noexcept {}
        AdcChannel(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Adc::IAdcChannel(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AdcController : winrt::Windows::Devices::Adc::IAdcController
    {
        AdcController(std::nullptr_t) noexcept {}
        AdcController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Adc::IAdcController(ptr, take_ownership_from_abi) {}
        static auto GetControllersAsync(winrt::Windows::Devices::Adc::Provider::IAdcProvider const& provider);
        static auto GetDefaultAsync();
    };
}
#endif
