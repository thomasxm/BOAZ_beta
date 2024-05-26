// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Pwm_Provider_1_H
#define WINRT_Windows_Devices_Pwm_Provider_1_H
#include "winrt/impl/Windows.Devices.Pwm.Provider.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Pwm::Provider
{
    struct __declspec(empty_bases) IPwmControllerProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPwmControllerProvider>
    {
        IPwmControllerProvider(std::nullptr_t = nullptr) noexcept {}
        IPwmControllerProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPwmProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPwmProvider>
    {
        IPwmProvider(std::nullptr_t = nullptr) noexcept {}
        IPwmProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
