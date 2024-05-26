// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Pwm_1_H
#define WINRT_Windows_Devices_Pwm_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.Pwm.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Pwm
{
    struct __declspec(empty_bases) IPwmController :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPwmController>
    {
        IPwmController(std::nullptr_t = nullptr) noexcept {}
        IPwmController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPwmControllerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPwmControllerStatics>
    {
        IPwmControllerStatics(std::nullptr_t = nullptr) noexcept {}
        IPwmControllerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPwmControllerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPwmControllerStatics2>
    {
        IPwmControllerStatics2(std::nullptr_t = nullptr) noexcept {}
        IPwmControllerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPwmControllerStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPwmControllerStatics3>
    {
        IPwmControllerStatics3(std::nullptr_t = nullptr) noexcept {}
        IPwmControllerStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPwmPin :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPwmPin>,
        impl::require<winrt::Windows::Devices::Pwm::IPwmPin, winrt::Windows::Foundation::IClosable>
    {
        IPwmPin(std::nullptr_t = nullptr) noexcept {}
        IPwmPin(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
