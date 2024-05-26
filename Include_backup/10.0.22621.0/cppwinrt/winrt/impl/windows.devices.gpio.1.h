// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Gpio_1_H
#define WINRT_Windows_Devices_Gpio_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.Gpio.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Gpio
{
    struct __declspec(empty_bases) IGpioChangeCounter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGpioChangeCounter>,
        impl::require<winrt::Windows::Devices::Gpio::IGpioChangeCounter, winrt::Windows::Foundation::IClosable>
    {
        IGpioChangeCounter(std::nullptr_t = nullptr) noexcept {}
        IGpioChangeCounter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGpioChangeCounterFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGpioChangeCounterFactory>
    {
        IGpioChangeCounterFactory(std::nullptr_t = nullptr) noexcept {}
        IGpioChangeCounterFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGpioChangeReader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGpioChangeReader>,
        impl::require<winrt::Windows::Devices::Gpio::IGpioChangeReader, winrt::Windows::Foundation::IClosable>
    {
        IGpioChangeReader(std::nullptr_t = nullptr) noexcept {}
        IGpioChangeReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGpioChangeReaderFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGpioChangeReaderFactory>
    {
        IGpioChangeReaderFactory(std::nullptr_t = nullptr) noexcept {}
        IGpioChangeReaderFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGpioController :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGpioController>
    {
        IGpioController(std::nullptr_t = nullptr) noexcept {}
        IGpioController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGpioControllerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGpioControllerStatics>
    {
        IGpioControllerStatics(std::nullptr_t = nullptr) noexcept {}
        IGpioControllerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGpioControllerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGpioControllerStatics2>
    {
        IGpioControllerStatics2(std::nullptr_t = nullptr) noexcept {}
        IGpioControllerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGpioPin :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGpioPin>,
        impl::require<winrt::Windows::Devices::Gpio::IGpioPin, winrt::Windows::Foundation::IClosable>
    {
        IGpioPin(std::nullptr_t = nullptr) noexcept {}
        IGpioPin(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGpioPinValueChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGpioPinValueChangedEventArgs>
    {
        IGpioPinValueChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IGpioPinValueChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
