// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Gpio_2_H
#define WINRT_Windows_Devices_Gpio_2_H
#include "winrt/impl/Windows.Devices.Gpio.Provider.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Gpio.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Gpio
{
    struct GpioChangeCount
    {
        uint64_t Count;
        winrt::Windows::Foundation::TimeSpan RelativeTime;
    };
    inline bool operator==(GpioChangeCount const& left, GpioChangeCount const& right) noexcept
    {
        return left.Count == right.Count && left.RelativeTime == right.RelativeTime;
    }
    inline bool operator!=(GpioChangeCount const& left, GpioChangeCount const& right) noexcept
    {
        return !(left == right);
    }
    struct GpioChangeRecord
    {
        winrt::Windows::Foundation::TimeSpan RelativeTime;
        winrt::Windows::Devices::Gpio::GpioPinEdge Edge;
    };
    inline bool operator==(GpioChangeRecord const& left, GpioChangeRecord const& right) noexcept
    {
        return left.RelativeTime == right.RelativeTime && left.Edge == right.Edge;
    }
    inline bool operator!=(GpioChangeRecord const& left, GpioChangeRecord const& right) noexcept
    {
        return !(left == right);
    }
    struct __declspec(empty_bases) GpioChangeCounter : winrt::Windows::Devices::Gpio::IGpioChangeCounter
    {
        GpioChangeCounter(std::nullptr_t) noexcept {}
        GpioChangeCounter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Gpio::IGpioChangeCounter(ptr, take_ownership_from_abi) {}
        explicit GpioChangeCounter(winrt::Windows::Devices::Gpio::GpioPin const& pin);
    };
    struct __declspec(empty_bases) GpioChangeReader : winrt::Windows::Devices::Gpio::IGpioChangeReader
    {
        GpioChangeReader(std::nullptr_t) noexcept {}
        GpioChangeReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Gpio::IGpioChangeReader(ptr, take_ownership_from_abi) {}
        explicit GpioChangeReader(winrt::Windows::Devices::Gpio::GpioPin const& pin);
        GpioChangeReader(winrt::Windows::Devices::Gpio::GpioPin const& pin, int32_t minCapacity);
    };
    struct __declspec(empty_bases) GpioController : winrt::Windows::Devices::Gpio::IGpioController
    {
        GpioController(std::nullptr_t) noexcept {}
        GpioController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Gpio::IGpioController(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
        static auto GetControllersAsync(winrt::Windows::Devices::Gpio::Provider::IGpioProvider const& provider);
        static auto GetDefaultAsync();
    };
    struct __declspec(empty_bases) GpioPin : winrt::Windows::Devices::Gpio::IGpioPin
    {
        GpioPin(std::nullptr_t) noexcept {}
        GpioPin(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Gpio::IGpioPin(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) GpioPinValueChangedEventArgs : winrt::Windows::Devices::Gpio::IGpioPinValueChangedEventArgs
    {
        GpioPinValueChangedEventArgs(std::nullptr_t) noexcept {}
        GpioPinValueChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Gpio::IGpioPinValueChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
