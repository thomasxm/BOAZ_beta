// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_SerialCommunication_1_H
#define WINRT_Windows_Devices_SerialCommunication_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.SerialCommunication.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::SerialCommunication
{
    struct __declspec(empty_bases) IErrorReceivedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IErrorReceivedEventArgs>
    {
        IErrorReceivedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IErrorReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPinChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPinChangedEventArgs>
    {
        IPinChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPinChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISerialDevice :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISerialDevice>,
        impl::require<winrt::Windows::Devices::SerialCommunication::ISerialDevice, winrt::Windows::Foundation::IClosable>
    {
        ISerialDevice(std::nullptr_t = nullptr) noexcept {}
        ISerialDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISerialDeviceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISerialDeviceStatics>
    {
        ISerialDeviceStatics(std::nullptr_t = nullptr) noexcept {}
        ISerialDeviceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
