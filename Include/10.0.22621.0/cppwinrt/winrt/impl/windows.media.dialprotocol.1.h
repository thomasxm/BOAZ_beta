// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_DialProtocol_1_H
#define WINRT_Windows_Media_DialProtocol_1_H
#include "winrt/impl/Windows.Media.DialProtocol.0.h"
WINRT_EXPORT namespace winrt::Windows::Media::DialProtocol
{
    struct __declspec(empty_bases) IDialApp :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialApp>
    {
        IDialApp(std::nullptr_t = nullptr) noexcept {}
        IDialApp(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDialAppStateDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialAppStateDetails>
    {
        IDialAppStateDetails(std::nullptr_t = nullptr) noexcept {}
        IDialAppStateDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDialDevice :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialDevice>
    {
        IDialDevice(std::nullptr_t = nullptr) noexcept {}
        IDialDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDialDevice2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialDevice2>
    {
        IDialDevice2(std::nullptr_t = nullptr) noexcept {}
        IDialDevice2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDialDevicePicker :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialDevicePicker>
    {
        IDialDevicePicker(std::nullptr_t = nullptr) noexcept {}
        IDialDevicePicker(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDialDevicePickerFilter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialDevicePickerFilter>
    {
        IDialDevicePickerFilter(std::nullptr_t = nullptr) noexcept {}
        IDialDevicePickerFilter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDialDeviceSelectedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialDeviceSelectedEventArgs>
    {
        IDialDeviceSelectedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IDialDeviceSelectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDialDeviceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialDeviceStatics>
    {
        IDialDeviceStatics(std::nullptr_t = nullptr) noexcept {}
        IDialDeviceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDialDisconnectButtonClickedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialDisconnectButtonClickedEventArgs>
    {
        IDialDisconnectButtonClickedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IDialDisconnectButtonClickedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDialReceiverApp :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialReceiverApp>
    {
        IDialReceiverApp(std::nullptr_t = nullptr) noexcept {}
        IDialReceiverApp(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDialReceiverApp2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialReceiverApp2>
    {
        IDialReceiverApp2(std::nullptr_t = nullptr) noexcept {}
        IDialReceiverApp2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDialReceiverAppStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDialReceiverAppStatics>
    {
        IDialReceiverAppStatics(std::nullptr_t = nullptr) noexcept {}
        IDialReceiverAppStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
