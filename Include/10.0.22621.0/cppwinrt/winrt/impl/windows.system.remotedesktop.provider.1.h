// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_RemoteDesktop_Provider_1_H
#define WINRT_Windows_System_RemoteDesktop_Provider_1_H
#include "winrt/impl/Windows.System.RemoteDesktop.Provider.0.h"
WINRT_EXPORT namespace winrt::Windows::System::RemoteDesktop::Provider
{
    struct __declspec(empty_bases) IPerformLocalActionRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerformLocalActionRequestedEventArgs>
    {
        IPerformLocalActionRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPerformLocalActionRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteDesktopConnectionInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteDesktopConnectionInfo>
    {
        IRemoteDesktopConnectionInfo(std::nullptr_t = nullptr) noexcept {}
        IRemoteDesktopConnectionInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteDesktopConnectionInfoStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteDesktopConnectionInfoStatics>
    {
        IRemoteDesktopConnectionInfoStatics(std::nullptr_t = nullptr) noexcept {}
        IRemoteDesktopConnectionInfoStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteDesktopConnectionRemoteInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteDesktopConnectionRemoteInfo>
    {
        IRemoteDesktopConnectionRemoteInfo(std::nullptr_t = nullptr) noexcept {}
        IRemoteDesktopConnectionRemoteInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteDesktopConnectionRemoteInfoStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteDesktopConnectionRemoteInfoStatics>
    {
        IRemoteDesktopConnectionRemoteInfoStatics(std::nullptr_t = nullptr) noexcept {}
        IRemoteDesktopConnectionRemoteInfoStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteDesktopInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteDesktopInfo>
    {
        IRemoteDesktopInfo(std::nullptr_t = nullptr) noexcept {}
        IRemoteDesktopInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteDesktopInfoFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteDesktopInfoFactory>
    {
        IRemoteDesktopInfoFactory(std::nullptr_t = nullptr) noexcept {}
        IRemoteDesktopInfoFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteDesktopRegistrarStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteDesktopRegistrarStatics>
    {
        IRemoteDesktopRegistrarStatics(std::nullptr_t = nullptr) noexcept {}
        IRemoteDesktopRegistrarStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
