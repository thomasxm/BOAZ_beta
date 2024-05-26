// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_LockScreen_1_H
#define WINRT_Windows_ApplicationModel_LockScreen_1_H
#include "winrt/impl/Windows.ApplicationModel.LockScreen.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::LockScreen
{
    struct __declspec(empty_bases) ILockApplicationHost :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILockApplicationHost>
    {
        ILockApplicationHost(std::nullptr_t = nullptr) noexcept {}
        ILockApplicationHost(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILockApplicationHostStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILockApplicationHostStatics>
    {
        ILockApplicationHostStatics(std::nullptr_t = nullptr) noexcept {}
        ILockApplicationHostStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILockScreenBadge :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILockScreenBadge>
    {
        ILockScreenBadge(std::nullptr_t = nullptr) noexcept {}
        ILockScreenBadge(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILockScreenInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILockScreenInfo>
    {
        ILockScreenInfo(std::nullptr_t = nullptr) noexcept {}
        ILockScreenInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILockScreenUnlockingDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILockScreenUnlockingDeferral>
    {
        ILockScreenUnlockingDeferral(std::nullptr_t = nullptr) noexcept {}
        ILockScreenUnlockingDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILockScreenUnlockingEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILockScreenUnlockingEventArgs>
    {
        ILockScreenUnlockingEventArgs(std::nullptr_t = nullptr) noexcept {}
        ILockScreenUnlockingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
