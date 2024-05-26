// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Notifications_Management_1_H
#define WINRT_Windows_UI_Notifications_Management_1_H
#include "winrt/impl/Windows.UI.Notifications.Management.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Notifications::Management
{
    struct __declspec(empty_bases) IUserNotificationListener :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserNotificationListener>
    {
        IUserNotificationListener(std::nullptr_t = nullptr) noexcept {}
        IUserNotificationListener(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserNotificationListenerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserNotificationListenerStatics>
    {
        IUserNotificationListenerStatics(std::nullptr_t = nullptr) noexcept {}
        IUserNotificationListenerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
