// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Notifications_Management_2_H
#define WINRT_Windows_UI_Notifications_Management_2_H
#include "winrt/impl/Windows.UI.Notifications.Management.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Notifications::Management
{
    struct __declspec(empty_bases) UserNotificationListener : winrt::Windows::UI::Notifications::Management::IUserNotificationListener
    {
        UserNotificationListener(std::nullptr_t) noexcept {}
        UserNotificationListener(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::Management::IUserNotificationListener(ptr, take_ownership_from_abi) {}
        [[nodiscard]] static auto Current();
    };
}
#endif
