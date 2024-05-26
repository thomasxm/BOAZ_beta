// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_AppBroadcasting_2_H
#define WINRT_Windows_Media_AppBroadcasting_2_H
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Media.AppBroadcasting.1.h"
WINRT_EXPORT namespace winrt::Windows::Media::AppBroadcasting
{
    struct __declspec(empty_bases) AppBroadcastingMonitor : winrt::Windows::Media::AppBroadcasting::IAppBroadcastingMonitor
    {
        AppBroadcastingMonitor(std::nullptr_t) noexcept {}
        AppBroadcastingMonitor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::AppBroadcasting::IAppBroadcastingMonitor(ptr, take_ownership_from_abi) {}
        AppBroadcastingMonitor();
    };
    struct __declspec(empty_bases) AppBroadcastingStatus : winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatus
    {
        AppBroadcastingStatus(std::nullptr_t) noexcept {}
        AppBroadcastingStatus(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatus(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppBroadcastingStatusDetails : winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails
    {
        AppBroadcastingStatusDetails(std::nullptr_t) noexcept {}
        AppBroadcastingStatusDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppBroadcastingUI : winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUI
    {
        AppBroadcastingUI(std::nullptr_t) noexcept {}
        AppBroadcastingUI(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUI(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
}
#endif
