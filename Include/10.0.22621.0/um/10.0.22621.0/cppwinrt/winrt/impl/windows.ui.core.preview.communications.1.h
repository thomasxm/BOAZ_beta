// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Core_Preview_Communications_1_H
#define WINRT_Windows_UI_Core_Preview_Communications_1_H
#include "winrt/impl/Windows.UI.Core.Preview.Communications.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Core::Preview::Communications
{
    struct __declspec(empty_bases) IPreviewTeamCleanupRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPreviewTeamCleanupRequestedEventArgs>
    {
        IPreviewTeamCleanupRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPreviewTeamCleanupRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPreviewTeamCommandInvokedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPreviewTeamCommandInvokedEventArgs>
    {
        IPreviewTeamCommandInvokedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPreviewTeamCommandInvokedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPreviewTeamDeviceCredentials :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPreviewTeamDeviceCredentials>
    {
        IPreviewTeamDeviceCredentials(std::nullptr_t = nullptr) noexcept {}
        IPreviewTeamDeviceCredentials(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPreviewTeamEndMeetingRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPreviewTeamEndMeetingRequestedEventArgs>
    {
        IPreviewTeamEndMeetingRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPreviewTeamEndMeetingRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPreviewTeamJoinMeetingRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPreviewTeamJoinMeetingRequestedEventArgs>
    {
        IPreviewTeamJoinMeetingRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPreviewTeamJoinMeetingRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPreviewTeamView :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPreviewTeamView>
    {
        IPreviewTeamView(std::nullptr_t = nullptr) noexcept {}
        IPreviewTeamView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPreviewTeamView2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPreviewTeamView2>
    {
        IPreviewTeamView2(std::nullptr_t = nullptr) noexcept {}
        IPreviewTeamView2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPreviewTeamViewStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPreviewTeamViewStatics>
    {
        IPreviewTeamViewStatics(std::nullptr_t = nullptr) noexcept {}
        IPreviewTeamViewStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
