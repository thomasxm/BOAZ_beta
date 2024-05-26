// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Control_1_H
#define WINRT_Windows_Media_Control_1_H
#include "winrt/impl/Windows.Media.Control.0.h"
WINRT_EXPORT namespace winrt::Windows::Media::Control
{
    struct __declspec(empty_bases) ICurrentSessionChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICurrentSessionChangedEventArgs>
    {
        ICurrentSessionChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICurrentSessionChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGlobalSystemMediaTransportControlsSession :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGlobalSystemMediaTransportControlsSession>
    {
        IGlobalSystemMediaTransportControlsSession(std::nullptr_t = nullptr) noexcept {}
        IGlobalSystemMediaTransportControlsSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGlobalSystemMediaTransportControlsSessionManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGlobalSystemMediaTransportControlsSessionManager>
    {
        IGlobalSystemMediaTransportControlsSessionManager(std::nullptr_t = nullptr) noexcept {}
        IGlobalSystemMediaTransportControlsSessionManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGlobalSystemMediaTransportControlsSessionManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGlobalSystemMediaTransportControlsSessionManagerStatics>
    {
        IGlobalSystemMediaTransportControlsSessionManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IGlobalSystemMediaTransportControlsSessionManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGlobalSystemMediaTransportControlsSessionMediaProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGlobalSystemMediaTransportControlsSessionMediaProperties>
    {
        IGlobalSystemMediaTransportControlsSessionMediaProperties(std::nullptr_t = nullptr) noexcept {}
        IGlobalSystemMediaTransportControlsSessionMediaProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGlobalSystemMediaTransportControlsSessionPlaybackControls :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGlobalSystemMediaTransportControlsSessionPlaybackControls>
    {
        IGlobalSystemMediaTransportControlsSessionPlaybackControls(std::nullptr_t = nullptr) noexcept {}
        IGlobalSystemMediaTransportControlsSessionPlaybackControls(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGlobalSystemMediaTransportControlsSessionPlaybackInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGlobalSystemMediaTransportControlsSessionPlaybackInfo>
    {
        IGlobalSystemMediaTransportControlsSessionPlaybackInfo(std::nullptr_t = nullptr) noexcept {}
        IGlobalSystemMediaTransportControlsSessionPlaybackInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGlobalSystemMediaTransportControlsSessionTimelineProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGlobalSystemMediaTransportControlsSessionTimelineProperties>
    {
        IGlobalSystemMediaTransportControlsSessionTimelineProperties(std::nullptr_t = nullptr) noexcept {}
        IGlobalSystemMediaTransportControlsSessionTimelineProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMediaPropertiesChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMediaPropertiesChangedEventArgs>
    {
        IMediaPropertiesChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IMediaPropertiesChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlaybackInfoChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlaybackInfoChangedEventArgs>
    {
        IPlaybackInfoChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPlaybackInfoChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISessionsChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISessionsChangedEventArgs>
    {
        ISessionsChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISessionsChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITimelinePropertiesChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITimelinePropertiesChangedEventArgs>
    {
        ITimelinePropertiesChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ITimelinePropertiesChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
