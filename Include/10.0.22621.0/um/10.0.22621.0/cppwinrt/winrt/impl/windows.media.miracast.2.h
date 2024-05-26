// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Miracast_2_H
#define WINRT_Windows_Media_Miracast_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Media.Miracast.1.h"
WINRT_EXPORT namespace winrt::Windows::Media::Miracast
{
    struct __declspec(empty_bases) MiracastReceiver : winrt::Windows::Media::Miracast::IMiracastReceiver
    {
        MiracastReceiver(std::nullptr_t) noexcept {}
        MiracastReceiver(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiver(ptr, take_ownership_from_abi) {}
        MiracastReceiver();
    };
    struct __declspec(empty_bases) MiracastReceiverApplySettingsResult : winrt::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult
    {
        MiracastReceiverApplySettingsResult(std::nullptr_t) noexcept {}
        MiracastReceiverApplySettingsResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverConnection : winrt::Windows::Media::Miracast::IMiracastReceiverConnection,
        impl::require<MiracastReceiverConnection, winrt::Windows::Foundation::IClosable>
    {
        MiracastReceiverConnection(std::nullptr_t) noexcept {}
        MiracastReceiverConnection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverConnection(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverConnectionCreatedEventArgs : winrt::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs
    {
        MiracastReceiverConnectionCreatedEventArgs(std::nullptr_t) noexcept {}
        MiracastReceiverConnectionCreatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverCursorImageChannel : winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel
    {
        MiracastReceiverCursorImageChannel(std::nullptr_t) noexcept {}
        MiracastReceiverCursorImageChannel(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverCursorImageChannelSettings : winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings
    {
        MiracastReceiverCursorImageChannelSettings(std::nullptr_t) noexcept {}
        MiracastReceiverCursorImageChannelSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverDisconnectedEventArgs : winrt::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs
    {
        MiracastReceiverDisconnectedEventArgs(std::nullptr_t) noexcept {}
        MiracastReceiverDisconnectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverGameControllerDevice : winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice
    {
        MiracastReceiverGameControllerDevice(std::nullptr_t) noexcept {}
        MiracastReceiverGameControllerDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverInputDevices : winrt::Windows::Media::Miracast::IMiracastReceiverInputDevices
    {
        MiracastReceiverInputDevices(std::nullptr_t) noexcept {}
        MiracastReceiverInputDevices(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverInputDevices(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverKeyboardDevice : winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice
    {
        MiracastReceiverKeyboardDevice(std::nullptr_t) noexcept {}
        MiracastReceiverKeyboardDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverMediaSourceCreatedEventArgs : winrt::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs
    {
        MiracastReceiverMediaSourceCreatedEventArgs(std::nullptr_t) noexcept {}
        MiracastReceiverMediaSourceCreatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverSession : winrt::Windows::Media::Miracast::IMiracastReceiverSession,
        impl::require<MiracastReceiverSession, winrt::Windows::Foundation::IClosable>
    {
        MiracastReceiverSession(std::nullptr_t) noexcept {}
        MiracastReceiverSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverSession(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverSessionStartResult : winrt::Windows::Media::Miracast::IMiracastReceiverSessionStartResult
    {
        MiracastReceiverSessionStartResult(std::nullptr_t) noexcept {}
        MiracastReceiverSessionStartResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverSessionStartResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverSettings : winrt::Windows::Media::Miracast::IMiracastReceiverSettings
    {
        MiracastReceiverSettings(std::nullptr_t) noexcept {}
        MiracastReceiverSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverSettings(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverStatus : winrt::Windows::Media::Miracast::IMiracastReceiverStatus
    {
        MiracastReceiverStatus(std::nullptr_t) noexcept {}
        MiracastReceiverStatus(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverStatus(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverStreamControl : winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl
    {
        MiracastReceiverStreamControl(std::nullptr_t) noexcept {}
        MiracastReceiverStreamControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastReceiverVideoStreamSettings : winrt::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings
    {
        MiracastReceiverVideoStreamSettings(std::nullptr_t) noexcept {}
        MiracastReceiverVideoStreamSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MiracastTransmitter : winrt::Windows::Media::Miracast::IMiracastTransmitter
    {
        MiracastTransmitter(std::nullptr_t) noexcept {}
        MiracastTransmitter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Miracast::IMiracastTransmitter(ptr, take_ownership_from_abi) {}
    };
}
#endif
