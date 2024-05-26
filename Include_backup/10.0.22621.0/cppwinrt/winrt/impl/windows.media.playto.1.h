// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_PlayTo_1_H
#define WINRT_Windows_Media_PlayTo_1_H
#include "winrt/impl/Windows.Media.PlayTo.0.h"
WINRT_EXPORT namespace winrt::Windows::Media::PlayTo
{
    struct __declspec(empty_bases) ICurrentTimeChangeRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICurrentTimeChangeRequestedEventArgs>
    {
        ICurrentTimeChangeRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICurrentTimeChangeRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMuteChangeRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMuteChangeRequestedEventArgs>
    {
        IMuteChangeRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IMuteChangeRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToConnection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToConnection>
    {
        IPlayToConnection(std::nullptr_t = nullptr) noexcept {}
        IPlayToConnection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToConnectionErrorEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToConnectionErrorEventArgs>
    {
        IPlayToConnectionErrorEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPlayToConnectionErrorEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToConnectionStateChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToConnectionStateChangedEventArgs>
    {
        IPlayToConnectionStateChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPlayToConnectionStateChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToConnectionTransferredEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToConnectionTransferredEventArgs>
    {
        IPlayToConnectionTransferredEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPlayToConnectionTransferredEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToManager>
    {
        IPlayToManager(std::nullptr_t = nullptr) noexcept {}
        IPlayToManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToManagerStatics>
    {
        IPlayToManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IPlayToManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToReceiver :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToReceiver>
    {
        IPlayToReceiver(std::nullptr_t = nullptr) noexcept {}
        IPlayToReceiver(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToSource>
    {
        IPlayToSource(std::nullptr_t = nullptr) noexcept {}
        IPlayToSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToSourceDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToSourceDeferral>
    {
        IPlayToSourceDeferral(std::nullptr_t = nullptr) noexcept {}
        IPlayToSourceDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToSourceRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToSourceRequest>
    {
        IPlayToSourceRequest(std::nullptr_t = nullptr) noexcept {}
        IPlayToSourceRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToSourceRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToSourceRequestedEventArgs>
    {
        IPlayToSourceRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPlayToSourceRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToSourceSelectedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToSourceSelectedEventArgs>
    {
        IPlayToSourceSelectedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPlayToSourceSelectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayToSourceWithPreferredSourceUri :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayToSourceWithPreferredSourceUri>
    {
        IPlayToSourceWithPreferredSourceUri(std::nullptr_t = nullptr) noexcept {}
        IPlayToSourceWithPreferredSourceUri(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlaybackRateChangeRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlaybackRateChangeRequestedEventArgs>
    {
        IPlaybackRateChangeRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPlaybackRateChangeRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISourceChangeRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISourceChangeRequestedEventArgs>
    {
        ISourceChangeRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISourceChangeRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVolumeChangeRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVolumeChangeRequestedEventArgs>
    {
        IVolumeChangeRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IVolumeChangeRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
