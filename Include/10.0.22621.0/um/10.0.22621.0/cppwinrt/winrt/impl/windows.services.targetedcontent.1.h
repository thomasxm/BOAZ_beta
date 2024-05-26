// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Services_TargetedContent_1_H
#define WINRT_Windows_Services_TargetedContent_1_H
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Services.TargetedContent.0.h"
WINRT_EXPORT namespace winrt::Windows::Services::TargetedContent
{
    struct __declspec(empty_bases) ITargetedContentAction :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentAction>
    {
        ITargetedContentAction(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentAction(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentAvailabilityChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentAvailabilityChangedEventArgs>
    {
        ITargetedContentAvailabilityChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentAvailabilityChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentChangedEventArgs>
    {
        ITargetedContentChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentCollection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentCollection>
    {
        ITargetedContentCollection(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentCollection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentContainer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentContainer>
    {
        ITargetedContentContainer(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentContainer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentContainerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentContainerStatics>
    {
        ITargetedContentContainerStatics(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentContainerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentImage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentImage>,
        impl::require<winrt::Windows::Services::TargetedContent::ITargetedContentImage, winrt::Windows::Storage::Streams::IRandomAccessStreamReference>
    {
        ITargetedContentImage(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentImage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentItem :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentItem>
    {
        ITargetedContentItem(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentItemState :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentItemState>
    {
        ITargetedContentItemState(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentItemState(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentObject :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentObject>
    {
        ITargetedContentObject(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentObject(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentStateChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentStateChangedEventArgs>
    {
        ITargetedContentStateChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentStateChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentSubscription :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentSubscription>
    {
        ITargetedContentSubscription(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentSubscription(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentSubscriptionOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentSubscriptionOptions>
    {
        ITargetedContentSubscriptionOptions(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentSubscriptionOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentSubscriptionStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentSubscriptionStatics>
    {
        ITargetedContentSubscriptionStatics(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentSubscriptionStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetedContentValue :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetedContentValue>
    {
        ITargetedContentValue(std::nullptr_t = nullptr) noexcept {}
        ITargetedContentValue(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
