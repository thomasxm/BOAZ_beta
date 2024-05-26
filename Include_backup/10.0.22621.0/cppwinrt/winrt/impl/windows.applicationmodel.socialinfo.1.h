// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_SocialInfo_1_H
#define WINRT_Windows_ApplicationModel_SocialInfo_1_H
#include "winrt/impl/Windows.ApplicationModel.SocialInfo.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo
{
    struct __declspec(empty_bases) ISocialFeedChildItem :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISocialFeedChildItem>
    {
        ISocialFeedChildItem(std::nullptr_t = nullptr) noexcept {}
        ISocialFeedChildItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISocialFeedContent :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISocialFeedContent>
    {
        ISocialFeedContent(std::nullptr_t = nullptr) noexcept {}
        ISocialFeedContent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISocialFeedItem :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISocialFeedItem>
    {
        ISocialFeedItem(std::nullptr_t = nullptr) noexcept {}
        ISocialFeedItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISocialFeedSharedItem :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISocialFeedSharedItem>
    {
        ISocialFeedSharedItem(std::nullptr_t = nullptr) noexcept {}
        ISocialFeedSharedItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISocialItemThumbnail :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISocialItemThumbnail>
    {
        ISocialItemThumbnail(std::nullptr_t = nullptr) noexcept {}
        ISocialItemThumbnail(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISocialUserInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISocialUserInfo>
    {
        ISocialUserInfo(std::nullptr_t = nullptr) noexcept {}
        ISocialUserInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
