// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_ContentRestrictions_1_H
#define WINRT_Windows_Media_ContentRestrictions_1_H
#include "winrt/impl/Windows.Media.ContentRestrictions.0.h"
WINRT_EXPORT namespace winrt::Windows::Media::ContentRestrictions
{
    struct __declspec(empty_bases) IContentRestrictionsBrowsePolicy :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContentRestrictionsBrowsePolicy>
    {
        IContentRestrictionsBrowsePolicy(std::nullptr_t = nullptr) noexcept {}
        IContentRestrictionsBrowsePolicy(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRatedContentDescription :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRatedContentDescription>
    {
        IRatedContentDescription(std::nullptr_t = nullptr) noexcept {}
        IRatedContentDescription(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRatedContentDescriptionFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRatedContentDescriptionFactory>
    {
        IRatedContentDescriptionFactory(std::nullptr_t = nullptr) noexcept {}
        IRatedContentDescriptionFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRatedContentRestrictions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRatedContentRestrictions>
    {
        IRatedContentRestrictions(std::nullptr_t = nullptr) noexcept {}
        IRatedContentRestrictions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRatedContentRestrictionsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRatedContentRestrictionsFactory>
    {
        IRatedContentRestrictionsFactory(std::nullptr_t = nullptr) noexcept {}
        IRatedContentRestrictionsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
