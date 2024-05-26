// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_ContentRestrictions_2_H
#define WINRT_Windows_Media_ContentRestrictions_2_H
#include "winrt/impl/Windows.Media.ContentRestrictions.1.h"
WINRT_EXPORT namespace winrt::Windows::Media::ContentRestrictions
{
    struct __declspec(empty_bases) ContentRestrictionsBrowsePolicy : winrt::Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy
    {
        ContentRestrictionsBrowsePolicy(std::nullptr_t) noexcept {}
        ContentRestrictionsBrowsePolicy(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RatedContentDescription : winrt::Windows::Media::ContentRestrictions::IRatedContentDescription
    {
        RatedContentDescription(std::nullptr_t) noexcept {}
        RatedContentDescription(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::ContentRestrictions::IRatedContentDescription(ptr, take_ownership_from_abi) {}
        RatedContentDescription(param::hstring const& id, param::hstring const& title, winrt::Windows::Media::ContentRestrictions::RatedContentCategory const& category);
    };
    struct __declspec(empty_bases) RatedContentRestrictions : winrt::Windows::Media::ContentRestrictions::IRatedContentRestrictions
    {
        RatedContentRestrictions(std::nullptr_t) noexcept {}
        RatedContentRestrictions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::ContentRestrictions::IRatedContentRestrictions(ptr, take_ownership_from_abi) {}
        RatedContentRestrictions();
        explicit RatedContentRestrictions(uint32_t maxAgeRating);
    };
}
#endif
