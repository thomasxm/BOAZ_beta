// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_ClosedCaptioning_1_H
#define WINRT_Windows_Media_ClosedCaptioning_1_H
#include "winrt/impl/Windows.Media.ClosedCaptioning.0.h"
WINRT_EXPORT namespace winrt::Windows::Media::ClosedCaptioning
{
    struct __declspec(empty_bases) IClosedCaptionPropertiesStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IClosedCaptionPropertiesStatics>
    {
        IClosedCaptionPropertiesStatics(std::nullptr_t = nullptr) noexcept {}
        IClosedCaptionPropertiesStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IClosedCaptionPropertiesStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IClosedCaptionPropertiesStatics2>
    {
        IClosedCaptionPropertiesStatics2(std::nullptr_t = nullptr) noexcept {}
        IClosedCaptionPropertiesStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
