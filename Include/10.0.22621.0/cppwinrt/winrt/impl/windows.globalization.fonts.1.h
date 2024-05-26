// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_Fonts_1_H
#define WINRT_Windows_Globalization_Fonts_1_H
#include "winrt/impl/Windows.Globalization.Fonts.0.h"
WINRT_EXPORT namespace winrt::Windows::Globalization::Fonts
{
    struct __declspec(empty_bases) ILanguageFont :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILanguageFont>
    {
        ILanguageFont(std::nullptr_t = nullptr) noexcept {}
        ILanguageFont(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILanguageFontGroup :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILanguageFontGroup>
    {
        ILanguageFontGroup(std::nullptr_t = nullptr) noexcept {}
        ILanguageFontGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILanguageFontGroupFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILanguageFontGroupFactory>
    {
        ILanguageFontGroupFactory(std::nullptr_t = nullptr) noexcept {}
        ILanguageFontGroupFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
