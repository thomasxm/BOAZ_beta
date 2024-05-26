// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Text_2_H
#define WINRT_Windows_UI_Text_2_H
#include "winrt/impl/Windows.UI.Text.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Text
{
    struct FontWeight
    {
        uint16_t Weight;
    };
    inline bool operator==(FontWeight const& left, FontWeight const& right) noexcept
    {
        return left.Weight == right.Weight;
    }
    inline bool operator!=(FontWeight const& left, FontWeight const& right) noexcept
    {
        return !(left == right);
    }
    struct __declspec(empty_bases) ContentLinkInfo : winrt::Windows::UI::Text::IContentLinkInfo
    {
        ContentLinkInfo(std::nullptr_t) noexcept {}
        ContentLinkInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Text::IContentLinkInfo(ptr, take_ownership_from_abi) {}
        ContentLinkInfo();
    };
    struct __declspec(empty_bases) FontWeights : winrt::Windows::UI::Text::IFontWeights
    {
        FontWeights(std::nullptr_t) noexcept {}
        FontWeights(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Text::IFontWeights(ptr, take_ownership_from_abi) {}
        [[nodiscard]] static auto Black();
        [[nodiscard]] static auto Bold();
        [[nodiscard]] static auto ExtraBlack();
        [[nodiscard]] static auto ExtraBold();
        [[nodiscard]] static auto ExtraLight();
        [[nodiscard]] static auto Light();
        [[nodiscard]] static auto Medium();
        [[nodiscard]] static auto Normal();
        [[nodiscard]] static auto SemiBold();
        [[nodiscard]] static auto SemiLight();
        [[nodiscard]] static auto Thin();
    };
    struct __declspec(empty_bases) RichEditTextDocument : winrt::Windows::UI::Text::ITextDocument,
        impl::require<RichEditTextDocument, winrt::Windows::UI::Text::ITextDocument2, winrt::Windows::UI::Text::ITextDocument3, winrt::Windows::UI::Text::ITextDocument4>
    {
        RichEditTextDocument(std::nullptr_t) noexcept {}
        RichEditTextDocument(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Text::ITextDocument(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RichEditTextRange : winrt::Windows::UI::Text::ITextRange,
        impl::require<RichEditTextRange, winrt::Windows::UI::Text::IRichEditTextRange>
    {
        RichEditTextRange(std::nullptr_t) noexcept {}
        RichEditTextRange(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Text::ITextRange(ptr, take_ownership_from_abi) {}
    };
    struct TextConstants
    {
        TextConstants() = delete;
        [[nodiscard]] static auto AutoColor();
        [[nodiscard]] static auto MinUnitCount();
        [[nodiscard]] static auto MaxUnitCount();
        [[nodiscard]] static auto UndefinedColor();
        [[nodiscard]] static auto UndefinedFloatValue();
        [[nodiscard]] static auto UndefinedInt32Value();
        [[nodiscard]] static auto UndefinedFontStretch();
        [[nodiscard]] static auto UndefinedFontStyle();
    };
}
#endif
