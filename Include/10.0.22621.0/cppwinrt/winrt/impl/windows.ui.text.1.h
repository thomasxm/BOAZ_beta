// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Text_1_H
#define WINRT_Windows_UI_Text_1_H
#include "winrt/impl/Windows.UI.Text.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Text
{
    struct __declspec(empty_bases) IContentLinkInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContentLinkInfo>
    {
        IContentLinkInfo(std::nullptr_t = nullptr) noexcept {}
        IContentLinkInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFontWeights :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFontWeights>
    {
        IFontWeights(std::nullptr_t = nullptr) noexcept {}
        IFontWeights(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFontWeightsStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFontWeightsStatics>
    {
        IFontWeightsStatics(std::nullptr_t = nullptr) noexcept {}
        IFontWeightsStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRichEditTextRange :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRichEditTextRange>
    {
        IRichEditTextRange(std::nullptr_t = nullptr) noexcept {}
        IRichEditTextRange(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITextCharacterFormat :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITextCharacterFormat>
    {
        ITextCharacterFormat(std::nullptr_t = nullptr) noexcept {}
        ITextCharacterFormat(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITextConstantsStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITextConstantsStatics>
    {
        ITextConstantsStatics(std::nullptr_t = nullptr) noexcept {}
        ITextConstantsStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITextDocument :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITextDocument>
    {
        ITextDocument(std::nullptr_t = nullptr) noexcept {}
        ITextDocument(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITextDocument2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITextDocument2>
    {
        ITextDocument2(std::nullptr_t = nullptr) noexcept {}
        ITextDocument2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITextDocument3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITextDocument3>
    {
        ITextDocument3(std::nullptr_t = nullptr) noexcept {}
        ITextDocument3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITextDocument4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITextDocument4>
    {
        ITextDocument4(std::nullptr_t = nullptr) noexcept {}
        ITextDocument4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITextParagraphFormat :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITextParagraphFormat>
    {
        ITextParagraphFormat(std::nullptr_t = nullptr) noexcept {}
        ITextParagraphFormat(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITextRange :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITextRange>
    {
        ITextRange(std::nullptr_t = nullptr) noexcept {}
        ITextRange(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITextSelection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITextSelection>,
        impl::require<winrt::Windows::UI::Text::ITextSelection, winrt::Windows::UI::Text::ITextRange>
    {
        ITextSelection(std::nullptr_t = nullptr) noexcept {}
        ITextSelection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
