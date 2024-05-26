// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Printing_1_H
#define WINRT_Windows_UI_Xaml_Printing_1_H
#include "winrt/impl/Windows.UI.Xaml.Printing.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Printing
{
    struct __declspec(empty_bases) IAddPagesEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAddPagesEventArgs>
    {
        IAddPagesEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAddPagesEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGetPreviewPageEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGetPreviewPageEventArgs>
    {
        IGetPreviewPageEventArgs(std::nullptr_t = nullptr) noexcept {}
        IGetPreviewPageEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaginateEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaginateEventArgs>
    {
        IPaginateEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPaginateEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintDocument :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintDocument>
    {
        IPrintDocument(std::nullptr_t = nullptr) noexcept {}
        IPrintDocument(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintDocumentFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintDocumentFactory>
    {
        IPrintDocumentFactory(std::nullptr_t = nullptr) noexcept {}
        IPrintDocumentFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintDocumentStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintDocumentStatics>
    {
        IPrintDocumentStatics(std::nullptr_t = nullptr) noexcept {}
        IPrintDocumentStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
