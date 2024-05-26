// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Data_Pdf_1_H
#define WINRT_Windows_Data_Pdf_1_H
#include "winrt/impl/Windows.Data.Pdf.0.h"
WINRT_EXPORT namespace winrt::Windows::Data::Pdf
{
    struct __declspec(empty_bases) IPdfDocument :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPdfDocument>
    {
        IPdfDocument(std::nullptr_t = nullptr) noexcept {}
        IPdfDocument(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPdfDocumentStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPdfDocumentStatics>
    {
        IPdfDocumentStatics(std::nullptr_t = nullptr) noexcept {}
        IPdfDocumentStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPdfPage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPdfPage>
    {
        IPdfPage(std::nullptr_t = nullptr) noexcept {}
        IPdfPage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPdfPageDimensions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPdfPageDimensions>
    {
        IPdfPageDimensions(std::nullptr_t = nullptr) noexcept {}
        IPdfPageDimensions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPdfPageRenderOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPdfPageRenderOptions>
    {
        IPdfPageRenderOptions(std::nullptr_t = nullptr) noexcept {}
        IPdfPageRenderOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
