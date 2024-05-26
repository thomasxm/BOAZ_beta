// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Data_Pdf_2_H
#define WINRT_Windows_Data_Pdf_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Data.Pdf.1.h"
WINRT_EXPORT namespace winrt::Windows::Data::Pdf
{
    struct __declspec(empty_bases) PdfDocument : winrt::Windows::Data::Pdf::IPdfDocument
    {
        PdfDocument(std::nullptr_t) noexcept {}
        PdfDocument(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Pdf::IPdfDocument(ptr, take_ownership_from_abi) {}
        static auto LoadFromFileAsync(winrt::Windows::Storage::IStorageFile const& file);
        static auto LoadFromFileAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& password);
        static auto LoadFromStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& inputStream);
        static auto LoadFromStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& inputStream, param::hstring const& password);
    };
    struct __declspec(empty_bases) PdfPage : winrt::Windows::Data::Pdf::IPdfPage,
        impl::require<PdfPage, winrt::Windows::Foundation::IClosable>
    {
        PdfPage(std::nullptr_t) noexcept {}
        PdfPage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Pdf::IPdfPage(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PdfPageDimensions : winrt::Windows::Data::Pdf::IPdfPageDimensions
    {
        PdfPageDimensions(std::nullptr_t) noexcept {}
        PdfPageDimensions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Pdf::IPdfPageDimensions(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PdfPageRenderOptions : winrt::Windows::Data::Pdf::IPdfPageRenderOptions
    {
        PdfPageRenderOptions(std::nullptr_t) noexcept {}
        PdfPageRenderOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Pdf::IPdfPageRenderOptions(ptr, take_ownership_from_abi) {}
        PdfPageRenderOptions();
    };
}
#endif
