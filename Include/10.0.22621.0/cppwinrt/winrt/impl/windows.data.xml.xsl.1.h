// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Data_Xml_Xsl_1_H
#define WINRT_Windows_Data_Xml_Xsl_1_H
#include "winrt/impl/Windows.Data.Xml.Xsl.0.h"
WINRT_EXPORT namespace winrt::Windows::Data::Xml::Xsl
{
    struct __declspec(empty_bases) IXsltProcessor :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXsltProcessor>
    {
        IXsltProcessor(std::nullptr_t = nullptr) noexcept {}
        IXsltProcessor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXsltProcessor2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXsltProcessor2>
    {
        IXsltProcessor2(std::nullptr_t = nullptr) noexcept {}
        IXsltProcessor2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXsltProcessorFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXsltProcessorFactory>
    {
        IXsltProcessorFactory(std::nullptr_t = nullptr) noexcept {}
        IXsltProcessorFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
