// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_DateTimeFormatting_1_H
#define WINRT_Windows_Globalization_DateTimeFormatting_1_H
#include "winrt/impl/Windows.Globalization.DateTimeFormatting.0.h"
WINRT_EXPORT namespace winrt::Windows::Globalization::DateTimeFormatting
{
    struct __declspec(empty_bases) IDateTimeFormatter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDateTimeFormatter>
    {
        IDateTimeFormatter(std::nullptr_t = nullptr) noexcept {}
        IDateTimeFormatter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDateTimeFormatter2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDateTimeFormatter2>
    {
        IDateTimeFormatter2(std::nullptr_t = nullptr) noexcept {}
        IDateTimeFormatter2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDateTimeFormatterFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDateTimeFormatterFactory>
    {
        IDateTimeFormatterFactory(std::nullptr_t = nullptr) noexcept {}
        IDateTimeFormatterFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDateTimeFormatterStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDateTimeFormatterStatics>
    {
        IDateTimeFormatterStatics(std::nullptr_t = nullptr) noexcept {}
        IDateTimeFormatterStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
