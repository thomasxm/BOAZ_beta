// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_PhoneNumberFormatting_1_H
#define WINRT_Windows_Globalization_PhoneNumberFormatting_1_H
#include "winrt/impl/Windows.Globalization.PhoneNumberFormatting.0.h"
WINRT_EXPORT namespace winrt::Windows::Globalization::PhoneNumberFormatting
{
    struct __declspec(empty_bases) IPhoneNumberFormatter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneNumberFormatter>
    {
        IPhoneNumberFormatter(std::nullptr_t = nullptr) noexcept {}
        IPhoneNumberFormatter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneNumberFormatterStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneNumberFormatterStatics>
    {
        IPhoneNumberFormatterStatics(std::nullptr_t = nullptr) noexcept {}
        IPhoneNumberFormatterStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneNumberInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneNumberInfo>
    {
        IPhoneNumberInfo(std::nullptr_t = nullptr) noexcept {}
        IPhoneNumberInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneNumberInfoFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneNumberInfoFactory>
    {
        IPhoneNumberInfoFactory(std::nullptr_t = nullptr) noexcept {}
        IPhoneNumberInfoFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneNumberInfoStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneNumberInfoStatics>
    {
        IPhoneNumberInfoStatics(std::nullptr_t = nullptr) noexcept {}
        IPhoneNumberInfoStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
