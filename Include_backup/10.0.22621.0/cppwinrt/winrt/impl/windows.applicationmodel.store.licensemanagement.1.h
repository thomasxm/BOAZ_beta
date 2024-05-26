// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Store_LicenseManagement_1_H
#define WINRT_Windows_ApplicationModel_Store_LicenseManagement_1_H
#include "winrt/impl/Windows.ApplicationModel.Store.LicenseManagement.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store::LicenseManagement
{
    struct __declspec(empty_bases) ILicenseManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILicenseManagerStatics>
    {
        ILicenseManagerStatics(std::nullptr_t = nullptr) noexcept {}
        ILicenseManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILicenseManagerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILicenseManagerStatics2>
    {
        ILicenseManagerStatics2(std::nullptr_t = nullptr) noexcept {}
        ILicenseManagerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILicenseSatisfactionInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILicenseSatisfactionInfo>
    {
        ILicenseSatisfactionInfo(std::nullptr_t = nullptr) noexcept {}
        ILicenseSatisfactionInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILicenseSatisfactionResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILicenseSatisfactionResult>
    {
        ILicenseSatisfactionResult(std::nullptr_t = nullptr) noexcept {}
        ILicenseSatisfactionResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
