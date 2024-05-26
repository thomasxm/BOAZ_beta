// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Cryptography_DataProtection_1_H
#define WINRT_Windows_Security_Cryptography_DataProtection_1_H
#include "winrt/impl/Windows.Security.Cryptography.DataProtection.0.h"
WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::DataProtection
{
    struct __declspec(empty_bases) IDataProtectionProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDataProtectionProvider>
    {
        IDataProtectionProvider(std::nullptr_t = nullptr) noexcept {}
        IDataProtectionProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDataProtectionProviderFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDataProtectionProviderFactory>
    {
        IDataProtectionProviderFactory(std::nullptr_t = nullptr) noexcept {}
        IDataProtectionProviderFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
