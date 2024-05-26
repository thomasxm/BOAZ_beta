// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Cryptography_DataProtection_2_H
#define WINRT_Windows_Security_Cryptography_DataProtection_2_H
#include "winrt/impl/Windows.Security.Cryptography.DataProtection.1.h"
WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::DataProtection
{
    struct __declspec(empty_bases) DataProtectionProvider : winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProvider
    {
        DataProtectionProvider(std::nullptr_t) noexcept {}
        DataProtectionProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProvider(ptr, take_ownership_from_abi) {}
        DataProtectionProvider();
        explicit DataProtectionProvider(param::hstring const& protectionDescriptor);
    };
}
#endif
