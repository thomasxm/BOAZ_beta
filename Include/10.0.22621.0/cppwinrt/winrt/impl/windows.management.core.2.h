// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_Core_2_H
#define WINRT_Windows_Management_Core_2_H
#include "winrt/impl/Windows.Management.Core.1.h"
WINRT_EXPORT namespace winrt::Windows::Management::Core
{
    struct __declspec(empty_bases) ApplicationDataManager : winrt::Windows::Management::Core::IApplicationDataManager
    {
        ApplicationDataManager(std::nullptr_t) noexcept {}
        ApplicationDataManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Management::Core::IApplicationDataManager(ptr, take_ownership_from_abi) {}
        static auto CreateForPackageFamily(param::hstring const& packageFamilyName);
    };
}
#endif
