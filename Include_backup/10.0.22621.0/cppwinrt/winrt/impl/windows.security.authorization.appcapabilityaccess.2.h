// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Authorization_AppCapabilityAccess_2_H
#define WINRT_Windows_Security_Authorization_AppCapabilityAccess_2_H
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Security.Authorization.AppCapabilityAccess.1.h"
WINRT_EXPORT namespace winrt::Windows::Security::Authorization::AppCapabilityAccess
{
    struct __declspec(empty_bases) AppCapability : winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability,
        impl::require<AppCapability, winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability2>
    {
        AppCapability(std::nullptr_t) noexcept {}
        AppCapability(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability(ptr, take_ownership_from_abi) {}
        static auto RequestAccessForCapabilitiesAsync(param::async_iterable<hstring> const& capabilityNames);
        static auto RequestAccessForCapabilitiesForUserAsync(winrt::Windows::System::User const& user, param::async_iterable<hstring> const& capabilityNames);
        static auto Create(param::hstring const& capabilityName);
        static auto CreateWithProcessIdForUser(winrt::Windows::System::User const& user, param::hstring const& capabilityName, uint32_t pid);
    };
    struct __declspec(empty_bases) AppCapabilityAccessChangedEventArgs : winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs
    {
        AppCapabilityAccessChangedEventArgs(std::nullptr_t) noexcept {}
        AppCapabilityAccessChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
