// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_DataProtection_2_H
#define WINRT_Windows_Security_DataProtection_2_H
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Security.DataProtection.1.h"
WINRT_EXPORT namespace winrt::Windows::Security::DataProtection
{
    struct __declspec(empty_bases) UserDataAvailabilityStateChangedEventArgs : winrt::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs
    {
        UserDataAvailabilityStateChangedEventArgs(std::nullptr_t) noexcept {}
        UserDataAvailabilityStateChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserDataBufferUnprotectResult : winrt::Windows::Security::DataProtection::IUserDataBufferUnprotectResult
    {
        UserDataBufferUnprotectResult(std::nullptr_t) noexcept {}
        UserDataBufferUnprotectResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::DataProtection::IUserDataBufferUnprotectResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserDataProtectionManager : winrt::Windows::Security::DataProtection::IUserDataProtectionManager
    {
        UserDataProtectionManager(std::nullptr_t) noexcept {}
        UserDataProtectionManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::DataProtection::IUserDataProtectionManager(ptr, take_ownership_from_abi) {}
        static auto TryGetDefault();
        static auto TryGetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) UserDataStorageItemProtectionInfo : winrt::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo
    {
        UserDataStorageItemProtectionInfo(std::nullptr_t) noexcept {}
        UserDataStorageItemProtectionInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo(ptr, take_ownership_from_abi) {}
    };
}
#endif
