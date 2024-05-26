// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_UserDataAccounts_SystemAccess_1_H
#define WINRT_Windows_ApplicationModel_UserDataAccounts_SystemAccess_1_H
#include "winrt/impl/Windows.ApplicationModel.UserDataAccounts.SystemAccess.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess
{
    struct __declspec(empty_bases) IDeviceAccountConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeviceAccountConfiguration>
    {
        IDeviceAccountConfiguration(std::nullptr_t = nullptr) noexcept {}
        IDeviceAccountConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDeviceAccountConfiguration2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeviceAccountConfiguration2>
    {
        IDeviceAccountConfiguration2(std::nullptr_t = nullptr) noexcept {}
        IDeviceAccountConfiguration2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataAccountSystemAccessManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataAccountSystemAccessManagerStatics>
    {
        IUserDataAccountSystemAccessManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IUserDataAccountSystemAccessManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataAccountSystemAccessManagerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataAccountSystemAccessManagerStatics2>
    {
        IUserDataAccountSystemAccessManagerStatics2(std::nullptr_t = nullptr) noexcept {}
        IUserDataAccountSystemAccessManagerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
