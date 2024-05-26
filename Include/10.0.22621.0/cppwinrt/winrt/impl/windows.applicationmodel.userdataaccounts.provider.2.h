// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_UserDataAccounts_Provider_2_H
#define WINRT_Windows_ApplicationModel_UserDataAccounts_Provider_2_H
#include "winrt/impl/Windows.ApplicationModel.UserDataAccounts.Provider.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataAccounts::Provider
{
    struct __declspec(empty_bases) UserDataAccountPartnerAccountInfo : winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo
    {
        UserDataAccountPartnerAccountInfo(std::nullptr_t) noexcept {}
        UserDataAccountPartnerAccountInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserDataAccountProviderAddAccountOperation : winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation
    {
        UserDataAccountProviderAddAccountOperation(std::nullptr_t) noexcept {}
        UserDataAccountProviderAddAccountOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserDataAccountProviderResolveErrorsOperation : winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation
    {
        UserDataAccountProviderResolveErrorsOperation(std::nullptr_t) noexcept {}
        UserDataAccountProviderResolveErrorsOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserDataAccountProviderSettingsOperation : winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation
    {
        UserDataAccountProviderSettingsOperation(std::nullptr_t) noexcept {}
        UserDataAccountProviderSettingsOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation(ptr, take_ownership_from_abi) {}
    };
}
#endif
