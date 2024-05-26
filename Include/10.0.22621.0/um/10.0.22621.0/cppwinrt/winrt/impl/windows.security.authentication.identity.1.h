// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Authentication_Identity_1_H
#define WINRT_Windows_Security_Authentication_Identity_1_H
#include "winrt/impl/Windows.Security.Authentication.Identity.0.h"
WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Identity
{
    struct __declspec(empty_bases) IEnterpriseKeyCredentialRegistrationInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEnterpriseKeyCredentialRegistrationInfo>
    {
        IEnterpriseKeyCredentialRegistrationInfo(std::nullptr_t = nullptr) noexcept {}
        IEnterpriseKeyCredentialRegistrationInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEnterpriseKeyCredentialRegistrationManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEnterpriseKeyCredentialRegistrationManager>
    {
        IEnterpriseKeyCredentialRegistrationManager(std::nullptr_t = nullptr) noexcept {}
        IEnterpriseKeyCredentialRegistrationManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEnterpriseKeyCredentialRegistrationManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEnterpriseKeyCredentialRegistrationManagerStatics>
    {
        IEnterpriseKeyCredentialRegistrationManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IEnterpriseKeyCredentialRegistrationManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
