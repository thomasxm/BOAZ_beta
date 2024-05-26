// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Credentials_1_H
#define WINRT_Windows_Security_Credentials_1_H
#include "winrt/impl/Windows.Security.Credentials.0.h"
WINRT_EXPORT namespace winrt::Windows::Security::Credentials
{
    struct __declspec(empty_bases) ICredentialFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICredentialFactory>
    {
        ICredentialFactory(std::nullptr_t = nullptr) noexcept {}
        ICredentialFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IKeyCredential :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKeyCredential>
    {
        IKeyCredential(std::nullptr_t = nullptr) noexcept {}
        IKeyCredential(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IKeyCredentialAttestationResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKeyCredentialAttestationResult>
    {
        IKeyCredentialAttestationResult(std::nullptr_t = nullptr) noexcept {}
        IKeyCredentialAttestationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IKeyCredentialManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKeyCredentialManagerStatics>
    {
        IKeyCredentialManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IKeyCredentialManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IKeyCredentialOperationResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKeyCredentialOperationResult>
    {
        IKeyCredentialOperationResult(std::nullptr_t = nullptr) noexcept {}
        IKeyCredentialOperationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IKeyCredentialRetrievalResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKeyCredentialRetrievalResult>
    {
        IKeyCredentialRetrievalResult(std::nullptr_t = nullptr) noexcept {}
        IKeyCredentialRetrievalResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPasswordCredential :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPasswordCredential>
    {
        IPasswordCredential(std::nullptr_t = nullptr) noexcept {}
        IPasswordCredential(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPasswordVault :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPasswordVault>
    {
        IPasswordVault(std::nullptr_t = nullptr) noexcept {}
        IPasswordVault(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccount :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccount>
    {
        IWebAccount(std::nullptr_t = nullptr) noexcept {}
        IWebAccount(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccount2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccount2>,
        impl::require<winrt::Windows::Security::Credentials::IWebAccount2, winrt::Windows::Security::Credentials::IWebAccount>
    {
        IWebAccount2(std::nullptr_t = nullptr) noexcept {}
        IWebAccount2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountFactory>
    {
        IWebAccountFactory(std::nullptr_t = nullptr) noexcept {}
        IWebAccountFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProvider>
    {
        IWebAccountProvider(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProvider2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProvider2>,
        impl::require<winrt::Windows::Security::Credentials::IWebAccountProvider2, winrt::Windows::Security::Credentials::IWebAccountProvider>
    {
        IWebAccountProvider2(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProvider2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProvider3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProvider3>,
        impl::require<winrt::Windows::Security::Credentials::IWebAccountProvider3, winrt::Windows::Security::Credentials::IWebAccountProvider, winrt::Windows::Security::Credentials::IWebAccountProvider2>
    {
        IWebAccountProvider3(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProvider3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProvider4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProvider4>
    {
        IWebAccountProvider4(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProvider4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderFactory>
    {
        IWebAccountProviderFactory(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
