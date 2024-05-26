// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Authentication_Web_Provider_1_H
#define WINRT_Windows_Security_Authentication_Web_Provider_1_H
#include "winrt/impl/Windows.Security.Authentication.Web.Provider.0.h"
WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Web::Provider
{
    struct __declspec(empty_bases) IWebAccountClientView :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountClientView>
    {
        IWebAccountClientView(std::nullptr_t = nullptr) noexcept {}
        IWebAccountClientView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountClientViewFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountClientViewFactory>
    {
        IWebAccountClientViewFactory(std::nullptr_t = nullptr) noexcept {}
        IWebAccountClientViewFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountManagerStatics>
    {
        IWebAccountManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IWebAccountManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountManagerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountManagerStatics2>
    {
        IWebAccountManagerStatics2(std::nullptr_t = nullptr) noexcept {}
        IWebAccountManagerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountManagerStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountManagerStatics3>
    {
        IWebAccountManagerStatics3(std::nullptr_t = nullptr) noexcept {}
        IWebAccountManagerStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountManagerStatics4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountManagerStatics4>
    {
        IWebAccountManagerStatics4(std::nullptr_t = nullptr) noexcept {}
        IWebAccountManagerStatics4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountMapManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountMapManagerStatics>
    {
        IWebAccountMapManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IWebAccountMapManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderAddAccountOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderAddAccountOperation>,
        impl::require<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation, winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>
    {
        IWebAccountProviderAddAccountOperation(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderAddAccountOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderBaseReportOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderBaseReportOperation>
    {
        IWebAccountProviderBaseReportOperation(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderBaseReportOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderDeleteAccountOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderDeleteAccountOperation>,
        impl::require<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation, winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>
    {
        IWebAccountProviderDeleteAccountOperation(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderDeleteAccountOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderManageAccountOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderManageAccountOperation>,
        impl::require<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation, winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>
    {
        IWebAccountProviderManageAccountOperation(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderManageAccountOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderOperation>
    {
        IWebAccountProviderOperation(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderRetrieveCookiesOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderRetrieveCookiesOperation>,
        impl::require<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation, winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>
    {
        IWebAccountProviderRetrieveCookiesOperation(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderRetrieveCookiesOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderSignOutAccountOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderSignOutAccountOperation>,
        impl::require<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation, winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>
    {
        IWebAccountProviderSignOutAccountOperation(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderSignOutAccountOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderSilentReportOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderSilentReportOperation>,
        impl::require<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation, winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation>
    {
        IWebAccountProviderSilentReportOperation(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderSilentReportOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderTokenObjects :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderTokenObjects>
    {
        IWebAccountProviderTokenObjects(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderTokenObjects(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderTokenObjects2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderTokenObjects2>,
        impl::require<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects2, winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects>
    {
        IWebAccountProviderTokenObjects2(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderTokenObjects2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderTokenOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderTokenOperation>,
        impl::require<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation, winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>
    {
        IWebAccountProviderTokenOperation(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderTokenOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderUIReportOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderUIReportOperation>,
        impl::require<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderUIReportOperation, winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation>
    {
        IWebAccountProviderUIReportOperation(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderUIReportOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountScopeManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountScopeManagerStatics>
    {
        IWebAccountScopeManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IWebAccountScopeManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebProviderTokenRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebProviderTokenRequest>
    {
        IWebProviderTokenRequest(std::nullptr_t = nullptr) noexcept {}
        IWebProviderTokenRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebProviderTokenRequest2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebProviderTokenRequest2>
    {
        IWebProviderTokenRequest2(std::nullptr_t = nullptr) noexcept {}
        IWebProviderTokenRequest2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebProviderTokenRequest3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebProviderTokenRequest3>
    {
        IWebProviderTokenRequest3(std::nullptr_t = nullptr) noexcept {}
        IWebProviderTokenRequest3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebProviderTokenResponse :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebProviderTokenResponse>
    {
        IWebProviderTokenResponse(std::nullptr_t = nullptr) noexcept {}
        IWebProviderTokenResponse(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebProviderTokenResponseFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebProviderTokenResponseFactory>
    {
        IWebProviderTokenResponseFactory(std::nullptr_t = nullptr) noexcept {}
        IWebProviderTokenResponseFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
