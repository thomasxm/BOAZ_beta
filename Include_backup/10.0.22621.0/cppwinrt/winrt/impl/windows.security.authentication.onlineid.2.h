// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Authentication_OnlineId_2_H
#define WINRT_Windows_Security_Authentication_OnlineId_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Security.Authentication.OnlineId.1.h"
WINRT_EXPORT namespace winrt::Windows::Security::Authentication::OnlineId
{
    struct __declspec(empty_bases) OnlineIdAuthenticator : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator
    {
        OnlineIdAuthenticator(std::nullptr_t) noexcept {}
        OnlineIdAuthenticator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator(ptr, take_ownership_from_abi) {}
        OnlineIdAuthenticator();
    };
    struct __declspec(empty_bases) OnlineIdServiceTicket : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicket
    {
        OnlineIdServiceTicket(std::nullptr_t) noexcept {}
        OnlineIdServiceTicket(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicket(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) OnlineIdServiceTicketRequest : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequest
    {
        OnlineIdServiceTicketRequest(std::nullptr_t) noexcept {}
        OnlineIdServiceTicketRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequest(ptr, take_ownership_from_abi) {}
        OnlineIdServiceTicketRequest(param::hstring const& service, param::hstring const& policy);
        explicit OnlineIdServiceTicketRequest(param::hstring const& service);
    };
    struct OnlineIdSystemAuthenticator
    {
        OnlineIdSystemAuthenticator() = delete;
        [[nodiscard]] static auto Default();
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) OnlineIdSystemAuthenticatorForUser : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorForUser
    {
        OnlineIdSystemAuthenticatorForUser(std::nullptr_t) noexcept {}
        OnlineIdSystemAuthenticatorForUser(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorForUser(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) OnlineIdSystemIdentity : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemIdentity
    {
        OnlineIdSystemIdentity(std::nullptr_t) noexcept {}
        OnlineIdSystemIdentity(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemIdentity(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) OnlineIdSystemTicketResult : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemTicketResult
    {
        OnlineIdSystemTicketResult(std::nullptr_t) noexcept {}
        OnlineIdSystemTicketResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemTicketResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SignOutUserOperation : winrt::Windows::Foundation::IAsyncAction
    {
        SignOutUserOperation(std::nullptr_t) noexcept {}
        SignOutUserOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IAsyncAction(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserAuthenticationOperation : winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::OnlineId::UserIdentity>
    {
        UserAuthenticationOperation(std::nullptr_t) noexcept {}
        UserAuthenticationOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::OnlineId::UserIdentity>(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserIdentity : winrt::Windows::Security::Authentication::OnlineId::IUserIdentity
    {
        UserIdentity(std::nullptr_t) noexcept {}
        UserIdentity(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::OnlineId::IUserIdentity(ptr, take_ownership_from_abi) {}
    };
}
#endif
