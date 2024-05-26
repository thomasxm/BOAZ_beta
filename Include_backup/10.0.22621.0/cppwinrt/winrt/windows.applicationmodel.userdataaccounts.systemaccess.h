// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_UserDataAccounts_SystemAccess_H
#define WINRT_Windows_ApplicationModel_UserDataAccounts_SystemAccess_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.UserDataAccounts.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataAccounts.SystemAccess.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::AccountName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_AccountName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::AccountName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_AccountName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::DeviceAccountTypeId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_DeviceAccountTypeId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::DeviceAccountTypeId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_DeviceAccountTypeId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::ServerType() const
    {
        winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_ServerType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::ServerType(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_ServerType(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::EmailAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_EmailAddress(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::EmailAddress(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_EmailAddress(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::Domain() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_Domain(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::Domain(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_Domain(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::EmailSyncEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_EmailSyncEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::EmailSyncEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_EmailSyncEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::ContactsSyncEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_ContactsSyncEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::ContactsSyncEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_ContactsSyncEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::CalendarSyncEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_CalendarSyncEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::CalendarSyncEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_CalendarSyncEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_IncomingServerAddress(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerAddress(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_IncomingServerAddress(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerPort() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_IncomingServerPort(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerPort(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_IncomingServerPort(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerRequiresSsl() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_IncomingServerRequiresSsl(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerRequiresSsl(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_IncomingServerRequiresSsl(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerUsername() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_IncomingServerUsername(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerUsername(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_IncomingServerUsername(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_OutgoingServerAddress(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerAddress(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_OutgoingServerAddress(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerPort() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_OutgoingServerPort(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerPort(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_OutgoingServerPort(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerRequiresSsl() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_OutgoingServerRequiresSsl(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerRequiresSsl(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_OutgoingServerRequiresSsl(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerUsername() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_OutgoingServerUsername(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerUsername(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_OutgoingServerUsername(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IncomingServerCredential() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IncomingServerCredential(&value));
        return winrt::Windows::Security::Credentials::PasswordCredential{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IncomingServerCredential(winrt::Windows::Security::Credentials::PasswordCredential const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IncomingServerCredential(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OutgoingServerCredential() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_OutgoingServerCredential(&value));
        return winrt::Windows::Security::Credentials::PasswordCredential{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OutgoingServerCredential(winrt::Windows::Security::Credentials::PasswordCredential const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_OutgoingServerCredential(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OAuthRefreshToken() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_OAuthRefreshToken(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OAuthRefreshToken(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_OAuthRefreshToken(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsExternallyManaged() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsExternallyManaged(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsExternallyManaged(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IsExternallyManaged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AccountIconId() const
    {
        winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_AccountIconId(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AccountIconId(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_AccountIconId(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AuthenticationType() const
    {
        winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_AuthenticationType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AuthenticationType(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_AuthenticationType(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsSsoAuthenticationSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsSsoAuthenticationSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::SsoAccountId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_SsoAccountId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::SsoAccountId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_SsoAccountId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AlwaysDownloadFullMessage() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_AlwaysDownloadFullMessage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AlwaysDownloadFullMessage(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_AlwaysDownloadFullMessage(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::DoesPolicyAllowMailSync() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_DoesPolicyAllowMailSync(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::SyncScheduleKind() const
    {
        winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_SyncScheduleKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::SyncScheduleKind(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_SyncScheduleKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::MailAgeFilter() const
    {
        winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_MailAgeFilter(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::MailAgeFilter(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_MailAgeFilter(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsClientAuthenticationCertificateRequired() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsClientAuthenticationCertificateRequired(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsClientAuthenticationCertificateRequired(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IsClientAuthenticationCertificateRequired(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AutoSelectAuthenticationCertificate() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_AutoSelectAuthenticationCertificate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AutoSelectAuthenticationCertificate(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_AutoSelectAuthenticationCertificate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AuthenticationCertificateId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_AuthenticationCertificateId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AuthenticationCertificateId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_AuthenticationCertificateId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavSyncScheduleKind() const
    {
        winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CardDavSyncScheduleKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavSyncScheduleKind(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CardDavSyncScheduleKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavSyncScheduleKind() const
    {
        winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CalDavSyncScheduleKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavSyncScheduleKind(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CalDavSyncScheduleKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavServerUrl() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CardDavServerUrl(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavServerUrl(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CardDavServerUrl(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavRequiresSsl() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CardDavRequiresSsl(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavRequiresSsl(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CardDavRequiresSsl(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavServerUrl() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CalDavServerUrl(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavServerUrl(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CalDavServerUrl(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavRequiresSsl() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CalDavRequiresSsl(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavRequiresSsl(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CalDavRequiresSsl(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasModifiedByUser() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_WasModifiedByUser(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasModifiedByUser(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_WasModifiedByUser(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasIncomingServerCertificateHashConfirmed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_WasIncomingServerCertificateHashConfirmed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasIncomingServerCertificateHashConfirmed(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_WasIncomingServerCertificateHashConfirmed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IncomingServerCertificateHash() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IncomingServerCertificateHash(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IncomingServerCertificateHash(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IncomingServerCertificateHash(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsOutgoingServerAuthenticationRequired() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsOutgoingServerAuthenticationRequired(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsOutgoingServerAuthenticationRequired(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IsOutgoingServerAuthenticationRequired(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsOutgoingServerAuthenticationEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsOutgoingServerAuthenticationEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsOutgoingServerAuthenticationEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IsOutgoingServerAuthenticationEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasOutgoingServerCertificateHashConfirmed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_WasOutgoingServerCertificateHashConfirmed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasOutgoingServerCertificateHashConfirmed(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_WasOutgoingServerCertificateHashConfirmed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OutgoingServerCertificateHash() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_OutgoingServerCertificateHash(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OutgoingServerCertificateHash(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_OutgoingServerCertificateHash(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsSyncScheduleManagedBySystem() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsSyncScheduleManagedBySystem(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsSyncScheduleManagedBySystem(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IsSyncScheduleManagedBySystem(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics<D>::AddAndShowDeviceAccountsAsync(param::async_iterable<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> const& accounts) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics)->AddAndShowDeviceAccountsAsync(*(void**)(&accounts), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics2<D>::SuppressLocalAccountWithAccountAsync(param::hstring const& userDataAccountId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2)->SuppressLocalAccountWithAccountAsync(*(void**)(&userDataAccountId), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics2<D>::CreateDeviceAccountAsync(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration const& account) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2)->CreateDeviceAccountAsync(*(void**)(&account), &result));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics2<D>::DeleteDeviceAccountAsync(param::hstring const& accountId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2)->DeleteDeviceAccountAsync(*(void**)(&accountId), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration>) consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics2<D>::GetDeviceAccountConfigurationAsync(param::hstring const& accountId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2)->GetDeviceAccountConfigurationAsync(*(void**)(&accountId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration>{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration> : produce_base<D, winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration>
    {
        int32_t __stdcall get_AccountName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AccountName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AccountName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccountName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceAccountTypeId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceAccountTypeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DeviceAccountTypeId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeviceAccountTypeId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType>(this->shim().ServerType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ServerType(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServerType(*reinterpret_cast<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EmailAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EmailAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EmailAddress(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EmailAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Domain(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Domain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Domain(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Domain(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EmailSyncEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().EmailSyncEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EmailSyncEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EmailSyncEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContactsSyncEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ContactsSyncEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContactsSyncEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContactsSyncEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CalendarSyncEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CalendarSyncEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CalendarSyncEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CalendarSyncEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncomingServerAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().IncomingServerAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IncomingServerAddress(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IncomingServerAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncomingServerPort(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().IncomingServerPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IncomingServerPort(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IncomingServerPort(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncomingServerRequiresSsl(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IncomingServerRequiresSsl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IncomingServerRequiresSsl(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IncomingServerRequiresSsl(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncomingServerUsername(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().IncomingServerUsername());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IncomingServerUsername(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IncomingServerUsername(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutgoingServerAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().OutgoingServerAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutgoingServerAddress(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutgoingServerAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutgoingServerPort(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().OutgoingServerPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutgoingServerPort(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutgoingServerPort(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutgoingServerRequiresSsl(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().OutgoingServerRequiresSsl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutgoingServerRequiresSsl(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutgoingServerRequiresSsl(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutgoingServerUsername(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().OutgoingServerUsername());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutgoingServerUsername(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutgoingServerUsername(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2> : produce_base<D, winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2>
    {
        int32_t __stdcall get_IncomingServerCredential(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().IncomingServerCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IncomingServerCredential(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IncomingServerCredential(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutgoingServerCredential(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().OutgoingServerCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutgoingServerCredential(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutgoingServerCredential(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OAuthRefreshToken(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().OAuthRefreshToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OAuthRefreshToken(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OAuthRefreshToken(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsExternallyManaged(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsExternallyManaged());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsExternallyManaged(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsExternallyManaged(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccountIconId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId>(this->shim().AccountIconId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AccountIconId(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccountIconId(*reinterpret_cast<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AuthenticationType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType>(this->shim().AuthenticationType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AuthenticationType(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AuthenticationType(*reinterpret_cast<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSsoAuthenticationSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSsoAuthenticationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SsoAccountId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SsoAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SsoAccountId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SsoAccountId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AlwaysDownloadFullMessage(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AlwaysDownloadFullMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AlwaysDownloadFullMessage(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AlwaysDownloadFullMessage(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DoesPolicyAllowMailSync(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DoesPolicyAllowMailSync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SyncScheduleKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind>(this->shim().SyncScheduleKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SyncScheduleKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SyncScheduleKind(*reinterpret_cast<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MailAgeFilter(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter>(this->shim().MailAgeFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MailAgeFilter(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MailAgeFilter(*reinterpret_cast<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsClientAuthenticationCertificateRequired(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsClientAuthenticationCertificateRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsClientAuthenticationCertificateRequired(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsClientAuthenticationCertificateRequired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoSelectAuthenticationCertificate(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AutoSelectAuthenticationCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoSelectAuthenticationCertificate(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoSelectAuthenticationCertificate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AuthenticationCertificateId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AuthenticationCertificateId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AuthenticationCertificateId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AuthenticationCertificateId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CardDavSyncScheduleKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind>(this->shim().CardDavSyncScheduleKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CardDavSyncScheduleKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CardDavSyncScheduleKind(*reinterpret_cast<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CalDavSyncScheduleKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind>(this->shim().CalDavSyncScheduleKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CalDavSyncScheduleKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CalDavSyncScheduleKind(*reinterpret_cast<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CardDavServerUrl(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().CardDavServerUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CardDavServerUrl(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CardDavServerUrl(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CardDavRequiresSsl(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CardDavRequiresSsl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CardDavRequiresSsl(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CardDavRequiresSsl(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CalDavServerUrl(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().CalDavServerUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CalDavServerUrl(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CalDavServerUrl(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CalDavRequiresSsl(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CalDavRequiresSsl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CalDavRequiresSsl(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CalDavRequiresSsl(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WasModifiedByUser(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().WasModifiedByUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_WasModifiedByUser(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WasModifiedByUser(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WasIncomingServerCertificateHashConfirmed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().WasIncomingServerCertificateHashConfirmed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_WasIncomingServerCertificateHashConfirmed(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WasIncomingServerCertificateHashConfirmed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncomingServerCertificateHash(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().IncomingServerCertificateHash());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IncomingServerCertificateHash(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IncomingServerCertificateHash(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOutgoingServerAuthenticationRequired(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOutgoingServerAuthenticationRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsOutgoingServerAuthenticationRequired(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsOutgoingServerAuthenticationRequired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOutgoingServerAuthenticationEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOutgoingServerAuthenticationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsOutgoingServerAuthenticationEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsOutgoingServerAuthenticationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WasOutgoingServerCertificateHashConfirmed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().WasOutgoingServerCertificateHashConfirmed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_WasOutgoingServerCertificateHashConfirmed(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WasOutgoingServerCertificateHashConfirmed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutgoingServerCertificateHash(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().OutgoingServerCertificateHash());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutgoingServerCertificateHash(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutgoingServerCertificateHash(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSyncScheduleManagedBySystem(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSyncScheduleManagedBySystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsSyncScheduleManagedBySystem(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsSyncScheduleManagedBySystem(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics>
    {
        int32_t __stdcall AddAndShowDeviceAccountsAsync(void* accounts, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().AddAndShowDeviceAccountsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> const*>(&accounts)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2> : produce_base<D, winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2>
    {
        int32_t __stdcall SuppressLocalAccountWithAccountAsync(void* userDataAccountId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SuppressLocalAccountWithAccountAsync(*reinterpret_cast<hstring const*>(&userDataAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDeviceAccountAsync(void* account, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CreateDeviceAccountAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration const*>(&account)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteDeviceAccountAsync(void* accountId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteDeviceAccountAsync(*reinterpret_cast<hstring const*>(&accountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceAccountConfigurationAsync(void* accountId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration>>(this->shim().GetDeviceAccountConfigurationAsync(*reinterpret_cast<hstring const*>(&accountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess
{
    inline DeviceAccountConfiguration::DeviceAccountConfiguration() :
        DeviceAccountConfiguration(impl::call_factory_cast<DeviceAccountConfiguration(*)(winrt::Windows::Foundation::IActivationFactory const&), DeviceAccountConfiguration>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DeviceAccountConfiguration>(); }))
    {
    }
    inline auto UserDataAccountSystemAccessManager::AddAndShowDeviceAccountsAsync(param::async_iterable<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> const& accounts)
    {
        return impl::call_factory<UserDataAccountSystemAccessManager, IUserDataAccountSystemAccessManagerStatics>([&](IUserDataAccountSystemAccessManagerStatics const& f) { return f.AddAndShowDeviceAccountsAsync(accounts); });
    }
    inline auto UserDataAccountSystemAccessManager::SuppressLocalAccountWithAccountAsync(param::hstring const& userDataAccountId)
    {
        return impl::call_factory<UserDataAccountSystemAccessManager, IUserDataAccountSystemAccessManagerStatics2>([&](IUserDataAccountSystemAccessManagerStatics2 const& f) { return f.SuppressLocalAccountWithAccountAsync(userDataAccountId); });
    }
    inline auto UserDataAccountSystemAccessManager::CreateDeviceAccountAsync(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration const& account)
    {
        return impl::call_factory<UserDataAccountSystemAccessManager, IUserDataAccountSystemAccessManagerStatics2>([&](IUserDataAccountSystemAccessManagerStatics2 const& f) { return f.CreateDeviceAccountAsync(account); });
    }
    inline auto UserDataAccountSystemAccessManager::DeleteDeviceAccountAsync(param::hstring const& accountId)
    {
        return impl::call_factory<UserDataAccountSystemAccessManager, IUserDataAccountSystemAccessManagerStatics2>([&](IUserDataAccountSystemAccessManagerStatics2 const& f) { return f.DeleteDeviceAccountAsync(accountId); });
    }
    inline auto UserDataAccountSystemAccessManager::GetDeviceAccountConfigurationAsync(param::hstring const& accountId)
    {
        return impl::call_factory<UserDataAccountSystemAccessManager, IUserDataAccountSystemAccessManagerStatics2>([&](IUserDataAccountSystemAccessManagerStatics2 const& f) { return f.GetDeviceAccountConfigurationAsync(accountId); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::UserDataAccountSystemAccessManager> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
