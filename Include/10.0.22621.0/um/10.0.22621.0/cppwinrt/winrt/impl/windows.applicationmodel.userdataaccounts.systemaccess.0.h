// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_UserDataAccounts_SystemAccess_0_H
#define WINRT_Windows_ApplicationModel_UserDataAccounts_SystemAccess_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Security::Credentials
{
    struct PasswordCredential;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess
{
    enum class DeviceAccountAuthenticationType : int32_t
    {
        Basic = 0,
        OAuth = 1,
        SingleSignOn = 2,
    };
    enum class DeviceAccountIconId : int32_t
    {
        Exchange = 0,
        Msa = 1,
        Outlook = 2,
        Generic = 3,
    };
    enum class DeviceAccountMailAgeFilter : int32_t
    {
        All = 0,
        Last1Day = 1,
        Last3Days = 2,
        Last7Days = 3,
        Last14Days = 4,
        Last30Days = 5,
        Last90Days = 6,
    };
    enum class DeviceAccountServerType : int32_t
    {
        Exchange = 0,
        Pop = 1,
        Imap = 2,
    };
    enum class DeviceAccountSyncScheduleKind : int32_t
    {
        Manual = 0,
        Every15Minutes = 1,
        Every30Minutes = 2,
        Every60Minutes = 3,
        Every2Hours = 4,
        Daily = 5,
        AsItemsArrive = 6,
    };
    struct IDeviceAccountConfiguration;
    struct IDeviceAccountConfiguration2;
    struct IUserDataAccountSystemAccessManagerStatics;
    struct IUserDataAccountSystemAccessManagerStatics2;
    struct DeviceAccountConfiguration;
    struct UserDataAccountSystemAccessManager;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::UserDataAccountSystemAccessManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> = L"Windows.ApplicationModel.UserDataAccounts.SystemAccess.DeviceAccountConfiguration";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::UserDataAccountSystemAccessManager> = L"Windows.ApplicationModel.UserDataAccounts.SystemAccess.UserDataAccountSystemAccessManager";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType> = L"Windows.ApplicationModel.UserDataAccounts.SystemAccess.DeviceAccountAuthenticationType";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId> = L"Windows.ApplicationModel.UserDataAccounts.SystemAccess.DeviceAccountIconId";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter> = L"Windows.ApplicationModel.UserDataAccounts.SystemAccess.DeviceAccountMailAgeFilter";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType> = L"Windows.ApplicationModel.UserDataAccounts.SystemAccess.DeviceAccountServerType";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind> = L"Windows.ApplicationModel.UserDataAccounts.SystemAccess.DeviceAccountSyncScheduleKind";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration> = L"Windows.ApplicationModel.UserDataAccounts.SystemAccess.IDeviceAccountConfiguration";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2> = L"Windows.ApplicationModel.UserDataAccounts.SystemAccess.IDeviceAccountConfiguration2";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics> = L"Windows.ApplicationModel.UserDataAccounts.SystemAccess.IUserDataAccountSystemAccessManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2> = L"Windows.ApplicationModel.UserDataAccounts.SystemAccess.IUserDataAccountSystemAccessManagerStatics2";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration>{ 0xAD0123A3,0xFBDC,0x4D1B,{ 0xBE,0x43,0x5A,0x27,0xEA,0x4A,0x1B,0x63 } }; // AD0123A3-FBDC-4D1B-BE43-5A27EA4A1B63
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2>{ 0xF2B2E5A6,0x728D,0x4A4A,{ 0x89,0x45,0x2B,0xF8,0x58,0x01,0x36,0xDE } }; // F2B2E5A6-728D-4A4A-8945-2BF8580136DE
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics>{ 0x9D6B11B9,0xCBE5,0x45F5,{ 0x82,0x2B,0xC2,0x67,0xB8,0x1D,0xBD,0xB6 } }; // 9D6B11B9-CBE5-45F5-822B-C267B81DBDB6
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2>{ 0x943F854D,0x4B4E,0x439F,{ 0x83,0xD3,0x97,0x9B,0x27,0xC0,0x5A,0xC7 } }; // 943F854D-4B4E-439F-83D3-979B27C05AC7
    template <> struct default_interface<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration>{ using type = winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration; };
    template <> struct abi<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AccountName(void**) noexcept = 0;
            virtual int32_t __stdcall put_AccountName(void*) noexcept = 0;
            virtual int32_t __stdcall get_DeviceAccountTypeId(void**) noexcept = 0;
            virtual int32_t __stdcall put_DeviceAccountTypeId(void*) noexcept = 0;
            virtual int32_t __stdcall get_ServerType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ServerType(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_EmailAddress(void**) noexcept = 0;
            virtual int32_t __stdcall put_EmailAddress(void*) noexcept = 0;
            virtual int32_t __stdcall get_Domain(void**) noexcept = 0;
            virtual int32_t __stdcall put_Domain(void*) noexcept = 0;
            virtual int32_t __stdcall get_EmailSyncEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_EmailSyncEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_ContactsSyncEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ContactsSyncEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_CalendarSyncEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_CalendarSyncEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_IncomingServerAddress(void**) noexcept = 0;
            virtual int32_t __stdcall put_IncomingServerAddress(void*) noexcept = 0;
            virtual int32_t __stdcall get_IncomingServerPort(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_IncomingServerPort(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IncomingServerRequiresSsl(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IncomingServerRequiresSsl(bool) noexcept = 0;
            virtual int32_t __stdcall get_IncomingServerUsername(void**) noexcept = 0;
            virtual int32_t __stdcall put_IncomingServerUsername(void*) noexcept = 0;
            virtual int32_t __stdcall get_OutgoingServerAddress(void**) noexcept = 0;
            virtual int32_t __stdcall put_OutgoingServerAddress(void*) noexcept = 0;
            virtual int32_t __stdcall get_OutgoingServerPort(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_OutgoingServerPort(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_OutgoingServerRequiresSsl(bool*) noexcept = 0;
            virtual int32_t __stdcall put_OutgoingServerRequiresSsl(bool) noexcept = 0;
            virtual int32_t __stdcall get_OutgoingServerUsername(void**) noexcept = 0;
            virtual int32_t __stdcall put_OutgoingServerUsername(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IncomingServerCredential(void**) noexcept = 0;
            virtual int32_t __stdcall put_IncomingServerCredential(void*) noexcept = 0;
            virtual int32_t __stdcall get_OutgoingServerCredential(void**) noexcept = 0;
            virtual int32_t __stdcall put_OutgoingServerCredential(void*) noexcept = 0;
            virtual int32_t __stdcall get_OAuthRefreshToken(void**) noexcept = 0;
            virtual int32_t __stdcall put_OAuthRefreshToken(void*) noexcept = 0;
            virtual int32_t __stdcall get_IsExternallyManaged(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsExternallyManaged(bool) noexcept = 0;
            virtual int32_t __stdcall get_AccountIconId(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_AccountIconId(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_AuthenticationType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_AuthenticationType(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsSsoAuthenticationSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SsoAccountId(void**) noexcept = 0;
            virtual int32_t __stdcall put_SsoAccountId(void*) noexcept = 0;
            virtual int32_t __stdcall get_AlwaysDownloadFullMessage(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AlwaysDownloadFullMessage(bool) noexcept = 0;
            virtual int32_t __stdcall get_DoesPolicyAllowMailSync(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SyncScheduleKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_SyncScheduleKind(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_MailAgeFilter(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_MailAgeFilter(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsClientAuthenticationCertificateRequired(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsClientAuthenticationCertificateRequired(bool) noexcept = 0;
            virtual int32_t __stdcall get_AutoSelectAuthenticationCertificate(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AutoSelectAuthenticationCertificate(bool) noexcept = 0;
            virtual int32_t __stdcall get_AuthenticationCertificateId(void**) noexcept = 0;
            virtual int32_t __stdcall put_AuthenticationCertificateId(void*) noexcept = 0;
            virtual int32_t __stdcall get_CardDavSyncScheduleKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_CardDavSyncScheduleKind(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_CalDavSyncScheduleKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_CalDavSyncScheduleKind(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_CardDavServerUrl(void**) noexcept = 0;
            virtual int32_t __stdcall put_CardDavServerUrl(void*) noexcept = 0;
            virtual int32_t __stdcall get_CardDavRequiresSsl(bool*) noexcept = 0;
            virtual int32_t __stdcall put_CardDavRequiresSsl(bool) noexcept = 0;
            virtual int32_t __stdcall get_CalDavServerUrl(void**) noexcept = 0;
            virtual int32_t __stdcall put_CalDavServerUrl(void*) noexcept = 0;
            virtual int32_t __stdcall get_CalDavRequiresSsl(bool*) noexcept = 0;
            virtual int32_t __stdcall put_CalDavRequiresSsl(bool) noexcept = 0;
            virtual int32_t __stdcall get_WasModifiedByUser(bool*) noexcept = 0;
            virtual int32_t __stdcall put_WasModifiedByUser(bool) noexcept = 0;
            virtual int32_t __stdcall get_WasIncomingServerCertificateHashConfirmed(bool*) noexcept = 0;
            virtual int32_t __stdcall put_WasIncomingServerCertificateHashConfirmed(bool) noexcept = 0;
            virtual int32_t __stdcall get_IncomingServerCertificateHash(void**) noexcept = 0;
            virtual int32_t __stdcall put_IncomingServerCertificateHash(void*) noexcept = 0;
            virtual int32_t __stdcall get_IsOutgoingServerAuthenticationRequired(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsOutgoingServerAuthenticationRequired(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsOutgoingServerAuthenticationEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsOutgoingServerAuthenticationEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_WasOutgoingServerCertificateHashConfirmed(bool*) noexcept = 0;
            virtual int32_t __stdcall put_WasOutgoingServerCertificateHashConfirmed(bool) noexcept = 0;
            virtual int32_t __stdcall get_OutgoingServerCertificateHash(void**) noexcept = 0;
            virtual int32_t __stdcall put_OutgoingServerCertificateHash(void*) noexcept = 0;
            virtual int32_t __stdcall get_IsSyncScheduleManagedBySystem(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsSyncScheduleManagedBySystem(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AddAndShowDeviceAccountsAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SuppressLocalAccountWithAccountAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateDeviceAccountAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall DeleteDeviceAccountAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceAccountConfigurationAsync(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AccountName() const;
        WINRT_IMPL_AUTO(void) AccountName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceAccountTypeId() const;
        WINRT_IMPL_AUTO(void) DeviceAccountTypeId(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType) ServerType() const;
        WINRT_IMPL_AUTO(void) ServerType(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailAddress() const;
        WINRT_IMPL_AUTO(void) EmailAddress(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Domain() const;
        WINRT_IMPL_AUTO(void) Domain(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) EmailSyncEnabled() const;
        WINRT_IMPL_AUTO(void) EmailSyncEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ContactsSyncEnabled() const;
        WINRT_IMPL_AUTO(void) ContactsSyncEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CalendarSyncEnabled() const;
        WINRT_IMPL_AUTO(void) CalendarSyncEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) IncomingServerAddress() const;
        WINRT_IMPL_AUTO(void) IncomingServerAddress(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) IncomingServerPort() const;
        WINRT_IMPL_AUTO(void) IncomingServerPort(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IncomingServerRequiresSsl() const;
        WINRT_IMPL_AUTO(void) IncomingServerRequiresSsl(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) IncomingServerUsername() const;
        WINRT_IMPL_AUTO(void) IncomingServerUsername(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) OutgoingServerAddress() const;
        WINRT_IMPL_AUTO(void) OutgoingServerAddress(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) OutgoingServerPort() const;
        WINRT_IMPL_AUTO(void) OutgoingServerPort(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) OutgoingServerRequiresSsl() const;
        WINRT_IMPL_AUTO(void) OutgoingServerRequiresSsl(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) OutgoingServerUsername() const;
        WINRT_IMPL_AUTO(void) OutgoingServerUsername(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) IncomingServerCredential() const;
        WINRT_IMPL_AUTO(void) IncomingServerCredential(winrt::Windows::Security::Credentials::PasswordCredential const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) OutgoingServerCredential() const;
        WINRT_IMPL_AUTO(void) OutgoingServerCredential(winrt::Windows::Security::Credentials::PasswordCredential const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) OAuthRefreshToken() const;
        WINRT_IMPL_AUTO(void) OAuthRefreshToken(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsExternallyManaged() const;
        WINRT_IMPL_AUTO(void) IsExternallyManaged(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId) AccountIconId() const;
        WINRT_IMPL_AUTO(void) AccountIconId(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType) AuthenticationType() const;
        WINRT_IMPL_AUTO(void) AuthenticationType(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSsoAuthenticationSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SsoAccountId() const;
        WINRT_IMPL_AUTO(void) SsoAccountId(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AlwaysDownloadFullMessage() const;
        WINRT_IMPL_AUTO(void) AlwaysDownloadFullMessage(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) DoesPolicyAllowMailSync() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind) SyncScheduleKind() const;
        WINRT_IMPL_AUTO(void) SyncScheduleKind(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter) MailAgeFilter() const;
        WINRT_IMPL_AUTO(void) MailAgeFilter(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsClientAuthenticationCertificateRequired() const;
        WINRT_IMPL_AUTO(void) IsClientAuthenticationCertificateRequired(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AutoSelectAuthenticationCertificate() const;
        WINRT_IMPL_AUTO(void) AutoSelectAuthenticationCertificate(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AuthenticationCertificateId() const;
        WINRT_IMPL_AUTO(void) AuthenticationCertificateId(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind) CardDavSyncScheduleKind() const;
        WINRT_IMPL_AUTO(void) CardDavSyncScheduleKind(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind) CalDavSyncScheduleKind() const;
        WINRT_IMPL_AUTO(void) CalDavSyncScheduleKind(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) CardDavServerUrl() const;
        WINRT_IMPL_AUTO(void) CardDavServerUrl(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CardDavRequiresSsl() const;
        WINRT_IMPL_AUTO(void) CardDavRequiresSsl(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) CalDavServerUrl() const;
        WINRT_IMPL_AUTO(void) CalDavServerUrl(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CalDavRequiresSsl() const;
        WINRT_IMPL_AUTO(void) CalDavRequiresSsl(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) WasModifiedByUser() const;
        WINRT_IMPL_AUTO(void) WasModifiedByUser(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) WasIncomingServerCertificateHashConfirmed() const;
        WINRT_IMPL_AUTO(void) WasIncomingServerCertificateHashConfirmed(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) IncomingServerCertificateHash() const;
        WINRT_IMPL_AUTO(void) IncomingServerCertificateHash(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsOutgoingServerAuthenticationRequired() const;
        WINRT_IMPL_AUTO(void) IsOutgoingServerAuthenticationRequired(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsOutgoingServerAuthenticationEnabled() const;
        WINRT_IMPL_AUTO(void) IsOutgoingServerAuthenticationEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) WasOutgoingServerCertificateHashConfirmed() const;
        WINRT_IMPL_AUTO(void) WasOutgoingServerCertificateHashConfirmed(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) OutgoingServerCertificateHash() const;
        WINRT_IMPL_AUTO(void) OutgoingServerCertificateHash(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSyncScheduleManagedBySystem() const;
        WINRT_IMPL_AUTO(void) IsSyncScheduleManagedBySystem(bool value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>) AddAndShowDeviceAccountsAsync(param::async_iterable<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> const& accounts) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SuppressLocalAccountWithAccountAsync(param::hstring const& userDataAccountId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) CreateDeviceAccountAsync(winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration const& account) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) DeleteDeviceAccountAsync(param::hstring const& accountId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration>) GetDeviceAccountConfigurationAsync(param::hstring const& accountId) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics2<D>;
    };
}
#endif
