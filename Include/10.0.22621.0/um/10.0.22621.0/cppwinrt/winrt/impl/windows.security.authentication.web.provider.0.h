// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Authentication_Web_Provider_0_H
#define WINRT_Windows_Security_Authentication_Web_Provider_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Web
{
    enum class TokenBindingKeyType : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Web::Core
{
    struct WebProviderError;
    struct WebTokenRequest;
    struct WebTokenResponse;
}
WINRT_EXPORT namespace winrt::Windows::Security::Credentials
{
    struct WebAccount;
}
WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::Core
{
    struct CryptographicKey;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
    struct IRandomAccessStream;
}
WINRT_EXPORT namespace winrt::Windows::System
{
    struct User;
}
WINRT_EXPORT namespace winrt::Windows::Web::Http
{
    struct HttpCookie;
}
WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Web::Provider
{
    enum class WebAccountClientViewType : int32_t
    {
        IdOnly = 0,
        IdAndProperties = 1,
    };
    enum class WebAccountProviderOperationKind : int32_t
    {
        RequestToken = 0,
        GetTokenSilently = 1,
        AddAccount = 2,
        ManageAccount = 3,
        DeleteAccount = 4,
        RetrieveCookies = 5,
        SignOutAccount = 6,
    };
    enum class WebAccountScope : int32_t
    {
        PerUser = 0,
        PerApplication = 1,
    };
    enum class WebAccountSelectionOptions : uint32_t
    {
        Default = 0,
        New = 0x1,
    };
    struct IWebAccountClientView;
    struct IWebAccountClientViewFactory;
    struct IWebAccountManagerStatics;
    struct IWebAccountManagerStatics2;
    struct IWebAccountManagerStatics3;
    struct IWebAccountManagerStatics4;
    struct IWebAccountMapManagerStatics;
    struct IWebAccountProviderAddAccountOperation;
    struct IWebAccountProviderBaseReportOperation;
    struct IWebAccountProviderDeleteAccountOperation;
    struct IWebAccountProviderManageAccountOperation;
    struct IWebAccountProviderOperation;
    struct IWebAccountProviderRetrieveCookiesOperation;
    struct IWebAccountProviderSignOutAccountOperation;
    struct IWebAccountProviderSilentReportOperation;
    struct IWebAccountProviderTokenObjects;
    struct IWebAccountProviderTokenObjects2;
    struct IWebAccountProviderTokenOperation;
    struct IWebAccountProviderUIReportOperation;
    struct IWebAccountScopeManagerStatics;
    struct IWebProviderTokenRequest;
    struct IWebProviderTokenRequest2;
    struct IWebProviderTokenRequest3;
    struct IWebProviderTokenResponse;
    struct IWebProviderTokenResponseFactory;
    struct WebAccountClientView;
    struct WebAccountManager;
    struct WebAccountProviderAddAccountOperation;
    struct WebAccountProviderDeleteAccountOperation;
    struct WebAccountProviderGetTokenSilentOperation;
    struct WebAccountProviderManageAccountOperation;
    struct WebAccountProviderRequestTokenOperation;
    struct WebAccountProviderRetrieveCookiesOperation;
    struct WebAccountProviderSignOutAccountOperation;
    struct WebAccountProviderTriggerDetails;
    struct WebProviderTokenRequest;
    struct WebProviderTokenResponse;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientView>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderUIReportOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponse>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponseFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientView>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderAddAccountOperation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderDeleteAccountOperation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderGetTokenSilentOperation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderManageAccountOperation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderRequestTokenOperation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderRetrieveCookiesOperation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderSignOutAccountOperation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientViewType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderOperationKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountScope>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::Provider::WebAccountSelectionOptions>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientView> = L"Windows.Security.Authentication.Web.Provider.WebAccountClientView";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountManager> = L"Windows.Security.Authentication.Web.Provider.WebAccountManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderAddAccountOperation> = L"Windows.Security.Authentication.Web.Provider.WebAccountProviderAddAccountOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderDeleteAccountOperation> = L"Windows.Security.Authentication.Web.Provider.WebAccountProviderDeleteAccountOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderGetTokenSilentOperation> = L"Windows.Security.Authentication.Web.Provider.WebAccountProviderGetTokenSilentOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderManageAccountOperation> = L"Windows.Security.Authentication.Web.Provider.WebAccountProviderManageAccountOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderRequestTokenOperation> = L"Windows.Security.Authentication.Web.Provider.WebAccountProviderRequestTokenOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderRetrieveCookiesOperation> = L"Windows.Security.Authentication.Web.Provider.WebAccountProviderRetrieveCookiesOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderSignOutAccountOperation> = L"Windows.Security.Authentication.Web.Provider.WebAccountProviderSignOutAccountOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderTriggerDetails> = L"Windows.Security.Authentication.Web.Provider.WebAccountProviderTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenRequest> = L"Windows.Security.Authentication.Web.Provider.WebProviderTokenRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse> = L"Windows.Security.Authentication.Web.Provider.WebProviderTokenResponse";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientViewType> = L"Windows.Security.Authentication.Web.Provider.WebAccountClientViewType";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderOperationKind> = L"Windows.Security.Authentication.Web.Provider.WebAccountProviderOperationKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountScope> = L"Windows.Security.Authentication.Web.Provider.WebAccountScope";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::WebAccountSelectionOptions> = L"Windows.Security.Authentication.Web.Provider.WebAccountSelectionOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientView> = L"Windows.Security.Authentication.Web.Provider.IWebAccountClientView";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory> = L"Windows.Security.Authentication.Web.Provider.IWebAccountClientViewFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics> = L"Windows.Security.Authentication.Web.Provider.IWebAccountManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics2> = L"Windows.Security.Authentication.Web.Provider.IWebAccountManagerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3> = L"Windows.Security.Authentication.Web.Provider.IWebAccountManagerStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4> = L"Windows.Security.Authentication.Web.Provider.IWebAccountManagerStatics4";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics> = L"Windows.Security.Authentication.Web.Provider.IWebAccountMapManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderAddAccountOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderBaseReportOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderDeleteAccountOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderManageAccountOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderRetrieveCookiesOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderSignOutAccountOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderSilentReportOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderTokenObjects";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects2> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderTokenObjects2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderTokenOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderUIReportOperation> = L"Windows.Security.Authentication.Web.Provider.IWebAccountProviderUIReportOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics> = L"Windows.Security.Authentication.Web.Provider.IWebAccountScopeManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest> = L"Windows.Security.Authentication.Web.Provider.IWebProviderTokenRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest2> = L"Windows.Security.Authentication.Web.Provider.IWebProviderTokenRequest2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3> = L"Windows.Security.Authentication.Web.Provider.IWebProviderTokenRequest3";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponse> = L"Windows.Security.Authentication.Web.Provider.IWebProviderTokenResponse";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponseFactory> = L"Windows.Security.Authentication.Web.Provider.IWebProviderTokenResponseFactory";
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientView>{ 0xE7BD66BA,0x0BC7,0x4C66,{ 0xBF,0xD4,0x65,0xD3,0x08,0x2C,0xBC,0xA8 } }; // E7BD66BA-0BC7-4C66-BFD4-65D3082CBCA8
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory>{ 0x616D16A4,0xDE22,0x4855,{ 0xA3,0x26,0x06,0xCE,0xBF,0x2A,0x3F,0x23 } }; // 616D16A4-DE22-4855-A326-06CEBF2A3F23
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>{ 0xB2E8E1A6,0xD49A,0x4032,{ 0x84,0xBF,0x1A,0x28,0x47,0x74,0x7B,0xF1 } }; // B2E8E1A6-D49A-4032-84BF-1A2847747BF1
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics2>{ 0x68A7A829,0x2D5F,0x4653,{ 0x8B,0xB0,0xBD,0x2F,0xA6,0xBD,0x2D,0x87 } }; // 68A7A829-2D5F-4653-8BB0-BD2FA6BD2D87
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3>{ 0xDD4523A6,0x8A4F,0x4AA2,{ 0xB1,0x5E,0x03,0xF5,0x50,0xAF,0x13,0x59 } }; // DD4523A6-8A4F-4AA2-B15E-03F550AF1359
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4>{ 0x59EBC2D2,0xF7DB,0x412F,{ 0xBC,0x3F,0xF2,0xFE,0xA0,0x44,0x30,0xB4 } }; // 59EBC2D2-F7DB-412F-BC3F-F2FEA04430B4
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics>{ 0xE8FA446F,0x3A1B,0x48A4,{ 0x8E,0x90,0x1E,0x59,0xCA,0x6F,0x54,0xDB } }; // E8FA446F-3A1B-48A4-8E90-1E59CA6F54DB
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation>{ 0x73EBDCCF,0x4378,0x4C79,{ 0x93,0x35,0xA5,0xD7,0xAB,0x81,0x59,0x4E } }; // 73EBDCCF-4378-4C79-9335-A5D7AB81594E
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation>{ 0xBBA4ACBB,0x993B,0x4D57,{ 0xBB,0xE4,0x14,0x21,0xE3,0x66,0x8B,0x4C } }; // BBA4ACBB-993B-4D57-BBE4-1421E3668B4C
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation>{ 0x0ABB48B8,0x9E01,0x49C9,{ 0xA3,0x55,0x7D,0x48,0xCA,0xF7,0xD6,0xCA } }; // 0ABB48B8-9E01-49C9-A355-7D48CAF7D6CA
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation>{ 0xED20DC5C,0xD21B,0x463E,{ 0xA9,0xB7,0xC1,0xFD,0x0E,0xDA,0xE9,0x78 } }; // ED20DC5C-D21B-463E-A9B7-C1FD0EDAE978
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>{ 0x6D5D2426,0x10B1,0x419A,{ 0xA4,0x4E,0xF9,0xC5,0x16,0x15,0x74,0xE6 } }; // 6D5D2426-10B1-419A-A44E-F9C5161574E6
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation>{ 0x5A040441,0x0FA3,0x4AB1,{ 0xA0,0x1C,0x20,0xB1,0x10,0x35,0x85,0x94 } }; // 5A040441-0FA3-4AB1-A01C-20B110358594
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation>{ 0xB890E21D,0x0C55,0x47BC,{ 0x8C,0x72,0x04,0xA6,0xFC,0x7C,0xAC,0x07 } }; // B890E21D-0C55-47BC-8C72-04A6FC7CAC07
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation>{ 0xE0B545F8,0x3B0F,0x44DA,{ 0x92,0x4C,0x7B,0x18,0xBA,0xAA,0x62,0xA9 } }; // E0B545F8-3B0F-44DA-924C-7B18BAAA62A9
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects>{ 0x408F284B,0x1328,0x42DB,{ 0x89,0xA4,0x0B,0xCE,0x7A,0x71,0x7D,0x8E } }; // 408F284B-1328-42DB-89A4-0BCE7A717D8E
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects2>{ 0x1020B893,0x5CA5,0x4FFF,{ 0x95,0xFB,0xB8,0x20,0x27,0x3F,0xC3,0x95 } }; // 1020B893-5CA5-4FFF-95FB-B820273FC395
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation>{ 0x95C613BE,0x2034,0x4C38,{ 0x94,0x34,0xD2,0x6C,0x14,0xB2,0xB4,0xB2 } }; // 95C613BE-2034-4C38-9434-D26C14B2B4B2
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderUIReportOperation>{ 0x28FF92D3,0x8F80,0x42FB,{ 0x94,0x4F,0xB2,0x10,0x7B,0xBD,0x42,0xE6 } }; // 28FF92D3-8F80-42FB-944F-B2107BBD42E6
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics>{ 0x5C6CE37C,0x12B2,0x423A,{ 0xBF,0x3D,0x85,0xB8,0xD7,0xE5,0x36,0x56 } }; // 5C6CE37C-12B2-423A-BF3D-85B8D7E53656
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest>{ 0x1E18778B,0x8805,0x454B,{ 0x9F,0x11,0x46,0x8D,0x2A,0xF1,0x09,0x5A } }; // 1E18778B-8805-454B-9F11-468D2AF1095A
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest2>{ 0xB5D72E4C,0x10B1,0x4AA6,{ 0x88,0xB1,0x0B,0x6C,0x9E,0x0C,0x1E,0x46 } }; // B5D72E4C-10B1-4AA6-88B1-0B6C9E0C1E46
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3>{ 0x1B2716AA,0x4289,0x446E,{ 0x92,0x56,0xDA,0xFB,0x6F,0x66,0xA5,0x1E } }; // 1B2716AA-4289-446E-9256-DAFB6F66A51E
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponse>{ 0xEF213793,0xEF55,0x4186,{ 0xB7,0xCE,0x8C,0xB2,0xE7,0xF9,0x84,0x9E } }; // EF213793-EF55-4186-B7CE-8CB2E7F9849E
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponseFactory>{ 0xFA49D99A,0x25BA,0x4077,{ 0x9C,0xFA,0x9D,0xB4,0xDE,0xA7,0xB7,0x1A } }; // FA49D99A-25BA-4077-9CFA-9DB4DEA7B71A
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientView>{ using type = winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientView; };
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderAddAccountOperation>{ using type = winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation; };
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderDeleteAccountOperation>{ using type = winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation; };
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderGetTokenSilentOperation>{ using type = winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation; };
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderManageAccountOperation>{ using type = winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation; };
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderRequestTokenOperation>{ using type = winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation; };
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderRetrieveCookiesOperation>{ using type = winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation; };
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderSignOutAccountOperation>{ using type = winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation; };
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderTriggerDetails>{ using type = winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects; };
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenRequest>{ using type = winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest; };
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse>{ using type = winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponse; };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientView>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ApplicationCallbackUri(void**) noexcept = 0;
            virtual int32_t __stdcall get_Type(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AccountPairwiseId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(int32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateWithPairwiseId(int32_t, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall UpdateWebAccountPropertiesAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall AddWebAccountAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall DeleteWebAccountAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindAllProviderWebAccountsAsync(void**) noexcept = 0;
            virtual int32_t __stdcall PushCookiesAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetViewAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ClearViewAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetViewsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetWebAccountPictureAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ClearWebAccountPictureAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall PullCookiesAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FindAllProviderWebAccountsForUserAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall AddWebAccountForUserAsync(void*, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall AddWebAccountWithScopeForUserAsync(void*, void*, void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall AddWebAccountWithScopeAndMapForUserAsync(void*, void*, void*, void*, int32_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall InvalidateAppCacheForAllAccountsAsync(void**) noexcept = 0;
            virtual int32_t __stdcall InvalidateAppCacheForAccountAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AddWebAccountWithScopeAndMapAsync(void*, void*, void*, int32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetPerAppToPerUserAccountAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetPerUserFromPerAppAccountAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ClearPerUserFromPerAppAccountAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ReportCompleted() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ReportCompleted() noexcept = 0;
            virtual int32_t __stdcall ReportError(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_WebAccount(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_WebAccount(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompleted() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Kind(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Context(void**) noexcept = 0;
            virtual int32_t __stdcall get_Cookies(void**) noexcept = 0;
            virtual int32_t __stdcall put_Uri(void*) noexcept = 0;
            virtual int32_t __stdcall get_Uri(void**) noexcept = 0;
            virtual int32_t __stdcall get_ApplicationCallbackUri(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_WebAccount(void**) noexcept = 0;
            virtual int32_t __stdcall get_ApplicationCallbackUri(void**) noexcept = 0;
            virtual int32_t __stdcall get_ClientId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ReportUserInteractionRequired() noexcept = 0;
            virtual int32_t __stdcall ReportUserInteractionRequiredWithError(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Operation(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_User(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ProviderRequest(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProviderResponses(void**) noexcept = 0;
            virtual int32_t __stdcall put_CacheExpirationTime(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_CacheExpirationTime(int64_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderUIReportOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ReportUserCanceled() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AddWebAccountWithScopeAsync(void*, void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall SetScopeAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetScope(void*, int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ClientRequest(void**) noexcept = 0;
            virtual int32_t __stdcall get_WebAccounts(void**) noexcept = 0;
            virtual int32_t __stdcall get_WebAccountSelectionOptions(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ApplicationCallbackUri(void**) noexcept = 0;
            virtual int32_t __stdcall GetApplicationTokenBindingKeyAsync(int32_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetApplicationTokenBindingKeyIdAsync(int32_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ApplicationPackageFamilyName(void**) noexcept = 0;
            virtual int32_t __stdcall get_ApplicationProcessName(void**) noexcept = 0;
            virtual int32_t __stdcall CheckApplicationForCapabilityAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponse>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ClientResponse(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponseFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountClientView
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) ApplicationCallbackUri() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientViewType) Type() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AccountPairwiseId() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientView>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountClientView<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountClientViewFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientView) Create(winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientViewType const& viewType, winrt::Windows::Foundation::Uri const& applicationCallbackUri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientView) CreateWithPairwiseId(winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientViewType const& viewType, winrt::Windows::Foundation::Uri const& applicationCallbackUri, param::hstring const& accountPairwiseId) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountClientViewFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) UpdateWebAccountPropertiesAsync(winrt::Windows::Security::Credentials::WebAccount const& webAccount, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& additionalProperties) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccount>) AddWebAccountAsync(param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) DeleteWebAccountAsync(winrt::Windows::Security::Credentials::WebAccount const& webAccount) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::WebAccount>>) FindAllProviderWebAccountsAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) PushCookiesAsync(winrt::Windows::Foundation::Uri const& uri, param::async_vector_view<winrt::Windows::Web::Http::HttpCookie> const& cookies) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetViewAsync(winrt::Windows::Security::Credentials::WebAccount const& webAccount, winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientView const& view) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ClearViewAsync(winrt::Windows::Security::Credentials::WebAccount const& webAccount, winrt::Windows::Foundation::Uri const& applicationCallbackUri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientView>>) GetViewsAsync(winrt::Windows::Security::Credentials::WebAccount const& webAccount) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetWebAccountPictureAsync(winrt::Windows::Security::Credentials::WebAccount const& webAccount, winrt::Windows::Storage::Streams::IRandomAccessStream const& webAccountPicture) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ClearWebAccountPictureAsync(winrt::Windows::Security::Credentials::WebAccount const& webAccount) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) PullCookiesAsync(param::hstring const& uriString, param::hstring const& callerPFN) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics2>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::WebAccount>>) FindAllProviderWebAccountsForUserAsync(winrt::Windows::System::User const& user) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccount>) AddWebAccountForUserAsync(winrt::Windows::System::User const& user, param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccount>) AddWebAccountForUserAsync(winrt::Windows::System::User const& user, param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, winrt::Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccount>) AddWebAccountForUserAsync(winrt::Windows::System::User const& user, param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, winrt::Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope, param::hstring const& perUserWebAccountId) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics4
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) InvalidateAppCacheForAllAccountsAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) InvalidateAppCacheForAccountAsync(winrt::Windows::Security::Credentials::WebAccount const& webAccount) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics4<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountMapManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccount>) AddWebAccountAsync(param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, winrt::Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope, param::hstring const& perUserWebAccountId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetPerAppToPerUserAccountAsync(winrt::Windows::Security::Credentials::WebAccount const& perAppAccount, param::hstring const& perUserWebAccountId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccount>) GetPerUserFromPerAppAccountAsync(winrt::Windows::Security::Credentials::WebAccount const& perAppAccount) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ClearPerUserFromPerAppAccountAsync(winrt::Windows::Security::Credentials::WebAccount const& perAppAccount) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountMapManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderAddAccountOperation
    {
        WINRT_IMPL_AUTO(void) ReportCompleted() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderAddAccountOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderBaseReportOperation
    {
        WINRT_IMPL_AUTO(void) ReportCompleted() const;
        WINRT_IMPL_AUTO(void) ReportError(winrt::Windows::Security::Authentication::Web::Core::WebProviderError const& value) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderBaseReportOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderDeleteAccountOperation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::WebAccount) WebAccount() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderDeleteAccountOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderManageAccountOperation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::WebAccount) WebAccount() const;
        WINRT_IMPL_AUTO(void) ReportCompleted() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderManageAccountOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderOperation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderOperationKind) Kind() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderRetrieveCookiesOperation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Context() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Http::HttpCookie>) Cookies() const;
        WINRT_IMPL_AUTO(void) Uri(winrt::Windows::Foundation::Uri const& uri) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Uri() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) ApplicationCallbackUri() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderRetrieveCookiesOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderSignOutAccountOperation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::WebAccount) WebAccount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) ApplicationCallbackUri() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ClientId() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderSignOutAccountOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderSilentReportOperation
    {
        WINRT_IMPL_AUTO(void) ReportUserInteractionRequired() const;
        WINRT_IMPL_AUTO(void) ReportUserInteractionRequired(winrt::Windows::Security::Authentication::Web::Core::WebProviderError const& value) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderSilentReportOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenObjects
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation) Operation() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenObjects<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenObjects2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::User) User() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects2>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenObjects2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenOperation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenRequest) ProviderRequest() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse>) ProviderResponses() const;
        WINRT_IMPL_AUTO(void) CacheExpirationTime(winrt::Windows::Foundation::DateTime const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) CacheExpirationTime() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderUIReportOperation
    {
        WINRT_IMPL_AUTO(void) ReportUserCanceled() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderUIReportOperation>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderUIReportOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebAccountScopeManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccount>) AddWebAccountAsync(param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, winrt::Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetScopeAsync(winrt::Windows::Security::Credentials::WebAccount const& webAccount, winrt::Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope) const;
        WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Provider::WebAccountScope) GetScope(winrt::Windows::Security::Credentials::WebAccount const& webAccount) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebAccountScopeManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest) ClientRequest() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::WebAccount>) WebAccounts() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Provider::WebAccountSelectionOptions) WebAccountSelectionOptions() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) ApplicationCallbackUri() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Cryptography::Core::CryptographicKey>) GetApplicationTokenBindingKeyAsync(winrt::Windows::Security::Authentication::Web::TokenBindingKeyType const& keyType, winrt::Windows::Foundation::Uri const& target) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) GetApplicationTokenBindingKeyIdAsync(winrt::Windows::Security::Authentication::Web::TokenBindingKeyType const& keyType, winrt::Windows::Foundation::Uri const& target) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest2>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ApplicationPackageFamilyName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ApplicationProcessName() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) CheckApplicationForCapabilityAsync(param::hstring const& capabilityName) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest3<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenResponse
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse) ClientResponse() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponse>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenResponse<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenResponseFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse) Create(winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse const& webTokenResponse) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponseFactory>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenResponseFactory<D>;
    };
}
#endif
