// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Authentication_Web_0_H
#define WINRT_Windows_Security_Authentication_Web_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    struct ValueSet;
}
WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Web
{
    enum class TokenBindingKeyType : int32_t
    {
        Rsa2048 = 0,
        EcdsaP256 = 1,
        AnyExisting = 2,
    };
    enum class WebAuthenticationOptions : uint32_t
    {
        None = 0,
        SilentMode = 0x1,
        UseTitle = 0x2,
        UseHttpPost = 0x4,
        UseCorporateNetwork = 0x8,
    };
    enum class WebAuthenticationStatus : int32_t
    {
        Success = 0,
        UserCancel = 1,
        ErrorHttp = 2,
    };
    struct IWebAuthenticationBrokerStatics;
    struct IWebAuthenticationBrokerStatics2;
    struct IWebAuthenticationResult;
    struct WebAuthenticationBroker;
    struct WebAuthenticationResult;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Security::Authentication::Web::IWebAuthenticationBrokerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::IWebAuthenticationBrokerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::IWebAuthenticationResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::WebAuthenticationBroker>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::WebAuthenticationResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::TokenBindingKeyType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::WebAuthenticationOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Authentication::Web::WebAuthenticationStatus>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::WebAuthenticationBroker> = L"Windows.Security.Authentication.Web.WebAuthenticationBroker";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::WebAuthenticationResult> = L"Windows.Security.Authentication.Web.WebAuthenticationResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::TokenBindingKeyType> = L"Windows.Security.Authentication.Web.TokenBindingKeyType";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::WebAuthenticationOptions> = L"Windows.Security.Authentication.Web.WebAuthenticationOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::WebAuthenticationStatus> = L"Windows.Security.Authentication.Web.WebAuthenticationStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::IWebAuthenticationBrokerStatics> = L"Windows.Security.Authentication.Web.IWebAuthenticationBrokerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::IWebAuthenticationBrokerStatics2> = L"Windows.Security.Authentication.Web.IWebAuthenticationBrokerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authentication::Web::IWebAuthenticationResult> = L"Windows.Security.Authentication.Web.IWebAuthenticationResult";
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::IWebAuthenticationBrokerStatics>{ 0x2F149F1A,0xE673,0x40B5,{ 0xBC,0x22,0x20,0x1A,0x68,0x64,0xA3,0x7B } }; // 2F149F1A-E673-40B5-BC22-201A6864A37B
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::IWebAuthenticationBrokerStatics2>{ 0x73CDFB9E,0x14E7,0x41DA,{ 0xA9,0x71,0xAA,0xF4,0x41,0x0B,0x62,0x1E } }; // 73CDFB9E-14E7-41DA-A971-AAF4410B621E
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authentication::Web::IWebAuthenticationResult>{ 0x64002B4B,0xEDE9,0x470A,{ 0xA5,0xCD,0x03,0x23,0xFA,0xF6,0xE2,0x62 } }; // 64002B4B-EDE9-470A-A5CD-0323FAF6E262
    template <> struct default_interface<winrt::Windows::Security::Authentication::Web::WebAuthenticationResult>{ using type = winrt::Windows::Security::Authentication::Web::IWebAuthenticationResult; };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::IWebAuthenticationBrokerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AuthenticateWithCallbackUriAsync(uint32_t, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall AuthenticateWithoutCallbackUriAsync(uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetCurrentApplicationCallbackUri(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::IWebAuthenticationBrokerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AuthenticateAndContinue(void*) noexcept = 0;
            virtual int32_t __stdcall AuthenticateWithCallbackUriAndContinue(void*, void*) noexcept = 0;
            virtual int32_t __stdcall AuthenticateWithCallbackUriContinuationDataAndOptionsAndContinue(void*, void*, void*, uint32_t) noexcept = 0;
            virtual int32_t __stdcall AuthenticateSilentlyAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall AuthenticateSilentlyWithOptionsAsync(void*, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authentication::Web::IWebAuthenticationResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ResponseData(void**) noexcept = 0;
            virtual int32_t __stdcall get_ResponseStatus(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ResponseErrorDetail(uint32_t*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_IWebAuthenticationBrokerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::WebAuthenticationResult>) AuthenticateAsync(winrt::Windows::Security::Authentication::Web::WebAuthenticationOptions const& options, winrt::Windows::Foundation::Uri const& requestUri, winrt::Windows::Foundation::Uri const& callbackUri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::WebAuthenticationResult>) AuthenticateAsync(winrt::Windows::Security::Authentication::Web::WebAuthenticationOptions const& options, winrt::Windows::Foundation::Uri const& requestUri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) GetCurrentApplicationCallbackUri() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::IWebAuthenticationBrokerStatics>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_IWebAuthenticationBrokerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_IWebAuthenticationBrokerStatics2
    {
        WINRT_IMPL_AUTO(void) AuthenticateAndContinue(winrt::Windows::Foundation::Uri const& requestUri) const;
        WINRT_IMPL_AUTO(void) AuthenticateAndContinue(winrt::Windows::Foundation::Uri const& requestUri, winrt::Windows::Foundation::Uri const& callbackUri) const;
        WINRT_IMPL_AUTO(void) AuthenticateAndContinue(winrt::Windows::Foundation::Uri const& requestUri, winrt::Windows::Foundation::Uri const& callbackUri, winrt::Windows::Foundation::Collections::ValueSet const& continuationData, winrt::Windows::Security::Authentication::Web::WebAuthenticationOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::WebAuthenticationResult>) AuthenticateSilentlyAsync(winrt::Windows::Foundation::Uri const& requestUri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::WebAuthenticationResult>) AuthenticateSilentlyAsync(winrt::Windows::Foundation::Uri const& requestUri, winrt::Windows::Security::Authentication::Web::WebAuthenticationOptions const& options) const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::IWebAuthenticationBrokerStatics2>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_IWebAuthenticationBrokerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authentication_Web_IWebAuthenticationResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResponseData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::WebAuthenticationStatus) ResponseStatus() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ResponseErrorDetail() const;
    };
    template <> struct consume<winrt::Windows::Security::Authentication::Web::IWebAuthenticationResult>
    {
        template <typename D> using type = consume_Windows_Security_Authentication_Web_IWebAuthenticationResult<D>;
    };
}
#endif
