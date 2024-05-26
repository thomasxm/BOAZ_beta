// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Authorization_AppCapabilityAccess_0_H
#define WINRT_Windows_Security_Authorization_AppCapabilityAccess_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
}
WINRT_EXPORT namespace winrt::Windows::System
{
    struct User;
}
WINRT_EXPORT namespace winrt::Windows::Security::Authorization::AppCapabilityAccess
{
    enum class AppCapabilityAccessStatus : int32_t
    {
        DeniedBySystem = 0,
        NotDeclaredByApp = 1,
        DeniedByUser = 2,
        UserPromptRequired = 3,
        Allowed = 4,
    };
    struct IAppCapability;
    struct IAppCapability2;
    struct IAppCapabilityAccessChangedEventArgs;
    struct IAppCapabilityStatics;
    struct AppCapability;
    struct AppCapabilityAccessChangedEventArgs;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability> = L"Windows.Security.Authorization.AppCapabilityAccess.AppCapability";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> = L"Windows.Security.Authorization.AppCapabilityAccess.AppCapabilityAccessChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus> = L"Windows.Security.Authorization.AppCapabilityAccess.AppCapabilityAccessStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability> = L"Windows.Security.Authorization.AppCapabilityAccess.IAppCapability";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability2> = L"Windows.Security.Authorization.AppCapabilityAccess.IAppCapability2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs> = L"Windows.Security.Authorization.AppCapabilityAccess.IAppCapabilityAccessChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics> = L"Windows.Security.Authorization.AppCapabilityAccess.IAppCapabilityStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>{ 0x4C49D915,0x8A2A,0x4295,{ 0x94,0x37,0x2D,0xF7,0xC3,0x96,0xAF,0xF4 } }; // 4C49D915-8A2A-4295-9437-2DF7C396AFF4
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability2>{ 0x11C7CCB6,0xC74F,0x50A3,{ 0xB9,0x60,0x88,0x00,0x87,0x67,0xD9,0x39 } }; // 11C7CCB6-C74F-50A3-B960-88008767D939
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs>{ 0x0A578D15,0xBDD7,0x457E,{ 0x8C,0xCA,0x6F,0x53,0xBD,0x2E,0x59,0x44 } }; // 0A578D15-BDD7-457E-8CCA-6F53BD2E5944
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>{ 0x7C353E2A,0x46EE,0x44E5,{ 0xAF,0x3D,0x6A,0xD3,0xFC,0x49,0xBD,0x22 } }; // 7C353E2A-46EE-44E5-AF3D-6AD3FC49BD22
    template <> struct default_interface<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability>{ using type = winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability; };
    template <> struct default_interface<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs>{ using type = winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs; };
    template <> struct abi<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CapabilityName(void**) noexcept = 0;
            virtual int32_t __stdcall get_User(void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessAsync(void**) noexcept = 0;
            virtual int32_t __stdcall CheckAccess(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_AccessChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AccessChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DisplayMessage(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayMessage(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RequestAccessForCapabilitiesAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessForCapabilitiesForUserAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateWithProcessIdForUser(void*, void*, uint32_t, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) CapabilityName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::User) User() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>) RequestAccessAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus) CheckAccess() const;
        WINRT_IMPL_AUTO(winrt::event_token) AccessChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> const& handler) const;
        using AccessChanged_revoker = impl::event_revoker<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability, &impl::abi_t<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>::remove_AccessChanged>;
        [[nodiscard]] AccessChanged_revoker AccessChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AccessChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>
    {
        template <typename D> using type = consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayMessage() const;
        WINRT_IMPL_AUTO(void) DisplayMessage(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability2>
    {
        template <typename D> using type = consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityAccessChangedEventArgs
    {
    };
    template <> struct consume<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityAccessChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>) RequestAccessForCapabilitiesAsync(param::async_iterable<hstring> const& capabilityNames) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>) RequestAccessForCapabilitiesForUserAsync(winrt::Windows::System::User const& user, param::async_iterable<hstring> const& capabilityNames) const;
        WINRT_IMPL_AUTO(winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability) Create(param::hstring const& capabilityName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability) CreateWithProcessIdForUser(winrt::Windows::System::User const& user, param::hstring const& capabilityName, uint32_t pid) const;
    };
    template <> struct consume<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>
    {
        template <typename D> using type = consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics<D>;
    };
}
#endif
