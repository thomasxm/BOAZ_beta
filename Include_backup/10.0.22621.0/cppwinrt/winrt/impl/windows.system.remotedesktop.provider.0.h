// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_RemoteDesktop_Provider_0_H
#define WINRT_Windows_System_RemoteDesktop_Provider_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::UI
{
    struct WindowId;
}
WINRT_EXPORT namespace winrt::Windows::System::RemoteDesktop::Provider
{
    enum class RemoteDesktopConnectionStatus : int32_t
    {
        Connecting = 0,
        Connected = 1,
        UserInputNeeded = 2,
        Disconnected = 3,
    };
    enum class RemoteDesktopLocalAction : int32_t
    {
        ShowBluetoothSettings = 0,
    };
    struct IPerformLocalActionRequestedEventArgs;
    struct IRemoteDesktopConnectionInfo;
    struct IRemoteDesktopConnectionInfoStatics;
    struct IRemoteDesktopConnectionRemoteInfo;
    struct IRemoteDesktopConnectionRemoteInfoStatics;
    struct IRemoteDesktopInfo;
    struct IRemoteDesktopInfoFactory;
    struct IRemoteDesktopRegistrarStatics;
    struct PerformLocalActionRequestedEventArgs;
    struct RemoteDesktopConnectionInfo;
    struct RemoteDesktopConnectionRemoteInfo;
    struct RemoteDesktopInfo;
    struct RemoteDesktopRegistrar;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::IPerformLocalActionRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfoStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfoStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfoFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopRegistrarStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::PerformLocalActionRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopRegistrar>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopLocalAction>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::PerformLocalActionRequestedEventArgs> = L"Windows.System.RemoteDesktop.Provider.PerformLocalActionRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionInfo> = L"Windows.System.RemoteDesktop.Provider.RemoteDesktopConnectionInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo> = L"Windows.System.RemoteDesktop.Provider.RemoteDesktopConnectionRemoteInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo> = L"Windows.System.RemoteDesktop.Provider.RemoteDesktopInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopRegistrar> = L"Windows.System.RemoteDesktop.Provider.RemoteDesktopRegistrar";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionStatus> = L"Windows.System.RemoteDesktop.Provider.RemoteDesktopConnectionStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopLocalAction> = L"Windows.System.RemoteDesktop.Provider.RemoteDesktopLocalAction";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::IPerformLocalActionRequestedEventArgs> = L"Windows.System.RemoteDesktop.Provider.IPerformLocalActionRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfo> = L"Windows.System.RemoteDesktop.Provider.IRemoteDesktopConnectionInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfoStatics> = L"Windows.System.RemoteDesktop.Provider.IRemoteDesktopConnectionInfoStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo> = L"Windows.System.RemoteDesktop.Provider.IRemoteDesktopConnectionRemoteInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfoStatics> = L"Windows.System.RemoteDesktop.Provider.IRemoteDesktopConnectionRemoteInfoStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfo> = L"Windows.System.RemoteDesktop.Provider.IRemoteDesktopInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfoFactory> = L"Windows.System.RemoteDesktop.Provider.IRemoteDesktopInfoFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopRegistrarStatics> = L"Windows.System.RemoteDesktop.Provider.IRemoteDesktopRegistrarStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::System::RemoteDesktop::Provider::IPerformLocalActionRequestedEventArgs>{ 0x59359F4F,0x0862,0x53A3,{ 0xA3,0xB3,0xC9,0x32,0xFB,0x71,0x8C,0xDC } }; // 59359F4F-0862-53A3-A3B3-C932FB718CDC
    template <> inline constexpr guid guid_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfo>{ 0x68BD69D6,0x6DEA,0x543B,{ 0xB7,0x37,0xF3,0x47,0x91,0x9F,0x50,0x93 } }; // 68BD69D6-6DEA-543B-B737-F347919F5093
    template <> inline constexpr guid guid_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfoStatics>{ 0x4A7DC5A1,0x3368,0x5A75,{ 0xBB,0x78,0x80,0x7D,0xF7,0xEB,0xC4,0x39 } }; // 4A7DC5A1-3368-5A75-BB78-807DF7EBC439
    template <> inline constexpr guid guid_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo>{ 0x2A3DFA7E,0xA7AB,0x547E,{ 0x9A,0x6A,0x4C,0x56,0x5B,0xBB,0x8D,0x71 } }; // 2A3DFA7E-A7AB-547E-9A6A-4C565BBB8D71
    template <> inline constexpr guid guid_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfoStatics>{ 0xB590E64A,0xE4C9,0x53E8,{ 0xB8,0x3D,0xA0,0xDB,0x36,0x76,0x24,0x6A } }; // B590E64A-E4C9-53E8-B83D-A0DB3676246A
    template <> inline constexpr guid guid_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfo>{ 0xD185BB25,0x2F1E,0x5098,{ 0xB9,0xE0,0xF4,0x6D,0x63,0x58,0xC5,0xC4 } }; // D185BB25-2F1E-5098-B9E0-F46D6358C5C4
    template <> inline constexpr guid guid_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfoFactory>{ 0xAD0E8D58,0xB56F,0x5A8B,{ 0xB4,0x19,0x80,0x02,0xEE,0x0C,0x5E,0xE9 } }; // AD0E8D58-B56F-5A8B-B419-8002EE0C5EE9
    template <> inline constexpr guid guid_v<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopRegistrarStatics>{ 0x687C2750,0x46D9,0x5DE3,{ 0x8D,0xC3,0x84,0xA9,0x20,0x2C,0xEC,0xFB } }; // 687C2750-46D9-5DE3-8DC3-84A9202CECFB
    template <> struct default_interface<winrt::Windows::System::RemoteDesktop::Provider::PerformLocalActionRequestedEventArgs>{ using type = winrt::Windows::System::RemoteDesktop::Provider::IPerformLocalActionRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionInfo>{ using type = winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfo; };
    template <> struct default_interface<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo>{ using type = winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo; };
    template <> struct default_interface<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo>{ using type = winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfo; };
    template <> struct abi<winrt::Windows::System::RemoteDesktop::Provider::IPerformLocalActionRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Action(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetConnectionStatus(int32_t) noexcept = 0;
            virtual int32_t __stdcall SwitchToLocalSession() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfoStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForLaunchUri(void*, struct struct_Windows_UI_WindowId, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ReportSwitched() noexcept = 0;
            virtual int32_t __stdcall add_SwitchToLocalSessionRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SwitchToLocalSessionRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_PerformLocalActionRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PerformLocalActionRequested(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfoStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsSwitchSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall GetForLaunchUri(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfoFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopRegistrarStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DesktopInfos(void**) noexcept = 0;
            virtual int32_t __stdcall IsSwitchToLocalSessionEnabled(bool*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_System_RemoteDesktop_Provider_IPerformLocalActionRequestedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopLocalAction) Action() const;
    };
    template <> struct consume<winrt::Windows::System::RemoteDesktop::Provider::IPerformLocalActionRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_System_RemoteDesktop_Provider_IPerformLocalActionRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionInfo
    {
        WINRT_IMPL_AUTO(void) SetConnectionStatus(winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionStatus const& value) const;
        WINRT_IMPL_AUTO(void) SwitchToLocalSession() const;
    };
    template <> struct consume<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfo>
    {
        template <typename D> using type = consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionInfo<D>;
    };
    template <typename D>
    struct consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionInfoStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionInfo) GetForLaunchUri(winrt::Windows::Foundation::Uri const& launchUri, winrt::Windows::UI::WindowId const& windowId) const;
    };
    template <> struct consume<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfoStatics>
    {
        template <typename D> using type = consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionInfoStatics<D>;
    };
    template <typename D>
    struct consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfo
    {
        WINRT_IMPL_AUTO(void) ReportSwitched() const;
        WINRT_IMPL_AUTO(winrt::event_token) SwitchToLocalSessionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using SwitchToLocalSessionRequested_revoker = impl::event_revoker<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo, &impl::abi_t<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo>::remove_SwitchToLocalSessionRequested>;
        [[nodiscard]] SwitchToLocalSessionRequested_revoker SwitchToLocalSessionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) SwitchToLocalSessionRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) PerformLocalActionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo, winrt::Windows::System::RemoteDesktop::Provider::PerformLocalActionRequestedEventArgs> const& handler) const;
        using PerformLocalActionRequested_revoker = impl::event_revoker<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo, &impl::abi_t<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo>::remove_PerformLocalActionRequested>;
        [[nodiscard]] PerformLocalActionRequested_revoker PerformLocalActionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo, winrt::Windows::System::RemoteDesktop::Provider::PerformLocalActionRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) PerformLocalActionRequested(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo>
    {
        template <typename D> using type = consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfo<D>;
    };
    template <typename D>
    struct consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfoStatics
    {
        WINRT_IMPL_AUTO(bool) IsSwitchSupported() const;
        WINRT_IMPL_AUTO(winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo) GetForLaunchUri(winrt::Windows::Foundation::Uri const& launchUri) const;
    };
    template <> struct consume<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfoStatics>
    {
        template <typename D> using type = consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfoStatics<D>;
    };
    template <typename D>
    struct consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
    };
    template <> struct consume<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfo>
    {
        template <typename D> using type = consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopInfo<D>;
    };
    template <typename D>
    struct consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopInfoFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo) CreateInstance(param::hstring const& id, param::hstring const& displayName) const;
    };
    template <> struct consume<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfoFactory>
    {
        template <typename D> using type = consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopInfoFactory<D>;
    };
    template <typename D>
    struct consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopRegistrarStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo>) DesktopInfos() const;
        WINRT_IMPL_AUTO(bool) IsSwitchToLocalSessionEnabled() const;
    };
    template <> struct consume<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopRegistrarStatics>
    {
        template <typename D> using type = consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopRegistrarStatics<D>;
    };
}
#endif
