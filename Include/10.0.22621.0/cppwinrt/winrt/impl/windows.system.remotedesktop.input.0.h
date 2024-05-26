// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_RemoteDesktop_Input_0_H
#define WINRT_Windows_System_RemoteDesktop_Input_0_H
WINRT_EXPORT namespace winrt::Windows::System::RemoteDesktop::Input
{
    struct IRemoteTextConnection;
    struct IRemoteTextConnectionFactory;
    struct RemoteTextConnection;
    struct RemoteTextConnectionDataHandler;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::System::RemoteDesktop::Input::IRemoteTextConnection>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Input::IRemoteTextConnectionFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Input::RemoteTextConnection>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::RemoteDesktop::Input::RemoteTextConnectionDataHandler>{ using type = delegate_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Input::RemoteTextConnection> = L"Windows.System.RemoteDesktop.Input.RemoteTextConnection";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Input::IRemoteTextConnection> = L"Windows.System.RemoteDesktop.Input.IRemoteTextConnection";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Input::IRemoteTextConnectionFactory> = L"Windows.System.RemoteDesktop.Input.IRemoteTextConnectionFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::System::RemoteDesktop::Input::RemoteTextConnectionDataHandler> = L"Windows.System.RemoteDesktop.Input.RemoteTextConnectionDataHandler";
    template <> inline constexpr guid guid_v<winrt::Windows::System::RemoteDesktop::Input::IRemoteTextConnection>{ 0x4E7BB02A,0x183E,0x5E66,{ 0xB5,0xE4,0x3E,0x6E,0x5C,0x57,0x0C,0xF1 } }; // 4E7BB02A-183E-5E66-B5E4-3E6E5C570CF1
    template <> inline constexpr guid guid_v<winrt::Windows::System::RemoteDesktop::Input::IRemoteTextConnectionFactory>{ 0x88E075C2,0x0CAE,0x596C,{ 0x85,0x0F,0x78,0xD3,0x45,0xCD,0x72,0x8B } }; // 88E075C2-0CAE-596C-850F-78D345CD728B
    template <> inline constexpr guid guid_v<winrt::Windows::System::RemoteDesktop::Input::RemoteTextConnectionDataHandler>{ 0x099FFBC8,0x8BCB,0x41B5,{ 0xB0,0x56,0x57,0xE7,0x70,0x21,0xBF,0x1B } }; // 099FFBC8-8BCB-41B5-B056-57E77021BF1B
    template <> struct default_interface<winrt::Windows::System::RemoteDesktop::Input::RemoteTextConnection>{ using type = winrt::Windows::System::RemoteDesktop::Input::IRemoteTextConnection; };
    template <> struct abi<winrt::Windows::System::RemoteDesktop::Input::IRemoteTextConnection>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall RegisterThread(uint32_t) noexcept = 0;
            virtual int32_t __stdcall UnregisterThread(uint32_t) noexcept = 0;
            virtual int32_t __stdcall ReportDataReceived(uint32_t, uint8_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::RemoteDesktop::Input::IRemoteTextConnectionFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(winrt::guid, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::RemoteDesktop::Input::RemoteTextConnectionDataHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(uint32_t, uint8_t*, bool*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_System_RemoteDesktop_Input_IRemoteTextConnection
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsEnabled() const;
        WINRT_IMPL_AUTO(void) IsEnabled(bool value) const;
        WINRT_IMPL_AUTO(void) RegisterThread(uint32_t threadId) const;
        WINRT_IMPL_AUTO(void) UnregisterThread(uint32_t threadId) const;
        WINRT_IMPL_AUTO(void) ReportDataReceived(array_view<uint8_t const> pduData) const;
    };
    template <> struct consume<winrt::Windows::System::RemoteDesktop::Input::IRemoteTextConnection>
    {
        template <typename D> using type = consume_Windows_System_RemoteDesktop_Input_IRemoteTextConnection<D>;
    };
    template <typename D>
    struct consume_Windows_System_RemoteDesktop_Input_IRemoteTextConnectionFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::System::RemoteDesktop::Input::RemoteTextConnection) CreateInstance(winrt::guid const& connectionId, winrt::Windows::System::RemoteDesktop::Input::RemoteTextConnectionDataHandler const& pduForwarder) const;
    };
    template <> struct consume<winrt::Windows::System::RemoteDesktop::Input::IRemoteTextConnectionFactory>
    {
        template <typename D> using type = consume_Windows_System_RemoteDesktop_Input_IRemoteTextConnectionFactory<D>;
    };
}
#endif
