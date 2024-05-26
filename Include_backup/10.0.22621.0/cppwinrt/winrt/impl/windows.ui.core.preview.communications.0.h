// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Core_Preview_Communications_0_H
#define WINRT_Windows_UI_Core_Preview_Communications_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct Deferral;
    struct EventRegistrationToken;
    struct Rect;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::UI::Core::Preview::Communications
{
    enum class PreviewMeetingInfoDisplayKind : int32_t
    {
        OrganizerAndTime = 0,
        OrganizerTimeAndTitle = 1,
    };
    enum class PreviewSystemState : int32_t
    {
        Preparing = 0,
        Rebooting = 1,
        Error = 2,
        SessionPaused = 3,
        Ready = 4,
    };
    enum class PreviewTeamEndMeetingKind : int32_t
    {
        ShowDefaultView = 0,
        CloseView = 1,
    };
    enum class PreviewTeamViewCommand : int32_t
    {
        ToggleCallControl = 0,
        ShowPeople = 1,
        ShowMessaging = 2,
        ShowContent = 3,
        ToggleMicrophone = 4,
        ToggleCamera = 5,
        ShowCalendar = 6,
        ToggleScreenSharing = 7,
        ToggleFullScreen = 8,
    };
    struct IPreviewTeamCleanupRequestedEventArgs;
    struct IPreviewTeamCommandInvokedEventArgs;
    struct IPreviewTeamDeviceCredentials;
    struct IPreviewTeamEndMeetingRequestedEventArgs;
    struct IPreviewTeamJoinMeetingRequestedEventArgs;
    struct IPreviewTeamView;
    struct IPreviewTeamView2;
    struct IPreviewTeamViewStatics;
    struct PreviewTeamCleanupRequestedEventArgs;
    struct PreviewTeamCommandInvokedEventArgs;
    struct PreviewTeamDeviceCredentials;
    struct PreviewTeamEndMeetingRequestedEventArgs;
    struct PreviewTeamJoinMeetingRequestedEventArgs;
    struct PreviewTeamView;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCleanupRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCommandInvokedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamEndMeetingRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamJoinMeetingRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamViewStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCleanupRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCommandInvokedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamDeviceCredentials>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamJoinMeetingRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::PreviewMeetingInfoDisplayKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::PreviewSystemState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamViewCommand>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCleanupRequestedEventArgs> = L"Windows.UI.Core.Preview.Communications.PreviewTeamCleanupRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCommandInvokedEventArgs> = L"Windows.UI.Core.Preview.Communications.PreviewTeamCommandInvokedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamDeviceCredentials> = L"Windows.UI.Core.Preview.Communications.PreviewTeamDeviceCredentials";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingRequestedEventArgs> = L"Windows.UI.Core.Preview.Communications.PreviewTeamEndMeetingRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamJoinMeetingRequestedEventArgs> = L"Windows.UI.Core.Preview.Communications.PreviewTeamJoinMeetingRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView> = L"Windows.UI.Core.Preview.Communications.PreviewTeamView";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::PreviewMeetingInfoDisplayKind> = L"Windows.UI.Core.Preview.Communications.PreviewMeetingInfoDisplayKind";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::PreviewSystemState> = L"Windows.UI.Core.Preview.Communications.PreviewSystemState";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingKind> = L"Windows.UI.Core.Preview.Communications.PreviewTeamEndMeetingKind";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamViewCommand> = L"Windows.UI.Core.Preview.Communications.PreviewTeamViewCommand";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCleanupRequestedEventArgs> = L"Windows.UI.Core.Preview.Communications.IPreviewTeamCleanupRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCommandInvokedEventArgs> = L"Windows.UI.Core.Preview.Communications.IPreviewTeamCommandInvokedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials> = L"Windows.UI.Core.Preview.Communications.IPreviewTeamDeviceCredentials";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamEndMeetingRequestedEventArgs> = L"Windows.UI.Core.Preview.Communications.IPreviewTeamEndMeetingRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamJoinMeetingRequestedEventArgs> = L"Windows.UI.Core.Preview.Communications.IPreviewTeamJoinMeetingRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView> = L"Windows.UI.Core.Preview.Communications.IPreviewTeamView";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView2> = L"Windows.UI.Core.Preview.Communications.IPreviewTeamView2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamViewStatics> = L"Windows.UI.Core.Preview.Communications.IPreviewTeamViewStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCleanupRequestedEventArgs>{ 0xF0190610,0x05AF,0x4250,{ 0xB9,0x6A,0xA7,0x4E,0xDE,0xF7,0x7A,0x0D } }; // F0190610-05AF-4250-B96A-A74EDEF77A0D
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCommandInvokedEventArgs>{ 0x661F4165,0xFE71,0x44AF,{ 0x95,0x68,0x6C,0xC7,0xCF,0x29,0xCD,0x4C } }; // 661F4165-FE71-44AF-9568-6CC7CF29CD4C
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials>{ 0x8959C9B9,0x02FC,0x4D1D,{ 0x89,0x21,0xD6,0x1E,0x77,0x66,0xCB,0x89 } }; // 8959C9B9-02FC-4D1D-8921-D61E7766CB89
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamEndMeetingRequestedEventArgs>{ 0x10B149E1,0xB6F1,0x4CA7,{ 0xB4,0xCE,0x2C,0x66,0xA4,0xA6,0x46,0x99 } }; // 10B149E1-B6F1-4CA7-B4CE-2C66A4A64699
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamJoinMeetingRequestedEventArgs>{ 0x421E6ADB,0x98D7,0x41AE,{ 0xBA,0x49,0x6C,0xAF,0x55,0x9B,0x8F,0x5A } }; // 421E6ADB-98D7-41AE-BA49-6CAF559B8F5A
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>{ 0x6F616677,0x02AE,0x49A0,{ 0xAA,0x50,0x86,0x2D,0x07,0x8C,0xF9,0xB1 } }; // 6F616677-02AE-49A0-AA50-862D078CF9B1
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView2>{ 0xBD44B2A2,0x0D77,0x416D,{ 0xA3,0x70,0x9E,0xA5,0xEC,0xE4,0x62,0x29 } }; // BD44B2A2-0D77-416D-A370-9EA5ECE46229
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamViewStatics>{ 0xFE241233,0xD49C,0x49EE,{ 0xB7,0x98,0xEC,0x31,0xD9,0x54,0x39,0x38 } }; // FE241233-D49C-49EE-B798-EC31D9543938
    template <> struct default_interface<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCleanupRequestedEventArgs>{ using type = winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCleanupRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCommandInvokedEventArgs>{ using type = winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCommandInvokedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamDeviceCredentials>{ using type = winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials; };
    template <> struct default_interface<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingRequestedEventArgs>{ using type = winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamEndMeetingRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamJoinMeetingRequestedEventArgs>{ using type = winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamJoinMeetingRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView>{ using type = winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView; };
    template <> struct abi<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCleanupRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCommandInvokedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Command(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UserPrincipalName(void**) noexcept = 0;
            virtual int32_t __stdcall get_DomainUserName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Password(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamEndMeetingRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamJoinMeetingRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
            virtual int32_t __stdcall get_MeetingUri(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetTitle(void*) noexcept = 0;
            virtual int32_t __stdcall EnterFullScreen() noexcept = 0;
            virtual int32_t __stdcall LeaveFullScreen() noexcept = 0;
            virtual int32_t __stdcall RequestForeground() noexcept = 0;
            virtual int32_t __stdcall StartSharingScreen() noexcept = 0;
            virtual int32_t __stdcall StopSharingScreen() noexcept = 0;
            virtual int32_t __stdcall NotifyMeetingEnded(int32_t) noexcept = 0;
            virtual int32_t __stdcall JoinMeetingWithUri(void*) noexcept = 0;
            virtual int32_t __stdcall get_MeetingUri(void**) noexcept = 0;
            virtual int32_t __stdcall get_SharingScreenBounds(winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall get_IsScreenSharing(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsFullScreen(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SystemState(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MeetingInfoDisplayType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_JoinMeetingRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_JoinMeetingRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_EndMeetingRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_EndMeetingRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_CleanupRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_CleanupRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_SharingScreenBoundsChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SharingScreenBoundsChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_IsScreenSharingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_IsScreenSharingChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_IsFullScreenChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_IsFullScreenChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_CommandInvoked(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_CommandInvoked(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_SystemStateChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SystemStateChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetButtonLabel(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamViewStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_UI_Core_Preview_Communications_IPreviewTeamCleanupRequestedEventArgs
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCleanupRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Core_Preview_Communications_IPreviewTeamCleanupRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Core_Preview_Communications_IPreviewTeamCommandInvokedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Core::Preview::Communications::PreviewTeamViewCommand) Command() const;
    };
    template <> struct consume<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCommandInvokedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Core_Preview_Communications_IPreviewTeamCommandInvokedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Core_Preview_Communications_IPreviewTeamDeviceCredentials
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UserPrincipalName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DomainUserName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Password() const;
    };
    template <> struct consume<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials>
    {
        template <typename D> using type = consume_Windows_UI_Core_Preview_Communications_IPreviewTeamDeviceCredentials<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Core_Preview_Communications_IPreviewTeamEndMeetingRequestedEventArgs
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamEndMeetingRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Core_Preview_Communications_IPreviewTeamEndMeetingRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Core_Preview_Communications_IPreviewTeamJoinMeetingRequestedEventArgs
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) MeetingUri() const;
    };
    template <> struct consume<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamJoinMeetingRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Core_Preview_Communications_IPreviewTeamJoinMeetingRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView
    {
        WINRT_IMPL_AUTO(void) SetTitle(param::hstring const& title) const;
        WINRT_IMPL_AUTO(void) EnterFullScreen() const;
        WINRT_IMPL_AUTO(void) LeaveFullScreen() const;
        WINRT_IMPL_AUTO(void) RequestForeground() const;
        WINRT_IMPL_AUTO(void) StartSharingScreen() const;
        WINRT_IMPL_AUTO(void) StopSharingScreen() const;
        WINRT_IMPL_AUTO(void) NotifyMeetingEnded(winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingKind const& kind) const;
        WINRT_IMPL_AUTO(void) JoinMeetingWithUri(winrt::Windows::Foundation::Uri const& meetingUri) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) MeetingUri() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) SharingScreenBounds() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsScreenSharing() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsFullScreen() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Core::Preview::Communications::PreviewSystemState) SystemState() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Core::Preview::Communications::PreviewMeetingInfoDisplayKind) MeetingInfoDisplayType() const;
        WINRT_IMPL_AUTO(winrt::event_token) JoinMeetingRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamJoinMeetingRequestedEventArgs> const& handler) const;
        using JoinMeetingRequested_revoker = impl::event_revoker<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView, &impl::abi_t<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>::remove_JoinMeetingRequested>;
        [[nodiscard]] JoinMeetingRequested_revoker JoinMeetingRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamJoinMeetingRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) JoinMeetingRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) EndMeetingRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingRequestedEventArgs> const& handler) const;
        using EndMeetingRequested_revoker = impl::event_revoker<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView, &impl::abi_t<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>::remove_EndMeetingRequested>;
        [[nodiscard]] EndMeetingRequested_revoker EndMeetingRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) EndMeetingRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) CleanupRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCleanupRequestedEventArgs> const& handler) const;
        using CleanupRequested_revoker = impl::event_revoker<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView, &impl::abi_t<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>::remove_CleanupRequested>;
        [[nodiscard]] CleanupRequested_revoker CleanupRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCleanupRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) CleanupRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) SharingScreenBoundsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using SharingScreenBoundsChanged_revoker = impl::event_revoker<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView, &impl::abi_t<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>::remove_SharingScreenBoundsChanged>;
        [[nodiscard]] SharingScreenBoundsChanged_revoker SharingScreenBoundsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) SharingScreenBoundsChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) IsScreenSharingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using IsScreenSharingChanged_revoker = impl::event_revoker<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView, &impl::abi_t<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>::remove_IsScreenSharingChanged>;
        [[nodiscard]] IsScreenSharingChanged_revoker IsScreenSharingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) IsScreenSharingChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) IsFullScreenChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using IsFullScreenChanged_revoker = impl::event_revoker<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView, &impl::abi_t<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>::remove_IsFullScreenChanged>;
        [[nodiscard]] IsFullScreenChanged_revoker IsFullScreenChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) IsFullScreenChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) CommandInvoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCommandInvokedEventArgs> const& handler) const;
        using CommandInvoked_revoker = impl::event_revoker<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView, &impl::abi_t<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>::remove_CommandInvoked>;
        [[nodiscard]] CommandInvoked_revoker CommandInvoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCommandInvokedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) CommandInvoked(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) SystemStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using SystemStateChanged_revoker = impl::event_revoker<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView, &impl::abi_t<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>::remove_SystemStateChanged>;
        [[nodiscard]] SystemStateChanged_revoker SystemStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) SystemStateChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>
    {
        template <typename D> using type = consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView2
    {
        WINRT_IMPL_AUTO(void) SetButtonLabel(param::hstring const& label) const;
    };
    template <> struct consume<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView2>
    {
        template <typename D> using type = consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Core_Preview_Communications_IPreviewTeamViewStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView) GetForCurrentView() const;
    };
    template <> struct consume<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamViewStatics>
    {
        template <typename D> using type = consume_Windows_UI_Core_Preview_Communications_IPreviewTeamViewStatics<D>;
    };
}
#endif
