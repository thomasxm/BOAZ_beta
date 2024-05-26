// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Gaming_UI_0_H
#define WINRT_Windows_Gaming_UI_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename T> struct __declspec(empty_bases) EventHandler;
    struct EventRegistrationToken;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    struct ValueSet;
}
WINRT_EXPORT namespace winrt::Windows::Gaming::UI
{
    enum class GameChatMessageOrigin : int32_t
    {
        Voice = 0,
        Text = 1,
    };
    enum class GameChatOverlayPosition : int32_t
    {
        BottomCenter = 0,
        BottomLeft = 1,
        BottomRight = 2,
        MiddleRight = 3,
        MiddleLeft = 4,
        TopCenter = 5,
        TopLeft = 6,
        TopRight = 7,
    };
    struct IGameBarStatics;
    struct IGameChatMessageReceivedEventArgs;
    struct IGameChatOverlay;
    struct IGameChatOverlayMessageSource;
    struct IGameChatOverlayStatics;
    struct IGameUIProviderActivatedEventArgs;
    struct GameBar;
    struct GameChatMessageReceivedEventArgs;
    struct GameChatOverlay;
    struct GameChatOverlayMessageSource;
    struct GameUIProviderActivatedEventArgs;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Gaming::UI::IGameBarStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Gaming::UI::IGameChatMessageReceivedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Gaming::UI::IGameChatOverlay>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Gaming::UI::IGameChatOverlayMessageSource>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Gaming::UI::IGameChatOverlayStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Gaming::UI::IGameUIProviderActivatedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Gaming::UI::GameBar>{ using type = class_category; };
    template <> struct category<winrt::Windows::Gaming::UI::GameChatMessageReceivedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Gaming::UI::GameChatOverlay>{ using type = class_category; };
    template <> struct category<winrt::Windows::Gaming::UI::GameChatOverlayMessageSource>{ using type = class_category; };
    template <> struct category<winrt::Windows::Gaming::UI::GameUIProviderActivatedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Gaming::UI::GameChatMessageOrigin>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Gaming::UI::GameChatOverlayPosition>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::GameBar> = L"Windows.Gaming.UI.GameBar";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::GameChatMessageReceivedEventArgs> = L"Windows.Gaming.UI.GameChatMessageReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::GameChatOverlay> = L"Windows.Gaming.UI.GameChatOverlay";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::GameChatOverlayMessageSource> = L"Windows.Gaming.UI.GameChatOverlayMessageSource";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::GameUIProviderActivatedEventArgs> = L"Windows.Gaming.UI.GameUIProviderActivatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::GameChatMessageOrigin> = L"Windows.Gaming.UI.GameChatMessageOrigin";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::GameChatOverlayPosition> = L"Windows.Gaming.UI.GameChatOverlayPosition";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::IGameBarStatics> = L"Windows.Gaming.UI.IGameBarStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::IGameChatMessageReceivedEventArgs> = L"Windows.Gaming.UI.IGameChatMessageReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::IGameChatOverlay> = L"Windows.Gaming.UI.IGameChatOverlay";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::IGameChatOverlayMessageSource> = L"Windows.Gaming.UI.IGameChatOverlayMessageSource";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::IGameChatOverlayStatics> = L"Windows.Gaming.UI.IGameChatOverlayStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::UI::IGameUIProviderActivatedEventArgs> = L"Windows.Gaming.UI.IGameUIProviderActivatedEventArgs";
    template <> inline constexpr guid guid_v<winrt::Windows::Gaming::UI::IGameBarStatics>{ 0x1DB9A292,0xCC78,0x4173,{ 0xBE,0x45,0xB6,0x1E,0x67,0x28,0x3E,0xA7 } }; // 1DB9A292-CC78-4173-BE45-B61E67283EA7
    template <> inline constexpr guid guid_v<winrt::Windows::Gaming::UI::IGameChatMessageReceivedEventArgs>{ 0xA28201F1,0x3FB9,0x4E42,{ 0xA4,0x03,0x7A,0xFC,0xE2,0x02,0x3B,0x1E } }; // A28201F1-3FB9-4E42-A403-7AFCE2023B1E
    template <> inline constexpr guid guid_v<winrt::Windows::Gaming::UI::IGameChatOverlay>{ 0xFBC64865,0xF6FC,0x4A48,{ 0xAE,0x07,0x03,0xAC,0x6E,0xD4,0x37,0x04 } }; // FBC64865-F6FC-4A48-AE07-03AC6ED43704
    template <> inline constexpr guid guid_v<winrt::Windows::Gaming::UI::IGameChatOverlayMessageSource>{ 0x1E177397,0x59FB,0x4F4F,{ 0x8E,0x9A,0x80,0xAC,0xF8,0x17,0x74,0x3C } }; // 1E177397-59FB-4F4F-8E9A-80ACF817743C
    template <> inline constexpr guid guid_v<winrt::Windows::Gaming::UI::IGameChatOverlayStatics>{ 0x89ACF614,0x7867,0x49F7,{ 0x96,0x87,0x25,0xD9,0xDB,0xF4,0x44,0xD1 } }; // 89ACF614-7867-49F7-9687-25D9DBF444D1
    template <> inline constexpr guid guid_v<winrt::Windows::Gaming::UI::IGameUIProviderActivatedEventArgs>{ 0xA7B3203E,0xCAF7,0x4DED,{ 0xBB,0xD2,0x47,0xDE,0x43,0xBB,0x6D,0xD5 } }; // A7B3203E-CAF7-4DED-BBD2-47DE43BB6DD5
    template <> struct default_interface<winrt::Windows::Gaming::UI::GameChatMessageReceivedEventArgs>{ using type = winrt::Windows::Gaming::UI::IGameChatMessageReceivedEventArgs; };
    template <> struct default_interface<winrt::Windows::Gaming::UI::GameChatOverlay>{ using type = winrt::Windows::Gaming::UI::IGameChatOverlay; };
    template <> struct default_interface<winrt::Windows::Gaming::UI::GameChatOverlayMessageSource>{ using type = winrt::Windows::Gaming::UI::IGameChatOverlayMessageSource; };
    template <> struct default_interface<winrt::Windows::Gaming::UI::GameUIProviderActivatedEventArgs>{ using type = winrt::Windows::Gaming::UI::IGameUIProviderActivatedEventArgs; };
    template <> struct abi<winrt::Windows::Gaming::UI::IGameBarStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_VisibilityChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_VisibilityChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_IsInputRedirectedChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_IsInputRedirectedChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_Visible(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsInputRedirected(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Gaming::UI::IGameChatMessageReceivedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AppId(void**) noexcept = 0;
            virtual int32_t __stdcall get_AppDisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall get_SenderName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Message(void**) noexcept = 0;
            virtual int32_t __stdcall get_Origin(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Gaming::UI::IGameChatOverlay>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DesiredPosition(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_DesiredPosition(int32_t) noexcept = 0;
            virtual int32_t __stdcall AddMessage(void*, void*, int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Gaming::UI::IGameChatOverlayMessageSource>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_MessageReceived(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_MessageReceived(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall SetDelayBeforeClosingAfterMessageReceived(int64_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Gaming::UI::IGameChatOverlayStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Gaming::UI::IGameUIProviderActivatedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_GameUIArgs(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompleted(void*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Gaming_UI_IGameBarStatics
    {
        WINRT_IMPL_AUTO(winrt::event_token) VisibilityChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        using VisibilityChanged_revoker = impl::event_revoker<winrt::Windows::Gaming::UI::IGameBarStatics, &impl::abi_t<winrt::Windows::Gaming::UI::IGameBarStatics>::remove_VisibilityChanged>;
        [[nodiscard]] VisibilityChanged_revoker VisibilityChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) VisibilityChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) IsInputRedirectedChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        using IsInputRedirectedChanged_revoker = impl::event_revoker<winrt::Windows::Gaming::UI::IGameBarStatics, &impl::abi_t<winrt::Windows::Gaming::UI::IGameBarStatics>::remove_IsInputRedirectedChanged>;
        [[nodiscard]] IsInputRedirectedChanged_revoker IsInputRedirectedChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) IsInputRedirectedChanged(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Visible() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsInputRedirected() const;
    };
    template <> struct consume<winrt::Windows::Gaming::UI::IGameBarStatics>
    {
        template <typename D> using type = consume_Windows_Gaming_UI_IGameBarStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Gaming_UI_IGameChatMessageReceivedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AppId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AppDisplayName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SenderName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Message() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Gaming::UI::GameChatMessageOrigin) Origin() const;
    };
    template <> struct consume<winrt::Windows::Gaming::UI::IGameChatMessageReceivedEventArgs>
    {
        template <typename D> using type = consume_Windows_Gaming_UI_IGameChatMessageReceivedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Gaming_UI_IGameChatOverlay
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Gaming::UI::GameChatOverlayPosition) DesiredPosition() const;
        WINRT_IMPL_AUTO(void) DesiredPosition(winrt::Windows::Gaming::UI::GameChatOverlayPosition const& value) const;
        WINRT_IMPL_AUTO(void) AddMessage(param::hstring const& sender, param::hstring const& message, winrt::Windows::Gaming::UI::GameChatMessageOrigin const& origin) const;
    };
    template <> struct consume<winrt::Windows::Gaming::UI::IGameChatOverlay>
    {
        template <typename D> using type = consume_Windows_Gaming_UI_IGameChatOverlay<D>;
    };
    template <typename D>
    struct consume_Windows_Gaming_UI_IGameChatOverlayMessageSource
    {
        WINRT_IMPL_AUTO(winrt::event_token) MessageReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Gaming::UI::GameChatOverlayMessageSource, winrt::Windows::Gaming::UI::GameChatMessageReceivedEventArgs> const& handler) const;
        using MessageReceived_revoker = impl::event_revoker<winrt::Windows::Gaming::UI::IGameChatOverlayMessageSource, &impl::abi_t<winrt::Windows::Gaming::UI::IGameChatOverlayMessageSource>::remove_MessageReceived>;
        [[nodiscard]] MessageReceived_revoker MessageReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Gaming::UI::GameChatOverlayMessageSource, winrt::Windows::Gaming::UI::GameChatMessageReceivedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) MessageReceived(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(void) SetDelayBeforeClosingAfterMessageReceived(winrt::Windows::Foundation::TimeSpan const& value) const;
    };
    template <> struct consume<winrt::Windows::Gaming::UI::IGameChatOverlayMessageSource>
    {
        template <typename D> using type = consume_Windows_Gaming_UI_IGameChatOverlayMessageSource<D>;
    };
    template <typename D>
    struct consume_Windows_Gaming_UI_IGameChatOverlayStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Gaming::UI::GameChatOverlay) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Gaming::UI::IGameChatOverlayStatics>
    {
        template <typename D> using type = consume_Windows_Gaming_UI_IGameChatOverlayStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Gaming_UI_IGameUIProviderActivatedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) GameUIArgs() const;
        WINRT_IMPL_AUTO(void) ReportCompleted(winrt::Windows::Foundation::Collections::ValueSet const& results) const;
    };
    template <> struct consume<winrt::Windows::Gaming::UI::IGameUIProviderActivatedEventArgs>
    {
        template <typename D> using type = consume_Windows_Gaming_UI_IGameUIProviderActivatedEventArgs<D>;
    };
}
#endif
