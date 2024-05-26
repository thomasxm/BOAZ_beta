// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_WebUI_Core_0_H
#define WINRT_Windows_UI_WebUI_Core_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    struct Size;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IObservableVector;
}
WINRT_EXPORT namespace winrt::Windows::UI
{
    struct Color;
}
WINRT_EXPORT namespace winrt::Windows::UI::WebUI::Core
{
    enum class WebUICommandBarClosedDisplayMode : int32_t
    {
        Default = 0,
        Minimal = 1,
        Compact = 2,
    };
    struct IWebUICommandBar;
    struct IWebUICommandBarBitmapIcon;
    struct IWebUICommandBarBitmapIconFactory;
    struct IWebUICommandBarConfirmationButton;
    struct IWebUICommandBarElement;
    struct IWebUICommandBarIcon;
    struct IWebUICommandBarIconButton;
    struct IWebUICommandBarItemInvokedEventArgs;
    struct IWebUICommandBarSizeChangedEventArgs;
    struct IWebUICommandBarStatics;
    struct IWebUICommandBarSymbolIcon;
    struct IWebUICommandBarSymbolIconFactory;
    struct WebUICommandBar;
    struct WebUICommandBarBitmapIcon;
    struct WebUICommandBarConfirmationButton;
    struct WebUICommandBarIconButton;
    struct WebUICommandBarItemInvokedEventArgs;
    struct WebUICommandBarSizeChangedEventArgs;
    struct WebUICommandBarSymbolIcon;
    struct MenuClosedEventHandler;
    struct MenuOpenedEventHandler;
    struct SizeChangedEventHandler;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBar>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBarStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::WebUICommandBar>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::WebUICommandBarIconButton>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::WebUICommandBarSizeChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler>{ using type = delegate_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler>{ using type = delegate_category; };
    template <> struct category<winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler>{ using type = delegate_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::WebUICommandBar> = L"Windows.UI.WebUI.Core.WebUICommandBar";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon> = L"Windows.UI.WebUI.Core.WebUICommandBarBitmapIcon";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton> = L"Windows.UI.WebUI.Core.WebUICommandBarConfirmationButton";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::WebUICommandBarIconButton> = L"Windows.UI.WebUI.Core.WebUICommandBarIconButton";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> = L"Windows.UI.WebUI.Core.WebUICommandBarItemInvokedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::WebUICommandBarSizeChangedEventArgs> = L"Windows.UI.WebUI.Core.WebUICommandBarSizeChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon> = L"Windows.UI.WebUI.Core.WebUICommandBarSymbolIcon";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode> = L"Windows.UI.WebUI.Core.WebUICommandBarClosedDisplayMode";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBar> = L"Windows.UI.WebUI.Core.IWebUICommandBar";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon> = L"Windows.UI.WebUI.Core.IWebUICommandBarBitmapIcon";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory> = L"Windows.UI.WebUI.Core.IWebUICommandBarBitmapIconFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton> = L"Windows.UI.WebUI.Core.IWebUICommandBarConfirmationButton";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement> = L"Windows.UI.WebUI.Core.IWebUICommandBarElement";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon> = L"Windows.UI.WebUI.Core.IWebUICommandBarIcon";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton> = L"Windows.UI.WebUI.Core.IWebUICommandBarIconButton";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs> = L"Windows.UI.WebUI.Core.IWebUICommandBarItemInvokedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs> = L"Windows.UI.WebUI.Core.IWebUICommandBarSizeChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarStatics> = L"Windows.UI.WebUI.Core.IWebUICommandBarStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon> = L"Windows.UI.WebUI.Core.IWebUICommandBarSymbolIcon";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory> = L"Windows.UI.WebUI.Core.IWebUICommandBarSymbolIconFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler> = L"Windows.UI.WebUI.Core.MenuClosedEventHandler";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler> = L"Windows.UI.WebUI.Core.MenuOpenedEventHandler";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler> = L"Windows.UI.WebUI.Core.SizeChangedEventHandler";
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBar>{ 0xA4FC0016,0xDBE5,0x41AD,{ 0x8D,0x7B,0x14,0x69,0x8B,0xD6,0x91,0x1D } }; // A4FC0016-DBE5-41AD-8D7B-14698BD6911D
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon>{ 0x858F4F45,0x08D8,0x4A46,{ 0x81,0xEC,0x00,0x01,0x5B,0x0B,0x1C,0x6C } }; // 858F4F45-08D8-4A46-81EC-00015B0B1C6C
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory>{ 0xF3F7D78A,0x7673,0x444A,{ 0xBE,0x62,0xAC,0x12,0xD3,0x1C,0x22,0x31 } }; // F3F7D78A-7673-444A-BE62-AC12D31C2231
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton>{ 0x86E7824A,0xE3D5,0x4EB6,{ 0xB2,0xFF,0x8F,0x01,0x8A,0x17,0x21,0x05 } }; // 86E7824A-E3D5-4EB6-B2FF-8F018A172105
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>{ 0xC9069EC2,0x284A,0x4633,{ 0x8A,0xAD,0x63,0x7A,0x27,0xE2,0x82,0xC3 } }; // C9069EC2-284A-4633-8AAD-637A27E282C3
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon>{ 0xD587655D,0x2014,0x42BE,{ 0x96,0x9A,0x7D,0x14,0xCA,0x6C,0x8A,0x49 } }; // D587655D-2014-42BE-969A-7D14CA6C8A49
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton>{ 0x8F1BC93A,0x3A7C,0x4842,{ 0xA0,0xCF,0xAF,0xF6,0xEA,0x30,0x85,0x86 } }; // 8F1BC93A-3A7C-4842-A0CF-AFF6EA308586
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs>{ 0x304EDBDD,0xE741,0x41EF,{ 0xBD,0xC4,0xA4,0x5C,0xEA,0x2A,0x4F,0x70 } }; // 304EDBDD-E741-41EF-BDC4-A45CEA2A4F70
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs>{ 0xFBF1E2F6,0x3029,0x4719,{ 0x83,0x78,0x92,0xF8,0x2B,0x87,0xAF,0x1E } }; // FBF1E2F6-3029-4719-8378-92F82B87AF1E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarStatics>{ 0x1449CDB9,0xA506,0x45BE,{ 0x8F,0x42,0xB2,0x83,0x7E,0x2F,0xE0,0xC9 } }; // 1449CDB9-A506-45BE-8F42-B2837E2FE0C9
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon>{ 0xD4935477,0xFD26,0x46ED,{ 0x86,0x58,0x1A,0x3F,0x44,0x00,0xE7,0xB3 } }; // D4935477-FD26-46ED-8658-1A3F4400E7B3
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory>{ 0x51BE1A1F,0x3730,0x429E,{ 0xB6,0x22,0x14,0xE2,0xB7,0xBF,0x6A,0x07 } }; // 51BE1A1F-3730-429E-B622-14E2B7BF6A07
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler>{ 0x435387C8,0x4DD0,0x4C52,{ 0x94,0x89,0xD3,0x90,0xCE,0x77,0x21,0xD2 } }; // 435387C8-4DD0-4C52-9489-D390CE7721D2
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler>{ 0x18DC0AD3,0x678F,0x4C19,{ 0x89,0x63,0xCC,0x1C,0x49,0xA5,0xEF,0x9E } }; // 18DC0AD3-678F-4C19-8963-CC1C49A5EF9E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler>{ 0xD49CFE3C,0xDD2E,0x4C28,{ 0xB6,0x27,0x30,0x3A,0x7F,0x91,0x1A,0xF5 } }; // D49CFE3C-DD2E-4C28-B627-303A7F911AF5
    template <> struct default_interface<winrt::Windows::UI::WebUI::Core::WebUICommandBar>{ using type = winrt::Windows::UI::WebUI::Core::IWebUICommandBar; };
    template <> struct default_interface<winrt::Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon>{ using type = winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon; };
    template <> struct default_interface<winrt::Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton>{ using type = winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton; };
    template <> struct default_interface<winrt::Windows::UI::WebUI::Core::WebUICommandBarIconButton>{ using type = winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton; };
    template <> struct default_interface<winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs>{ using type = winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::WebUI::Core::WebUICommandBarSizeChangedEventArgs>{ using type = winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon>{ using type = winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon; };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBar>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Visible(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Visible(bool) noexcept = 0;
            virtual int32_t __stdcall get_Opacity(double*) noexcept = 0;
            virtual int32_t __stdcall put_Opacity(double) noexcept = 0;
            virtual int32_t __stdcall get_ForegroundColor(struct struct_Windows_UI_Color*) noexcept = 0;
            virtual int32_t __stdcall put_ForegroundColor(struct struct_Windows_UI_Color) noexcept = 0;
            virtual int32_t __stdcall get_BackgroundColor(struct struct_Windows_UI_Color*) noexcept = 0;
            virtual int32_t __stdcall put_BackgroundColor(struct struct_Windows_UI_Color) noexcept = 0;
            virtual int32_t __stdcall get_ClosedDisplayMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ClosedDisplayMode(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsOpen(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsOpen(bool) noexcept = 0;
            virtual int32_t __stdcall get_Size(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall get_PrimaryCommands(void**) noexcept = 0;
            virtual int32_t __stdcall get_SecondaryCommands(void**) noexcept = 0;
            virtual int32_t __stdcall add_MenuOpened(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_MenuOpened(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_MenuClosed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_MenuClosed(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_SizeChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SizeChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Uri(void**) noexcept = 0;
            virtual int32_t __stdcall put_Uri(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Text(void**) noexcept = 0;
            virtual int32_t __stdcall put_Text(void*) noexcept = 0;
            virtual int32_t __stdcall add_ItemInvoked(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ItemInvoked(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Enabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Enabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_Label(void**) noexcept = 0;
            virtual int32_t __stdcall put_Label(void*) noexcept = 0;
            virtual int32_t __stdcall get_IsToggleButton(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsToggleButton(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsChecked(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsChecked(bool) noexcept = 0;
            virtual int32_t __stdcall get_Icon(void**) noexcept = 0;
            virtual int32_t __stdcall put_Icon(void*) noexcept = 0;
            virtual int32_t __stdcall add_ItemInvoked(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ItemInvoked(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsPrimaryCommand(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Size(winrt::Windows::Foundation::Size*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBarStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Symbol(void**) noexcept = 0;
            virtual int32_t __stdcall put_Symbol(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBar
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Visible() const;
        WINRT_IMPL_AUTO(void) Visible(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) Opacity() const;
        WINRT_IMPL_AUTO(void) Opacity(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Color) ForegroundColor() const;
        WINRT_IMPL_AUTO(void) ForegroundColor(winrt::Windows::UI::Color const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Color) BackgroundColor() const;
        WINRT_IMPL_AUTO(void) BackgroundColor(winrt::Windows::UI::Color const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode) ClosedDisplayMode() const;
        WINRT_IMPL_AUTO(void) ClosedDisplayMode(winrt::Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsOpen() const;
        WINRT_IMPL_AUTO(void) IsOpen(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) Size() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>) PrimaryCommands() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>) SecondaryCommands() const;
        WINRT_IMPL_AUTO(winrt::event_token) MenuOpened(winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler const& handler) const;
        using MenuOpened_revoker = impl::event_revoker<winrt::Windows::UI::WebUI::Core::IWebUICommandBar, &impl::abi_t<winrt::Windows::UI::WebUI::Core::IWebUICommandBar>::remove_MenuOpened>;
        [[nodiscard]] MenuOpened_revoker MenuOpened(auto_revoke_t, winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler const& handler) const;
        WINRT_IMPL_AUTO(void) MenuOpened(winrt::event_token const& value) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) MenuClosed(winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler const& handler) const;
        using MenuClosed_revoker = impl::event_revoker<winrt::Windows::UI::WebUI::Core::IWebUICommandBar, &impl::abi_t<winrt::Windows::UI::WebUI::Core::IWebUICommandBar>::remove_MenuClosed>;
        [[nodiscard]] MenuClosed_revoker MenuClosed(auto_revoke_t, winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler const& handler) const;
        WINRT_IMPL_AUTO(void) MenuClosed(winrt::event_token const& value) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) SizeChanged(winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler const& handler) const;
        using SizeChanged_revoker = impl::event_revoker<winrt::Windows::UI::WebUI::Core::IWebUICommandBar, &impl::abi_t<winrt::Windows::UI::WebUI::Core::IWebUICommandBar>::remove_SizeChanged>;
        [[nodiscard]] SizeChanged_revoker SizeChanged(auto_revoke_t, winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler const& handler) const;
        WINRT_IMPL_AUTO(void) SizeChanged(winrt::event_token const& value) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBar>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>;
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBarBitmapIcon
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Uri() const;
        WINRT_IMPL_AUTO(void) Uri(winrt::Windows::Foundation::Uri const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBarBitmapIcon<D>;
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBarBitmapIconFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon) Create(winrt::Windows::Foundation::Uri const& uri) const;
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBarBitmapIconFactory<D>;
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Text() const;
        WINRT_IMPL_AUTO(void) Text(param::hstring const& value) const;
        WINRT_IMPL_AUTO(winrt::event_token) ItemInvoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton, winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const;
        using ItemInvoked_revoker = impl::event_revoker<winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton, &impl::abi_t<winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton>::remove_ItemInvoked>;
        [[nodiscard]] ItemInvoked_revoker ItemInvoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton, winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ItemInvoked(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>;
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBarElement
    {
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBarElement<D>;
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBarIcon
    {
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBarIcon<D>;
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Enabled() const;
        WINRT_IMPL_AUTO(void) Enabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Label() const;
        WINRT_IMPL_AUTO(void) Label(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsToggleButton() const;
        WINRT_IMPL_AUTO(void) IsToggleButton(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsChecked() const;
        WINRT_IMPL_AUTO(void) IsChecked(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon) Icon() const;
        WINRT_IMPL_AUTO(void) Icon(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon const& value) const;
        WINRT_IMPL_AUTO(winrt::event_token) ItemInvoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WebUI::Core::WebUICommandBarIconButton, winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const;
        using ItemInvoked_revoker = impl::event_revoker<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton, &impl::abi_t<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton>::remove_ItemInvoked>;
        [[nodiscard]] ItemInvoked_revoker ItemInvoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WebUI::Core::WebUICommandBarIconButton, winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ItemInvoked(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>;
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBarItemInvokedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPrimaryCommand() const;
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBarItemInvokedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBarSizeChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) Size() const;
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBarSizeChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBarStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::WebUI::Core::WebUICommandBar) GetForCurrentView() const;
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBarStatics>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBarStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBarSymbolIcon
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Symbol() const;
        WINRT_IMPL_AUTO(void) Symbol(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBarSymbolIcon<D>;
    };
    template <typename D>
    struct consume_Windows_UI_WebUI_Core_IWebUICommandBarSymbolIconFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon) Create(param::hstring const& symbol) const;
    };
    template <> struct consume<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory>
    {
        template <typename D> using type = consume_Windows_UI_WebUI_Core_IWebUICommandBarSymbolIconFactory<D>;
    };
}
#endif
