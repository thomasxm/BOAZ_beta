// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_UI_Interop_0_H
#define WINRT_Windows_Web_UI_Interop_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    struct Rect;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::System
{
    enum class VirtualKey : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::UI::Core
{
    enum class CoreAcceleratorKeyEventType : int32_t;
    struct CorePhysicalKeyStatus;
}
WINRT_EXPORT namespace winrt::Windows::Web::UI
{
    struct IWebViewControl;
}
WINRT_EXPORT namespace winrt::Windows::Web::UI::Interop
{
    enum class WebViewControlAcceleratorKeyRoutingStage : int32_t
    {
        Tunneling = 0,
        Bubbling = 1,
    };
    enum class WebViewControlMoveFocusReason : int32_t
    {
        Programmatic = 0,
        Next = 1,
        Previous = 2,
    };
    enum class WebViewControlProcessCapabilityState : int32_t
    {
        Default = 0,
        Disabled = 1,
        Enabled = 2,
    };
    struct IWebViewControlAcceleratorKeyPressedEventArgs;
    struct IWebViewControlMoveFocusRequestedEventArgs;
    struct IWebViewControlProcess;
    struct IWebViewControlProcessFactory;
    struct IWebViewControlProcessOptions;
    struct IWebViewControlSite;
    struct IWebViewControlSite2;
    struct WebViewControl;
    struct WebViewControlAcceleratorKeyPressedEventArgs;
    struct WebViewControlMoveFocusRequestedEventArgs;
    struct WebViewControlProcess;
    struct WebViewControlProcessOptions;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::IWebViewControlProcess>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::IWebViewControlProcessFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::IWebViewControlSite>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::IWebViewControlSite2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::WebViewControl>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::WebViewControlProcess>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::WebViewControlProcessOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusReason>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Web::UI::Interop::WebViewControlProcessCapabilityState>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::WebViewControl> = L"Windows.Web.UI.Interop.WebViewControl";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> = L"Windows.Web.UI.Interop.WebViewControlAcceleratorKeyPressedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> = L"Windows.Web.UI.Interop.WebViewControlMoveFocusRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::WebViewControlProcess> = L"Windows.Web.UI.Interop.WebViewControlProcess";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::WebViewControlProcessOptions> = L"Windows.Web.UI.Interop.WebViewControlProcessOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage> = L"Windows.Web.UI.Interop.WebViewControlAcceleratorKeyRoutingStage";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusReason> = L"Windows.Web.UI.Interop.WebViewControlMoveFocusReason";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::WebViewControlProcessCapabilityState> = L"Windows.Web.UI.Interop.WebViewControlProcessCapabilityState";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs> = L"Windows.Web.UI.Interop.IWebViewControlAcceleratorKeyPressedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs> = L"Windows.Web.UI.Interop.IWebViewControlMoveFocusRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::IWebViewControlProcess> = L"Windows.Web.UI.Interop.IWebViewControlProcess";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::IWebViewControlProcessFactory> = L"Windows.Web.UI.Interop.IWebViewControlProcessFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions> = L"Windows.Web.UI.Interop.IWebViewControlProcessOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::IWebViewControlSite> = L"Windows.Web.UI.Interop.IWebViewControlSite";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::UI::Interop::IWebViewControlSite2> = L"Windows.Web.UI.Interop.IWebViewControlSite2";
    template <> inline constexpr guid guid_v<winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs>{ 0x77A2A53E,0x7C74,0x437D,{ 0xA2,0x90,0x3A,0xC0,0xD8,0xCD,0x56,0x55 } }; // 77A2A53E-7C74-437D-A290-3AC0D8CD5655
    template <> inline constexpr guid guid_v<winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs>{ 0x6B2A340D,0x4BD0,0x405E,{ 0xB7,0xC1,0x1E,0x72,0xA4,0x92,0xF4,0x46 } }; // 6B2A340D-4BD0-405E-B7C1-1E72A492F446
    template <> inline constexpr guid guid_v<winrt::Windows::Web::UI::Interop::IWebViewControlProcess>{ 0x02C723EC,0x98D6,0x424A,{ 0xB6,0x3E,0xC6,0x13,0x6C,0x36,0xA0,0xF2 } }; // 02C723EC-98D6-424A-B63E-C6136C36A0F2
    template <> inline constexpr guid guid_v<winrt::Windows::Web::UI::Interop::IWebViewControlProcessFactory>{ 0x47B65CF9,0xA2D2,0x453C,{ 0xB0,0x97,0xF6,0x77,0x9D,0x4B,0x8E,0x02 } }; // 47B65CF9-A2D2-453C-B097-F6779D4B8E02
    template <> inline constexpr guid guid_v<winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions>{ 0x1CCA72A7,0x3BD6,0x4826,{ 0x82,0x61,0x6C,0x81,0x89,0x50,0x5D,0x89 } }; // 1CCA72A7-3BD6-4826-8261-6C8189505D89
    template <> inline constexpr guid guid_v<winrt::Windows::Web::UI::Interop::IWebViewControlSite>{ 0x133F47C6,0x12DC,0x4898,{ 0xBD,0x47,0x04,0x96,0x7D,0xE6,0x48,0xBA } }; // 133F47C6-12DC-4898-BD47-04967DE648BA
    template <> inline constexpr guid guid_v<winrt::Windows::Web::UI::Interop::IWebViewControlSite2>{ 0xD13B2E3F,0x48EE,0x4730,{ 0x82,0x43,0xD2,0xED,0x0C,0x05,0x60,0x6A } }; // D13B2E3F-48EE-4730-8243-D2ED0C05606A
    template <> struct default_interface<winrt::Windows::Web::UI::Interop::WebViewControl>{ using type = winrt::Windows::Web::UI::IWebViewControl; };
    template <> struct default_interface<winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs>{ using type = winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs; };
    template <> struct default_interface<winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs>{ using type = winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::Web::UI::Interop::WebViewControlProcess>{ using type = winrt::Windows::Web::UI::Interop::IWebViewControlProcess; };
    template <> struct default_interface<winrt::Windows::Web::UI::Interop::WebViewControlProcessOptions>{ using type = winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions; };
    template <> struct abi<winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EventType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_VirtualKey(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_KeyStatus(struct struct_Windows_UI_Core_CorePhysicalKeyStatus*) noexcept = 0;
            virtual int32_t __stdcall get_RoutingStage(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Handled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Handled(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reason(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::UI::Interop::IWebViewControlProcess>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ProcessId(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_EnterpriseId(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsPrivateNetworkClientServerCapabilityEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall CreateWebViewControlAsync(int64_t, winrt::Windows::Foundation::Rect, void**) noexcept = 0;
            virtual int32_t __stdcall GetWebViewControls(void**) noexcept = 0;
            virtual int32_t __stdcall Terminate() noexcept = 0;
            virtual int32_t __stdcall add_ProcessExited(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ProcessExited(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::UI::Interop::IWebViewControlProcessFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateWithOptions(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_EnterpriseId(void*) noexcept = 0;
            virtual int32_t __stdcall get_EnterpriseId(void**) noexcept = 0;
            virtual int32_t __stdcall put_PrivateNetworkClientServerCapability(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_PrivateNetworkClientServerCapability(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::UI::Interop::IWebViewControlSite>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Process(void**) noexcept = 0;
            virtual int32_t __stdcall put_Scale(double) noexcept = 0;
            virtual int32_t __stdcall get_Scale(double*) noexcept = 0;
            virtual int32_t __stdcall put_Bounds(winrt::Windows::Foundation::Rect) noexcept = 0;
            virtual int32_t __stdcall get_Bounds(winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall put_IsVisible(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsVisible(bool*) noexcept = 0;
            virtual int32_t __stdcall Close() noexcept = 0;
            virtual int32_t __stdcall MoveFocus(int32_t) noexcept = 0;
            virtual int32_t __stdcall add_MoveFocusRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_MoveFocusRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_AcceleratorKeyPressed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AcceleratorKeyPressed(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::UI::Interop::IWebViewControlSite2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_GotFocus(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_GotFocus(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_LostFocus(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_LostFocus(winrt::event_token) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreAcceleratorKeyEventType) EventType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) VirtualKey() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CorePhysicalKeyStatus) KeyStatus() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage) RoutingStage() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Handled() const;
        WINRT_IMPL_AUTO(void) Handled(bool value) const;
    };
    template <> struct consume<winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs>
    {
        template <typename D> using type = consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Web_UI_Interop_IWebViewControlMoveFocusRequestedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusReason) Reason() const;
    };
    template <> struct consume<winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_Web_UI_Interop_IWebViewControlMoveFocusRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Web_UI_Interop_IWebViewControlProcess
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ProcessId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EnterpriseId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPrivateNetworkClientServerCapabilityEnabled() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Web::UI::Interop::WebViewControl>) CreateWebViewControlAsync(int64_t hostWindowHandle, winrt::Windows::Foundation::Rect const& bounds) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::UI::Interop::WebViewControl>) GetWebViewControls() const;
        WINRT_IMPL_AUTO(void) Terminate() const;
        WINRT_IMPL_AUTO(winrt::event_token) ProcessExited(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControlProcess, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ProcessExited_revoker = impl::event_revoker<winrt::Windows::Web::UI::Interop::IWebViewControlProcess, &impl::abi_t<winrt::Windows::Web::UI::Interop::IWebViewControlProcess>::remove_ProcessExited>;
        [[nodiscard]] ProcessExited_revoker ProcessExited(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControlProcess, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ProcessExited(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Web::UI::Interop::IWebViewControlProcess>
    {
        template <typename D> using type = consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>;
    };
    template <typename D>
    struct consume_Windows_Web_UI_Interop_IWebViewControlProcessFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Web::UI::Interop::WebViewControlProcess) CreateWithOptions(winrt::Windows::Web::UI::Interop::WebViewControlProcessOptions const& processOptions) const;
    };
    template <> struct consume<winrt::Windows::Web::UI::Interop::IWebViewControlProcessFactory>
    {
        template <typename D> using type = consume_Windows_Web_UI_Interop_IWebViewControlProcessFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Web_UI_Interop_IWebViewControlProcessOptions
    {
        WINRT_IMPL_AUTO(void) EnterpriseId(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EnterpriseId() const;
        WINRT_IMPL_AUTO(void) PrivateNetworkClientServerCapability(winrt::Windows::Web::UI::Interop::WebViewControlProcessCapabilityState const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Web::UI::Interop::WebViewControlProcessCapabilityState) PrivateNetworkClientServerCapability() const;
    };
    template <> struct consume<winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions>
    {
        template <typename D> using type = consume_Windows_Web_UI_Interop_IWebViewControlProcessOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Web_UI_Interop_IWebViewControlSite
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Web::UI::Interop::WebViewControlProcess) Process() const;
        WINRT_IMPL_AUTO(void) Scale(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) Scale() const;
        WINRT_IMPL_AUTO(void) Bounds(winrt::Windows::Foundation::Rect const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) Bounds() const;
        WINRT_IMPL_AUTO(void) IsVisible(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsVisible() const;
        WINRT_IMPL_AUTO(void) Close() const;
        WINRT_IMPL_AUTO(void) MoveFocus(winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusReason const& reason) const;
        WINRT_IMPL_AUTO(winrt::event_token) MoveFocusRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> const& handler) const;
        using MoveFocusRequested_revoker = impl::event_revoker<winrt::Windows::Web::UI::Interop::IWebViewControlSite, &impl::abi_t<winrt::Windows::Web::UI::Interop::IWebViewControlSite>::remove_MoveFocusRequested>;
        [[nodiscard]] MoveFocusRequested_revoker MoveFocusRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) MoveFocusRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) AcceleratorKeyPressed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> const& handler) const;
        using AcceleratorKeyPressed_revoker = impl::event_revoker<winrt::Windows::Web::UI::Interop::IWebViewControlSite, &impl::abi_t<winrt::Windows::Web::UI::Interop::IWebViewControlSite>::remove_AcceleratorKeyPressed>;
        [[nodiscard]] AcceleratorKeyPressed_revoker AcceleratorKeyPressed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AcceleratorKeyPressed(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Web::UI::Interop::IWebViewControlSite>
    {
        template <typename D> using type = consume_Windows_Web_UI_Interop_IWebViewControlSite<D>;
    };
    template <typename D>
    struct consume_Windows_Web_UI_Interop_IWebViewControlSite2
    {
        WINRT_IMPL_AUTO(winrt::event_token) GotFocus(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using GotFocus_revoker = impl::event_revoker<winrt::Windows::Web::UI::Interop::IWebViewControlSite2, &impl::abi_t<winrt::Windows::Web::UI::Interop::IWebViewControlSite2>::remove_GotFocus>;
        [[nodiscard]] GotFocus_revoker GotFocus(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) GotFocus(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) LostFocus(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using LostFocus_revoker = impl::event_revoker<winrt::Windows::Web::UI::Interop::IWebViewControlSite2, &impl::abi_t<winrt::Windows::Web::UI::Interop::IWebViewControlSite2>::remove_LostFocus>;
        [[nodiscard]] LostFocus_revoker LostFocus(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) LostFocus(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Web::UI::Interop::IWebViewControlSite2>
    {
        template <typename D> using type = consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>;
    };
}
#endif
