// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Inking_Core_0_H
#define WINRT_Windows_UI_Input_Inking_Core_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    struct Rect;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Numerics
{
}
WINRT_EXPORT namespace winrt::Windows::UI::Composition
{
    struct ContainerVisual;
}
WINRT_EXPORT namespace winrt::Windows::UI::Core
{
    struct CoreCursor;
    struct PointerEventArgs;
}
WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking
{
    struct InkDrawingAttributes;
    struct InkPoint;
    struct InkPresenter;
    struct InkStroke;
}
WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Core
{
    enum class CoreWetStrokeDisposition : int32_t
    {
        Inking = 0,
        Completed = 1,
        Canceled = 2,
    };
    struct ICoreIncrementalInkStroke;
    struct ICoreIncrementalInkStrokeFactory;
    struct ICoreInkIndependentInputSource;
    struct ICoreInkIndependentInputSource2;
    struct ICoreInkIndependentInputSourceStatics;
    struct ICoreInkPresenterHost;
    struct ICoreWetStrokeUpdateEventArgs;
    struct ICoreWetStrokeUpdateSource;
    struct ICoreWetStrokeUpdateSourceStatics;
    struct CoreIncrementalInkStroke;
    struct CoreInkIndependentInputSource;
    struct CoreInkPresenterHost;
    struct CoreWetStrokeUpdateEventArgs;
    struct CoreWetStrokeUpdateSource;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::ICoreInkPresenterHost>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::CoreInkPresenterHost>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke> = L"Windows.UI.Input.Inking.Core.CoreIncrementalInkStroke";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource> = L"Windows.UI.Input.Inking.Core.CoreInkIndependentInputSource";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::CoreInkPresenterHost> = L"Windows.UI.Input.Inking.Core.CoreInkPresenterHost";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> = L"Windows.UI.Input.Inking.Core.CoreWetStrokeUpdateEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource> = L"Windows.UI.Input.Inking.Core.CoreWetStrokeUpdateSource";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition> = L"Windows.UI.Input.Inking.Core.CoreWetStrokeDisposition";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke> = L"Windows.UI.Input.Inking.Core.ICoreIncrementalInkStroke";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory> = L"Windows.UI.Input.Inking.Core.ICoreIncrementalInkStrokeFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource> = L"Windows.UI.Input.Inking.Core.ICoreInkIndependentInputSource";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource2> = L"Windows.UI.Input.Inking.Core.ICoreInkIndependentInputSource2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics> = L"Windows.UI.Input.Inking.Core.ICoreInkIndependentInputSourceStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::ICoreInkPresenterHost> = L"Windows.UI.Input.Inking.Core.ICoreInkPresenterHost";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs> = L"Windows.UI.Input.Inking.Core.ICoreWetStrokeUpdateEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource> = L"Windows.UI.Input.Inking.Core.ICoreWetStrokeUpdateSource";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics> = L"Windows.UI.Input.Inking.Core.ICoreWetStrokeUpdateSourceStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke>{ 0xFDA015D3,0x9D66,0x4F7D,{ 0xA5,0x7F,0xCC,0x70,0xB9,0xCF,0xAA,0x76 } }; // FDA015D3-9D66-4F7D-A57F-CC70B9CFAA76
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory>{ 0xD7C59F46,0x8DA8,0x4F70,{ 0x97,0x51,0xE5,0x3B,0xB6,0xDF,0x45,0x96 } }; // D7C59F46-8DA8-4F70-9751-E53BB6DF4596
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>{ 0x39B38DA9,0x7639,0x4499,{ 0xA5,0xB5,0x19,0x1D,0x00,0xE3,0x5B,0x16 } }; // 39B38DA9-7639-4499-A5B5-191D00E35B16
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource2>{ 0x2846B012,0x0B59,0x5BB9,{ 0xA3,0xC5,0xBE,0xCB,0x7C,0xF0,0x3A,0x33 } }; // 2846B012-0B59-5BB9-A3C5-BECB7CF03A33
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics>{ 0x73E6011B,0x80C0,0x4DFB,{ 0x9B,0x66,0x10,0xBA,0x7F,0x3F,0x9C,0x84 } }; // 73E6011B-80C0-4DFB-9B66-10BA7F3F9C84
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Inking::Core::ICoreInkPresenterHost>{ 0x396E89E6,0x7D55,0x4617,{ 0x9E,0x58,0x68,0xC7,0x0C,0x91,0x69,0xB9 } }; // 396E89E6-7D55-4617-9E58-68C70C9169B9
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs>{ 0xFB07D14C,0x3380,0x457A,{ 0xA9,0x87,0x99,0x13,0x57,0x89,0x6C,0x1B } }; // FB07D14C-3380-457A-A987-991357896C1B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>{ 0x1F718E22,0xEE52,0x4E00,{ 0x82,0x09,0x4C,0x3E,0x5B,0x21,0xA3,0xCC } }; // 1F718E22-EE52-4E00-8209-4C3E5B21A3CC
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics>{ 0x3DAD9CBA,0x1D3D,0x46AE,{ 0xAB,0x9D,0x86,0x47,0x48,0x6C,0x6F,0x90 } }; // 3DAD9CBA-1D3D-46AE-AB9D-8647486C6F90
    template <> struct default_interface<winrt::Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke>{ using type = winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke; };
    template <> struct default_interface<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource>{ using type = winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource; };
    template <> struct default_interface<winrt::Windows::UI::Input::Inking::Core::CoreInkPresenterHost>{ using type = winrt::Windows::UI::Input::Inking::Core::ICoreInkPresenterHost; };
    template <> struct default_interface<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs>{ using type = winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource>{ using type = winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource; };
    template <> struct abi<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AppendInkPoints(void*, winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall CreateInkStroke(void**) noexcept = 0;
            virtual int32_t __stdcall get_DrawingAttributes(void**) noexcept = 0;
            virtual int32_t __stdcall get_PointTransform(winrt::Windows::Foundation::Numerics::float3x2*) noexcept = 0;
            virtual int32_t __stdcall get_BoundingRect(winrt::Windows::Foundation::Rect*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, winrt::Windows::Foundation::Numerics::float3x2, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_PointerEntering(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PointerEntering(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_PointerHovering(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PointerHovering(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_PointerExiting(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PointerExiting(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_PointerPressing(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PointerPressing(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_PointerMoving(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PointerMoving(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_PointerReleasing(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PointerReleasing(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_PointerLost(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PointerLost(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_InkPresenter(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PointerCursor(void**) noexcept = 0;
            virtual int32_t __stdcall put_PointerCursor(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::Inking::Core::ICoreInkPresenterHost>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_InkPresenter(void**) noexcept = 0;
            virtual int32_t __stdcall get_RootVisual(void**) noexcept = 0;
            virtual int32_t __stdcall put_RootVisual(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_NewInkPoints(void**) noexcept = 0;
            virtual int32_t __stdcall get_PointerId(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Disposition(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Disposition(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_WetStrokeStarting(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_WetStrokeStarting(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_WetStrokeContinuing(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_WetStrokeContinuing(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_WetStrokeStopping(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_WetStrokeStopping(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_WetStrokeCompleted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_WetStrokeCompleted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_WetStrokeCanceled(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_WetStrokeCanceled(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_InkPresenter(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStroke
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) AppendInkPoints(param::iterable<winrt::Windows::UI::Input::Inking::InkPoint> const& inkPoints) const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkStroke) CreateInkStroke() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkDrawingAttributes) DrawingAttributes() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3x2) PointTransform() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) BoundingRect() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke>
    {
        template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStroke<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStrokeFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke) Create(winrt::Windows::UI::Input::Inking::InkDrawingAttributes const& drawingAttributes, winrt::Windows::Foundation::Numerics::float3x2 const& pointTransform) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory>
    {
        template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStrokeFactory<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource
    {
        WINRT_IMPL_AUTO(winrt::event_token) PointerEntering(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        using PointerEntering_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerEntering>;
        [[nodiscard]] PointerEntering_revoker PointerEntering(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) PointerEntering(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) PointerHovering(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        using PointerHovering_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerHovering>;
        [[nodiscard]] PointerHovering_revoker PointerHovering(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) PointerHovering(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) PointerExiting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        using PointerExiting_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerExiting>;
        [[nodiscard]] PointerExiting_revoker PointerExiting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) PointerExiting(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) PointerPressing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        using PointerPressing_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerPressing>;
        [[nodiscard]] PointerPressing_revoker PointerPressing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) PointerPressing(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) PointerMoving(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        using PointerMoving_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerMoving>;
        [[nodiscard]] PointerMoving_revoker PointerMoving(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) PointerMoving(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) PointerReleasing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        using PointerReleasing_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerReleasing>;
        [[nodiscard]] PointerReleasing_revoker PointerReleasing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) PointerReleasing(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) PointerLost(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        using PointerLost_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerLost>;
        [[nodiscard]] PointerLost_revoker PointerLost(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) PointerLost(winrt::event_token const& cookie) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkPresenter) InkPresenter() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>
    {
        template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreCursor) PointerCursor() const;
        WINRT_IMPL_AUTO(void) PointerCursor(winrt::Windows::UI::Core::CoreCursor const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource2>
    {
        template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSourceStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource) Create(winrt::Windows::UI::Input::Inking::InkPresenter const& inkPresenter) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics>
    {
        template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSourceStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_Inking_Core_ICoreInkPresenterHost
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkPresenter) InkPresenter() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::ContainerVisual) RootVisual() const;
        WINRT_IMPL_AUTO(void) RootVisual(winrt::Windows::UI::Composition::ContainerVisual const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Inking::Core::ICoreInkPresenterHost>
    {
        template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreInkPresenterHost<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::Inking::InkPoint>) NewInkPoints() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) PointerId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition) Disposition() const;
        WINRT_IMPL_AUTO(void) Disposition(winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource
    {
        WINRT_IMPL_AUTO(winrt::event_token) WetStrokeStarting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
        using WetStrokeStarting_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>::remove_WetStrokeStarting>;
        [[nodiscard]] WetStrokeStarting_revoker WetStrokeStarting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) WetStrokeStarting(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) WetStrokeContinuing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
        using WetStrokeContinuing_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>::remove_WetStrokeContinuing>;
        [[nodiscard]] WetStrokeContinuing_revoker WetStrokeContinuing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) WetStrokeContinuing(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) WetStrokeStopping(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
        using WetStrokeStopping_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>::remove_WetStrokeStopping>;
        [[nodiscard]] WetStrokeStopping_revoker WetStrokeStopping(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) WetStrokeStopping(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) WetStrokeCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
        using WetStrokeCompleted_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>::remove_WetStrokeCompleted>;
        [[nodiscard]] WetStrokeCompleted_revoker WetStrokeCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) WetStrokeCompleted(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) WetStrokeCanceled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
        using WetStrokeCanceled_revoker = impl::event_revoker<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource, &impl::abi_t<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>::remove_WetStrokeCanceled>;
        [[nodiscard]] WetStrokeCanceled_revoker WetStrokeCanceled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) WetStrokeCanceled(winrt::event_token const& cookie) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkPresenter) InkPresenter() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>
    {
        template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSourceStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource) Create(winrt::Windows::UI::Input::Inking::InkPresenter const& inkPresenter) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics>
    {
        template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSourceStatics<D>;
    };
}
#endif
