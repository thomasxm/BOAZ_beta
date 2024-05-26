// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Composition_Diagnostics_0_H
#define WINRT_Windows_UI_Composition_Diagnostics_0_H
WINRT_EXPORT namespace winrt::Windows::UI::Composition
{
    struct Compositor;
    struct Visual;
}
WINRT_EXPORT namespace winrt::Windows::UI::Composition::Diagnostics
{
    enum class CompositionDebugOverdrawContentKinds : uint32_t
    {
        None = 0,
        OffscreenRendered = 0x1,
        Colors = 0x2,
        Effects = 0x4,
        Shadows = 0x8,
        Lights = 0x10,
        Surfaces = 0x20,
        SwapChains = 0x40,
        All = 0xffffffff,
    };
    struct ICompositionDebugHeatMaps;
    struct ICompositionDebugSettings;
    struct ICompositionDebugSettingsStatics;
    struct CompositionDebugHeatMaps;
    struct CompositionDebugSettings;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugSettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps> = L"Windows.UI.Composition.Diagnostics.CompositionDebugHeatMaps";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugSettings> = L"Windows.UI.Composition.Diagnostics.CompositionDebugSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds> = L"Windows.UI.Composition.Diagnostics.CompositionDebugOverdrawContentKinds";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps> = L"Windows.UI.Composition.Diagnostics.ICompositionDebugHeatMaps";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings> = L"Windows.UI.Composition.Diagnostics.ICompositionDebugSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics> = L"Windows.UI.Composition.Diagnostics.ICompositionDebugSettingsStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps>{ 0xE49C90AC,0x2FF3,0x5805,{ 0x71,0x8C,0xB7,0x25,0xEE,0x07,0x65,0x0F } }; // E49C90AC-2FF3-5805-718C-B725EE07650F
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings>{ 0x2831987E,0x1D82,0x4D38,{ 0xB7,0xB7,0xEF,0xD1,0x1C,0x7B,0xC3,0xD1 } }; // 2831987E-1D82-4D38-B7B7-EFD11C7BC3D1
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics>{ 0x64EC1F1E,0x6AF8,0x4AF8,{ 0xB8,0x14,0xC8,0x70,0xFD,0x5A,0x95,0x05 } }; // 64EC1F1E-6AF8-4AF8-B814-C870FD5A9505
    template <> struct default_interface<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps>{ using type = winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps; };
    template <> struct default_interface<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugSettings>{ using type = winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings; };
    template <> struct abi<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Hide(void*) noexcept = 0;
            virtual int32_t __stdcall ShowMemoryUsage(void*) noexcept = 0;
            virtual int32_t __stdcall ShowOverdraw(void*, uint32_t) noexcept = 0;
            virtual int32_t __stdcall ShowRedraw(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_HeatMaps(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TryGetSettings(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_UI_Composition_Diagnostics_ICompositionDebugHeatMaps
    {
        WINRT_IMPL_AUTO(void) Hide(winrt::Windows::UI::Composition::Visual const& subtree) const;
        WINRT_IMPL_AUTO(void) ShowMemoryUsage(winrt::Windows::UI::Composition::Visual const& subtree) const;
        WINRT_IMPL_AUTO(void) ShowOverdraw(winrt::Windows::UI::Composition::Visual const& subtree, winrt::Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds const& contentKinds) const;
        WINRT_IMPL_AUTO(void) ShowRedraw(winrt::Windows::UI::Composition::Visual const& subtree) const;
    };
    template <> struct consume<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps>
    {
        template <typename D> using type = consume_Windows_UI_Composition_Diagnostics_ICompositionDebugHeatMaps<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Composition_Diagnostics_ICompositionDebugSettings
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps) HeatMaps() const;
    };
    template <> struct consume<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings>
    {
        template <typename D> using type = consume_Windows_UI_Composition_Diagnostics_ICompositionDebugSettings<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Composition_Diagnostics_ICompositionDebugSettingsStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Diagnostics::CompositionDebugSettings) TryGetSettings(winrt::Windows::UI::Composition::Compositor const& compositor) const;
    };
    template <> struct consume<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics>
    {
        template <typename D> using type = consume_Windows_UI_Composition_Diagnostics_ICompositionDebugSettingsStatics<D>;
    };
}
#endif
