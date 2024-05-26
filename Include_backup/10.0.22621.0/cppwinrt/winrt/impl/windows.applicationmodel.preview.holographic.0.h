// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Preview_Holographic_0_H
#define WINRT_Windows_ApplicationModel_Preview_Holographic_0_H
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Activation
{
    struct IActivatedEventArgs;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Numerics
{
}
WINRT_EXPORT namespace winrt::Windows::Perception::Spatial
{
    struct SpatialCoordinateSystem;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::Holographic
{
    struct IHolographicApplicationPreviewStatics;
    struct IHolographicKeyboardPlacementOverridePreview;
    struct IHolographicKeyboardPlacementOverridePreviewStatics;
    struct HolographicApplicationPreview;
    struct HolographicKeyboardPlacementOverridePreview;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Holographic::HolographicApplicationPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Holographic::HolographicApplicationPreview> = L"Windows.ApplicationModel.Preview.Holographic.HolographicApplicationPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview> = L"Windows.ApplicationModel.Preview.Holographic.HolographicKeyboardPlacementOverridePreview";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics> = L"Windows.ApplicationModel.Preview.Holographic.IHolographicApplicationPreviewStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview> = L"Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreview";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics> = L"Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreviewStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics>{ 0xFE038691,0x2A3A,0x45A9,{ 0xA2,0x08,0x7B,0xED,0x69,0x19,0x19,0xF3 } }; // FE038691-2A3A-45A9-A208-7BED691919F3
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview>{ 0xC8A8CE3A,0xDFDE,0x5A14,{ 0x8D,0x5F,0x18,0x2C,0x52,0x6D,0xD9,0xC4 } }; // C8A8CE3A-DFDE-5A14-8D5F-182C526DD9C4
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics>{ 0x202E6039,0x1FF6,0x5A06,{ 0xAA,0xC4,0xA5,0xE2,0x4F,0xA3,0xEC,0x4B } }; // 202E6039-1FF6-5A06-AAC4-A5E24FA3EC4B
    template <> struct default_interface<winrt::Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview>{ using type = winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview; };
    template <> struct abi<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsCurrentViewPresentedOnHolographicDisplay(bool*) noexcept = 0;
            virtual int32_t __stdcall IsHolographicActivation(void*, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetPlacementOverride(void*, winrt::Windows::Foundation::Numerics::float3, winrt::Windows::Foundation::Numerics::float3) noexcept = 0;
            virtual int32_t __stdcall SetPlacementOverrideWithMaxSize(void*, winrt::Windows::Foundation::Numerics::float3, winrt::Windows::Foundation::Numerics::float3, winrt::Windows::Foundation::Numerics::float2) noexcept = 0;
            virtual int32_t __stdcall ResetPlacementOverride() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Preview_Holographic_IHolographicApplicationPreviewStatics
    {
        WINRT_IMPL_AUTO(bool) IsCurrentViewPresentedOnHolographicDisplay() const;
        WINRT_IMPL_AUTO(bool) IsHolographicActivation(winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs const& activatedEventArgs) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Preview_Holographic_IHolographicApplicationPreviewStatics<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreview
    {
        WINRT_IMPL_AUTO(void) SetPlacementOverride(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& topCenterPosition, winrt::Windows::Foundation::Numerics::float3 const& normal) const;
        WINRT_IMPL_AUTO(void) SetPlacementOverride(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& topCenterPosition, winrt::Windows::Foundation::Numerics::float3 const& normal, winrt::Windows::Foundation::Numerics::float2 const& maxSize) const;
        WINRT_IMPL_AUTO(void) ResetPlacementOverride() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreview<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreviewStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview) GetForCurrentView() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreviewStatics<D>;
    };
}
#endif
