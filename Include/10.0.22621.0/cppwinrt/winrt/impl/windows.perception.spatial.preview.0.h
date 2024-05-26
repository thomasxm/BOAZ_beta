// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Perception_Spatial_Preview_0_H
#define WINRT_Windows_Perception_Spatial_Preview_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation::Numerics
{
}
WINRT_EXPORT namespace winrt::Windows::Perception::Spatial
{
    struct SpatialCoordinateSystem;
    struct SpatialLocator;
}
WINRT_EXPORT namespace winrt::Windows::Perception::Spatial::Preview
{
    struct ISpatialGraphInteropFrameOfReferencePreview;
    struct ISpatialGraphInteropPreviewStatics;
    struct ISpatialGraphInteropPreviewStatics2;
    struct SpatialGraphInteropFrameOfReferencePreview;
    struct SpatialGraphInteropPreview;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropPreview>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview> = L"Windows.Perception.Spatial.Preview.SpatialGraphInteropFrameOfReferencePreview";
    template <> inline constexpr auto& name_v<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropPreview> = L"Windows.Perception.Spatial.Preview.SpatialGraphInteropPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview> = L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropFrameOfReferencePreview";
    template <> inline constexpr auto& name_v<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics> = L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2> = L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics2";
    template <> inline constexpr guid guid_v<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview>{ 0xA8271B23,0x735F,0x5729,{ 0xA9,0x8E,0xE6,0x4E,0xD1,0x89,0xAB,0xC5 } }; // A8271B23-735F-5729-A98E-E64ED189ABC5
    template <> inline constexpr guid guid_v<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>{ 0xC042644C,0x20D8,0x4ED0,{ 0xAE,0xF7,0x68,0x05,0xB8,0xE5,0x3F,0x55 } }; // C042644C-20D8-4ED0-AEF7-6805B8E53F55
    template <> inline constexpr guid guid_v<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>{ 0x2490B15F,0x6CBD,0x4B1E,{ 0xB7,0x65,0x31,0xE4,0x62,0xA3,0x2D,0xF2 } }; // 2490B15F-6CBD-4B1E-B765-31E462A32DF2
    template <> struct default_interface<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview>{ using type = winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview; };
    template <> struct abi<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CoordinateSystem(void**) noexcept = 0;
            virtual int32_t __stdcall get_NodeId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_CoordinateSystemToNodeTransform(winrt::Windows::Foundation::Numerics::float4x4*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateCoordinateSystemForNode(winrt::guid, void**) noexcept = 0;
            virtual int32_t __stdcall CreateCoordinateSystemForNodeWithPosition(winrt::guid, winrt::Windows::Foundation::Numerics::float3, void**) noexcept = 0;
            virtual int32_t __stdcall CreateCoordinateSystemForNodeWithPositionAndOrientation(winrt::guid, winrt::Windows::Foundation::Numerics::float3, winrt::Windows::Foundation::Numerics::quaternion, void**) noexcept = 0;
            virtual int32_t __stdcall CreateLocatorForNode(winrt::guid, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TryCreateFrameOfReference(void*, void**) noexcept = 0;
            virtual int32_t __stdcall TryCreateFrameOfReferenceWithPosition(void*, winrt::Windows::Foundation::Numerics::float3, void**) noexcept = 0;
            virtual int32_t __stdcall TryCreateFrameOfReferenceWithPositionAndOrientation(void*, winrt::Windows::Foundation::Numerics::float3, winrt::Windows::Foundation::Numerics::quaternion, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) CoordinateSystem() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) NodeId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float4x4) CoordinateSystemToNodeTransform() const;
    };
    template <> struct consume<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview>
    {
        template <typename D> using type = consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview<D>;
    };
    template <typename D>
    struct consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) CreateCoordinateSystemForNode(winrt::guid const& nodeId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) CreateCoordinateSystemForNode(winrt::guid const& nodeId, winrt::Windows::Foundation::Numerics::float3 const& relativePosition) const;
        WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) CreateCoordinateSystemForNode(winrt::guid const& nodeId, winrt::Windows::Foundation::Numerics::float3 const& relativePosition, winrt::Windows::Foundation::Numerics::quaternion const& relativeOrientation) const;
        WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialLocator) CreateLocatorForNode(winrt::guid const& nodeId) const;
    };
    template <> struct consume<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>
    {
        template <typename D> using type = consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview) TryCreateFrameOfReference(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const;
        WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview) TryCreateFrameOfReference(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& relativePosition) const;
        WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview) TryCreateFrameOfReference(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& relativePosition, winrt::Windows::Foundation::Numerics::quaternion const& relativeOrientation) const;
    };
    template <> struct consume<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>
    {
        template <typename D> using type = consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2<D>;
    };
}
#endif
