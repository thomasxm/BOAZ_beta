// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Perception_Provider_0_H
#define WINRT_Windows_Devices_Perception_Provider_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Perception
{
    enum class PerceptionFrameSourcePropertyChangeStatus : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct Deferral;
    struct IMemoryBuffer;
    struct Size;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    struct IPropertySet;
    template <typename T> struct __declspec(empty_bases) IVectorView;
    struct ValueSet;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Numerics
{
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging
{
    enum class BitmapAlphaMode : int32_t;
    enum class BitmapPixelFormat : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Media
{
    struct VideoFrame;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Perception::Provider
{
    struct IKnownPerceptionFrameKindStatics;
    struct IPerceptionControlGroup;
    struct IPerceptionControlGroupFactory;
    struct IPerceptionCorrelation;
    struct IPerceptionCorrelationFactory;
    struct IPerceptionCorrelationGroup;
    struct IPerceptionCorrelationGroupFactory;
    struct IPerceptionFaceAuthenticationGroup;
    struct IPerceptionFaceAuthenticationGroupFactory;
    struct IPerceptionFrame;
    struct IPerceptionFrameProvider;
    struct IPerceptionFrameProviderInfo;
    struct IPerceptionFrameProviderManager;
    struct IPerceptionFrameProviderManagerServiceStatics;
    struct IPerceptionPropertyChangeRequest;
    struct IPerceptionVideoFrameAllocator;
    struct IPerceptionVideoFrameAllocatorFactory;
    struct KnownPerceptionFrameKind;
    struct PerceptionControlGroup;
    struct PerceptionCorrelation;
    struct PerceptionCorrelationGroup;
    struct PerceptionFaceAuthenticationGroup;
    struct PerceptionFrame;
    struct PerceptionFrameProviderInfo;
    struct PerceptionFrameProviderManagerService;
    struct PerceptionPropertyChangeRequest;
    struct PerceptionVideoFrameAllocator;
    struct PerceptionStartFaceAuthenticationHandler;
    struct PerceptionStopFaceAuthenticationHandler;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionFrame>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::KnownPerceptionFrameKind>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::PerceptionFrame>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderManagerService>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler>{ using type = delegate_category; };
    template <> struct category<winrt::Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler>{ using type = delegate_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::KnownPerceptionFrameKind> = L"Windows.Devices.Perception.Provider.KnownPerceptionFrameKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup> = L"Windows.Devices.Perception.Provider.PerceptionControlGroup";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation> = L"Windows.Devices.Perception.Provider.PerceptionCorrelation";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup> = L"Windows.Devices.Perception.Provider.PerceptionCorrelationGroup";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup> = L"Windows.Devices.Perception.Provider.PerceptionFaceAuthenticationGroup";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::PerceptionFrame> = L"Windows.Devices.Perception.Provider.PerceptionFrame";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo> = L"Windows.Devices.Perception.Provider.PerceptionFrameProviderInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderManagerService> = L"Windows.Devices.Perception.Provider.PerceptionFrameProviderManagerService";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest> = L"Windows.Devices.Perception.Provider.PerceptionPropertyChangeRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator> = L"Windows.Devices.Perception.Provider.PerceptionVideoFrameAllocator";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics> = L"Windows.Devices.Perception.Provider.IKnownPerceptionFrameKindStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup> = L"Windows.Devices.Perception.Provider.IPerceptionControlGroup";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory> = L"Windows.Devices.Perception.Provider.IPerceptionControlGroupFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation> = L"Windows.Devices.Perception.Provider.IPerceptionCorrelation";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory> = L"Windows.Devices.Perception.Provider.IPerceptionCorrelationFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup> = L"Windows.Devices.Perception.Provider.IPerceptionCorrelationGroup";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory> = L"Windows.Devices.Perception.Provider.IPerceptionCorrelationGroupFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup> = L"Windows.Devices.Perception.Provider.IPerceptionFaceAuthenticationGroup";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory> = L"Windows.Devices.Perception.Provider.IPerceptionFaceAuthenticationGroupFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFrame> = L"Windows.Devices.Perception.Provider.IPerceptionFrame";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider> = L"Windows.Devices.Perception.Provider.IPerceptionFrameProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo> = L"Windows.Devices.Perception.Provider.IPerceptionFrameProviderInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager> = L"Windows.Devices.Perception.Provider.IPerceptionFrameProviderManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics> = L"Windows.Devices.Perception.Provider.IPerceptionFrameProviderManagerServiceStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest> = L"Windows.Devices.Perception.Provider.IPerceptionPropertyChangeRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator> = L"Windows.Devices.Perception.Provider.IPerceptionVideoFrameAllocator";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory> = L"Windows.Devices.Perception.Provider.IPerceptionVideoFrameAllocatorFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler> = L"Windows.Devices.Perception.Provider.PerceptionStartFaceAuthenticationHandler";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler> = L"Windows.Devices.Perception.Provider.PerceptionStopFaceAuthenticationHandler";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics>{ 0x3AE651D6,0x9669,0x4106,{ 0x9F,0xAE,0x48,0x35,0xC1,0xB9,0x61,0x04 } }; // 3AE651D6-9669-4106-9FAE-4835C1B96104
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup>{ 0x172C4882,0x2FD9,0x4C4E,{ 0xBA,0x34,0xFD,0xF2,0x0A,0x73,0xDD,0xE5 } }; // 172C4882-2FD9-4C4E-BA34-FDF20A73DDE5
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory>{ 0x2F1AF2E0,0xBAF1,0x453B,{ 0xBE,0xD4,0xCD,0x9D,0x46,0x19,0x15,0x4C } }; // 2F1AF2E0-BAF1-453B-BED4-CD9D4619154C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation>{ 0xB4131A82,0xDFF5,0x4047,{ 0x8A,0x19,0x3B,0x4D,0x80,0x5F,0x71,0x76 } }; // B4131A82-DFF5-4047-8A19-3B4D805F7176
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory>{ 0xD4A6C425,0x2884,0x4A8F,{ 0x81,0x34,0x28,0x35,0xD7,0x28,0x6C,0xBF } }; // D4A6C425-2884-4A8F-8134-2835D7286CBF
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup>{ 0x752A0906,0x36A7,0x47BB,{ 0x9B,0x79,0x56,0xCC,0x6B,0x74,0x67,0x70 } }; // 752A0906-36A7-47BB-9B79-56CC6B746770
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory>{ 0x7DFE2088,0x63DF,0x48ED,{ 0x83,0xB1,0x4A,0xB8,0x29,0x13,0x29,0x95 } }; // 7DFE2088-63DF-48ED-83B1-4AB829132995
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup>{ 0xE8019814,0x4A91,0x41B0,{ 0x83,0xA6,0x88,0x1A,0x17,0x75,0x35,0x3E } }; // E8019814-4A91-41B0-83A6-881A1775353E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory>{ 0xE68A05D4,0xB60C,0x40F4,{ 0xBC,0xB9,0xF2,0x4D,0x46,0x46,0x73,0x20 } }; // E68A05D4-B60C-40F4-BCB9-F24D46467320
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFrame>{ 0x7CFE7825,0x54BB,0x4D9D,{ 0xBE,0xC5,0x8E,0xF6,0x61,0x51,0xD2,0xAC } }; // 7CFE7825-54BB-4D9D-BEC5-8EF66151D2AC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider>{ 0x794F7AB9,0xB37D,0x3B33,{ 0xA1,0x0D,0x30,0x62,0x64,0x19,0xCE,0x65 } }; // 794F7AB9-B37D-3B33-A10D-30626419CE65
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo>{ 0xCCA959E8,0x797E,0x4E83,{ 0x9B,0x87,0x03,0x6A,0x74,0x14,0x2F,0xC4 } }; // CCA959E8-797E-4E83-9B87-036A74142FC4
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager>{ 0xA959CE07,0xEAD3,0x33DF,{ 0x8E,0xC1,0xB9,0x24,0xAB,0xE0,0x19,0xC4 } }; // A959CE07-EAD3-33DF-8EC1-B924ABE019C4
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>{ 0xAE8386E6,0xCAD9,0x4359,{ 0x8F,0x96,0x8E,0xAE,0x51,0x81,0x05,0x26 } }; // AE8386E6-CAD9-4359-8F96-8EAE51810526
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest>{ 0x3C5AEB51,0x350B,0x4DF8,{ 0x94,0x14,0x59,0xE0,0x98,0x15,0x51,0x0B } }; // 3C5AEB51-350B-4DF8-9414-59E09815510B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator>{ 0x4C38A7DA,0xFDD8,0x4ED4,{ 0xA0,0x39,0x2A,0x6F,0x9B,0x23,0x50,0x38 } }; // 4C38A7DA-FDD8-4ED4-A039-2A6F9B235038
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory>{ 0x1A58B0E1,0xE91A,0x481E,{ 0xB8,0x76,0xA8,0x9E,0x2B,0xBC,0x6B,0x33 } }; // 1A58B0E1-E91A-481E-B876-A89E2BBC6B33
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler>{ 0x74816D2A,0x2090,0x4670,{ 0x8C,0x48,0xEF,0x39,0xE7,0xFF,0x7C,0x26 } }; // 74816D2A-2090-4670-8C48-EF39E7FF7C26
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler>{ 0x387EE6AA,0x89CD,0x481E,{ 0xAA,0xDE,0xDD,0x92,0xF7,0x0B,0x2A,0xD7 } }; // 387EE6AA-89CD-481E-AADE-DD92F70B2AD7
    template <> struct default_interface<winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup>{ using type = winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup; };
    template <> struct default_interface<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation>{ using type = winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation; };
    template <> struct default_interface<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup>{ using type = winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup; };
    template <> struct default_interface<winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup>{ using type = winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup; };
    template <> struct default_interface<winrt::Windows::Devices::Perception::Provider::PerceptionFrame>{ using type = winrt::Windows::Devices::Perception::Provider::IPerceptionFrame; };
    template <> struct default_interface<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo>{ using type = winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo; };
    template <> struct default_interface<winrt::Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest>{ using type = winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest; };
    template <> struct default_interface<winrt::Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator>{ using type = winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator; };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Color(void**) noexcept = 0;
            virtual int32_t __stdcall get_Depth(void**) noexcept = 0;
            virtual int32_t __stdcall get_Infrared(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_FrameProviderIds(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TargetId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Numerics::float3*) noexcept = 0;
            virtual int32_t __stdcall get_Orientation(winrt::Windows::Foundation::Numerics::quaternion*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, winrt::Windows::Foundation::Numerics::float3, winrt::Windows::Foundation::Numerics::quaternion, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RelativeLocations(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_FrameProviderIds(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionFrame>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RelativeTime(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_RelativeTime(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
            virtual int32_t __stdcall get_FrameData(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_FrameProviderInfo(void**) noexcept = 0;
            virtual int32_t __stdcall get_Available(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
            virtual int32_t __stdcall Stop() noexcept = 0;
            virtual int32_t __stdcall SetProperty(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
            virtual int32_t __stdcall put_Id(void*) noexcept = 0;
            virtual int32_t __stdcall get_DisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayName(void*) noexcept = 0;
            virtual int32_t __stdcall get_DeviceKind(void**) noexcept = 0;
            virtual int32_t __stdcall put_DeviceKind(void*) noexcept = 0;
            virtual int32_t __stdcall get_FrameKind(void**) noexcept = 0;
            virtual int32_t __stdcall put_FrameKind(void*) noexcept = 0;
            virtual int32_t __stdcall get_Hidden(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Hidden(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetFrameProvider(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RegisterFrameProviderInfo(void*, void*) noexcept = 0;
            virtual int32_t __stdcall UnregisterFrameProviderInfo(void*, void*) noexcept = 0;
            virtual int32_t __stdcall RegisterFaceAuthenticationGroup(void*, void*) noexcept = 0;
            virtual int32_t __stdcall UnregisterFaceAuthenticationGroup(void*, void*) noexcept = 0;
            virtual int32_t __stdcall RegisterControlGroup(void*, void*) noexcept = 0;
            virtual int32_t __stdcall UnregisterControlGroup(void*, void*) noexcept = 0;
            virtual int32_t __stdcall RegisterCorrelationGroup(void*, void*) noexcept = 0;
            virtual int32_t __stdcall UnregisterCorrelationGroup(void*, void*) noexcept = 0;
            virtual int32_t __stdcall UpdateAvailabilityForProvider(void*, bool) noexcept = 0;
            virtual int32_t __stdcall PublishFrameForProvider(void*, void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_Value(void**) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Status(int32_t) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AllocateFrame(void**) noexcept = 0;
            virtual int32_t __stdcall CopyFromVideoFrame(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(uint32_t, int32_t, winrt::Windows::Foundation::Size, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IKnownPerceptionFrameKindStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Color() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Depth() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Infrared() const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IKnownPerceptionFrameKindStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionControlGroup
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) FrameProviderIds() const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionControlGroup<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionControlGroupFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup) Create(param::iterable<hstring> const& ids) const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionControlGroupFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionCorrelation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TargetId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) Position() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::quaternion) Orientation() const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionCorrelation<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation) Create(param::hstring const& targetId, winrt::Windows::Foundation::Numerics::float3 const& position, winrt::Windows::Foundation::Numerics::quaternion const& orientation) const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationGroup
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation>) RelativeLocations() const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationGroup<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationGroupFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup) Create(param::iterable<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation> const& relativeLocations) const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationGroupFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionFaceAuthenticationGroup
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) FrameProviderIds() const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionFaceAuthenticationGroup<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionFaceAuthenticationGroupFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup) Create(param::iterable<hstring> const& ids, winrt::Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler const& startHandler, winrt::Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler const& stopHandler) const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionFaceAuthenticationGroupFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionFrame
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) RelativeTime() const;
        WINRT_IMPL_AUTO(void) RelativeTime(winrt::Windows::Foundation::TimeSpan const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) Properties() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IMemoryBuffer) FrameData() const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionFrame>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionFrame<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo) FrameProviderInfo() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Available() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) Properties() const;
        WINRT_IMPL_AUTO(void) Start() const;
        WINRT_IMPL_AUTO(void) Stop() const;
        WINRT_IMPL_AUTO(void) SetProperty(winrt::Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
        WINRT_IMPL_AUTO(void) Id(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayName() const;
        WINRT_IMPL_AUTO(void) DisplayName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceKind() const;
        WINRT_IMPL_AUTO(void) DeviceKind(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) FrameKind() const;
        WINRT_IMPL_AUTO(void) FrameKind(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Hidden() const;
        WINRT_IMPL_AUTO(void) Hidden(bool value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManager
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider) GetFrameProvider(winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo) const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManager<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics
    {
        WINRT_IMPL_AUTO(void) RegisterFrameProviderInfo(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo) const;
        WINRT_IMPL_AUTO(void) UnregisterFrameProviderInfo(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo) const;
        WINRT_IMPL_AUTO(void) RegisterFaceAuthenticationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup) const;
        WINRT_IMPL_AUTO(void) UnregisterFaceAuthenticationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup) const;
        WINRT_IMPL_AUTO(void) RegisterControlGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup) const;
        WINRT_IMPL_AUTO(void) UnregisterControlGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup) const;
        WINRT_IMPL_AUTO(void) RegisterCorrelationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup) const;
        WINRT_IMPL_AUTO(void) UnregisterCorrelationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup) const;
        WINRT_IMPL_AUTO(void) UpdateAvailabilityForProvider(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, bool available) const;
        WINRT_IMPL_AUTO(void) PublishFrameForProvider(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, winrt::Windows::Devices::Perception::Provider::PerceptionFrame const& frame) const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) Value() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus) Status() const;
        WINRT_IMPL_AUTO(void) Status(winrt::Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionVideoFrameAllocator
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionFrame) AllocateFrame() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionFrame) CopyFromVideoFrame(winrt::Windows::Media::VideoFrame const& frame) const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionVideoFrameAllocator<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Perception_Provider_IPerceptionVideoFrameAllocatorFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator) Create(uint32_t maxOutstandingFrameCountForWrite, winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& format, winrt::Windows::Foundation::Size const& resolution, winrt::Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const;
    };
    template <> struct consume<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Perception_Provider_IPerceptionVideoFrameAllocatorFactory<D>;
    };
}
#endif
