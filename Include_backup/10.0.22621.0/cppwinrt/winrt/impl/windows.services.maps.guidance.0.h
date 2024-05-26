// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Services_Maps_Guidance_0_H
#define WINRT_Windows_Services_Maps_Guidance_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation
{
    struct BasicGeoposition;
    struct GeoboundingBox;
    struct Geocoordinate;
    struct Geopath;
    struct Geopoint;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Services::Maps
{
    struct MapRoute;
}
WINRT_EXPORT namespace winrt::Windows::UI
{
    struct Color;
}
WINRT_EXPORT namespace winrt::Windows::Services::Maps::Guidance
{
    enum class GuidanceAudioMeasurementSystem : int32_t
    {
        Meters = 0,
        MilesAndYards = 1,
        MilesAndFeet = 2,
    };
    enum class GuidanceAudioNotificationKind : int32_t
    {
        Maneuver = 0,
        Route = 1,
        Gps = 2,
        SpeedLimit = 3,
        Traffic = 4,
        TrafficCamera = 5,
    };
    enum class GuidanceAudioNotifications : uint32_t
    {
        None = 0,
        Maneuver = 0x1,
        Route = 0x2,
        Gps = 0x4,
        SpeedLimit = 0x8,
        Traffic = 0x10,
        TrafficCamera = 0x20,
    };
    enum class GuidanceLaneMarkers : uint32_t
    {
        None = 0,
        LightRight = 0x1,
        Right = 0x2,
        HardRight = 0x4,
        Straight = 0x8,
        UTurnLeft = 0x10,
        HardLeft = 0x20,
        Left = 0x40,
        LightLeft = 0x80,
        UTurnRight = 0x100,
        Unknown = 0xffffffff,
    };
    enum class GuidanceManeuverKind : int32_t
    {
        None = 0,
        GoStraight = 1,
        UTurnRight = 2,
        UTurnLeft = 3,
        TurnKeepRight = 4,
        TurnLightRight = 5,
        TurnRight = 6,
        TurnHardRight = 7,
        KeepMiddle = 8,
        TurnKeepLeft = 9,
        TurnLightLeft = 10,
        TurnLeft = 11,
        TurnHardLeft = 12,
        FreewayEnterRight = 13,
        FreewayEnterLeft = 14,
        FreewayLeaveRight = 15,
        FreewayLeaveLeft = 16,
        FreewayKeepRight = 17,
        FreewayKeepLeft = 18,
        TrafficCircleRight1 = 19,
        TrafficCircleRight2 = 20,
        TrafficCircleRight3 = 21,
        TrafficCircleRight4 = 22,
        TrafficCircleRight5 = 23,
        TrafficCircleRight6 = 24,
        TrafficCircleRight7 = 25,
        TrafficCircleRight8 = 26,
        TrafficCircleRight9 = 27,
        TrafficCircleRight10 = 28,
        TrafficCircleRight11 = 29,
        TrafficCircleRight12 = 30,
        TrafficCircleLeft1 = 31,
        TrafficCircleLeft2 = 32,
        TrafficCircleLeft3 = 33,
        TrafficCircleLeft4 = 34,
        TrafficCircleLeft5 = 35,
        TrafficCircleLeft6 = 36,
        TrafficCircleLeft7 = 37,
        TrafficCircleLeft8 = 38,
        TrafficCircleLeft9 = 39,
        TrafficCircleLeft10 = 40,
        TrafficCircleLeft11 = 41,
        TrafficCircleLeft12 = 42,
        Start = 43,
        End = 44,
        TakeFerry = 45,
        PassTransitStation = 46,
        LeaveTransitStation = 47,
    };
    enum class GuidanceMode : int32_t
    {
        None = 0,
        Simulation = 1,
        Navigation = 2,
        Tracking = 3,
    };
    struct IGuidanceAudioNotificationRequestedEventArgs;
    struct IGuidanceLaneInfo;
    struct IGuidanceManeuver;
    struct IGuidanceMapMatchedCoordinate;
    struct IGuidanceNavigator;
    struct IGuidanceNavigator2;
    struct IGuidanceNavigatorStatics;
    struct IGuidanceNavigatorStatics2;
    struct IGuidanceReroutedEventArgs;
    struct IGuidanceRoadSegment;
    struct IGuidanceRoadSegment2;
    struct IGuidanceRoadSignpost;
    struct IGuidanceRoute;
    struct IGuidanceRouteStatics;
    struct IGuidanceTelemetryCollector;
    struct IGuidanceTelemetryCollectorStatics;
    struct IGuidanceUpdatedEventArgs;
    struct GuidanceAudioNotificationRequestedEventArgs;
    struct GuidanceLaneInfo;
    struct GuidanceManeuver;
    struct GuidanceMapMatchedCoordinate;
    struct GuidanceNavigator;
    struct GuidanceReroutedEventArgs;
    struct GuidanceRoadSegment;
    struct GuidanceRoadSignpost;
    struct GuidanceRoute;
    struct GuidanceTelemetryCollector;
    struct GuidanceUpdatedEventArgs;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceRoute>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceLaneInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver>{ using type = class_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate>{ using type = class_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment>{ using type = class_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSignpost>{ using type = class_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceRoute>{ using type = class_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceTelemetryCollector>{ using type = class_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotifications>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceLaneMarkers>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceManeuverKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Services::Maps::Guidance::GuidanceMode>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> = L"Windows.Services.Maps.Guidance.GuidanceAudioNotificationRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceLaneInfo> = L"Windows.Services.Maps.Guidance.GuidanceLaneInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver> = L"Windows.Services.Maps.Guidance.GuidanceManeuver";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate> = L"Windows.Services.Maps.Guidance.GuidanceMapMatchedCoordinate";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator> = L"Windows.Services.Maps.Guidance.GuidanceNavigator";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> = L"Windows.Services.Maps.Guidance.GuidanceReroutedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment> = L"Windows.Services.Maps.Guidance.GuidanceRoadSegment";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSignpost> = L"Windows.Services.Maps.Guidance.GuidanceRoadSignpost";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceRoute> = L"Windows.Services.Maps.Guidance.GuidanceRoute";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceTelemetryCollector> = L"Windows.Services.Maps.Guidance.GuidanceTelemetryCollector";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> = L"Windows.Services.Maps.Guidance.GuidanceUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem> = L"Windows.Services.Maps.Guidance.GuidanceAudioMeasurementSystem";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationKind> = L"Windows.Services.Maps.Guidance.GuidanceAudioNotificationKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotifications> = L"Windows.Services.Maps.Guidance.GuidanceAudioNotifications";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceLaneMarkers> = L"Windows.Services.Maps.Guidance.GuidanceLaneMarkers";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceManeuverKind> = L"Windows.Services.Maps.Guidance.GuidanceManeuverKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::GuidanceMode> = L"Windows.Services.Maps.Guidance.GuidanceMode";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs> = L"Windows.Services.Maps.Guidance.IGuidanceAudioNotificationRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo> = L"Windows.Services.Maps.Guidance.IGuidanceLaneInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver> = L"Windows.Services.Maps.Guidance.IGuidanceManeuver";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate> = L"Windows.Services.Maps.Guidance.IGuidanceMapMatchedCoordinate";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator> = L"Windows.Services.Maps.Guidance.IGuidanceNavigator";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2> = L"Windows.Services.Maps.Guidance.IGuidanceNavigator2";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics> = L"Windows.Services.Maps.Guidance.IGuidanceNavigatorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2> = L"Windows.Services.Maps.Guidance.IGuidanceNavigatorStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs> = L"Windows.Services.Maps.Guidance.IGuidanceReroutedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment> = L"Windows.Services.Maps.Guidance.IGuidanceRoadSegment";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment2> = L"Windows.Services.Maps.Guidance.IGuidanceRoadSegment2";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost> = L"Windows.Services.Maps.Guidance.IGuidanceRoadSignpost";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceRoute> = L"Windows.Services.Maps.Guidance.IGuidanceRoute";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics> = L"Windows.Services.Maps.Guidance.IGuidanceRouteStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector> = L"Windows.Services.Maps.Guidance.IGuidanceTelemetryCollector";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics> = L"Windows.Services.Maps.Guidance.IGuidanceTelemetryCollectorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs> = L"Windows.Services.Maps.Guidance.IGuidanceUpdatedEventArgs";
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs>{ 0xCA2AA24A,0xC7C2,0x4D4C,{ 0x9D,0x7C,0x49,0x95,0x76,0xBC,0xED,0xDB } }; // CA2AA24A-C7C2-4D4C-9D7C-499576BCEDDB
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo>{ 0x8404D114,0x6581,0x43B7,{ 0xAC,0x15,0xC9,0x07,0x9B,0xF9,0x0D,0xF1 } }; // 8404D114-6581-43B7-AC15-C9079BF90DF1
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver>{ 0xFC09326C,0xECC9,0x4928,{ 0xA2,0xA1,0x72,0x32,0xB9,0x9B,0x94,0xA1 } }; // FC09326C-ECC9-4928-A2A1-7232B99B94A1
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate>{ 0xB7ACB168,0x2912,0x4A99,{ 0xAF,0xF1,0x79,0x86,0x09,0xB9,0x81,0xFE } }; // B7ACB168-2912-4A99-AFF1-798609B981FE
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>{ 0x08F17EF7,0x8E3F,0x4D9A,{ 0xBE,0x8A,0x10,0x8F,0x9A,0x01,0x2C,0x67 } }; // 08F17EF7-8E3F-4D9A-BE8A-108F9A012C67
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2>{ 0x6CDC50D1,0x041C,0x4BF3,{ 0xB6,0x33,0xA1,0x01,0xFC,0x2F,0x6B,0x57 } }; // 6CDC50D1-041C-4BF3-B633-A101FC2F6B57
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics>{ 0x00FD9513,0x4456,0x4E66,{ 0xA1,0x43,0x3A,0xDD,0x6B,0xE0,0x84,0x26 } }; // 00FD9513-4456-4E66-A143-3ADD6BE08426
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2>{ 0x54C5C3E2,0x7784,0x4C85,{ 0x8C,0x95,0xD0,0xC6,0xEF,0xB4,0x39,0x65 } }; // 54C5C3E2-7784-4C85-8C95-D0C6EFB43965
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs>{ 0x115D4008,0xD528,0x454E,{ 0xBB,0x94,0xA5,0x03,0x41,0xD2,0xC9,0xF1 } }; // 115D4008-D528-454E-BB94-A50341D2C9F1
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment>{ 0xB32758A6,0xBE78,0x4C63,{ 0xAF,0xE7,0x6C,0x29,0x57,0x47,0x9B,0x3E } }; // B32758A6-BE78-4C63-AFE7-6C2957479B3E
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment2>{ 0x2474A61D,0x1723,0x49F1,{ 0x89,0x5B,0x47,0xA2,0xC4,0xAA,0x9C,0x55 } }; // 2474A61D-1723-49F1-895B-47A2C4AA9C55
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost>{ 0xF1A728B6,0xF77A,0x4742,{ 0x83,0x12,0x53,0x30,0x0F,0x98,0x45,0xF0 } }; // F1A728B6-F77A-4742-8312-53300F9845F0
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceRoute>{ 0x3A14545D,0x801A,0x40BD,{ 0xA2,0x86,0xAF,0xB2,0x01,0x0C,0xCE,0x6C } }; // 3A14545D-801A-40BD-A286-AFB2010CCE6C
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics>{ 0xF56D926A,0x55ED,0x49C1,{ 0xB0,0x9C,0x4B,0x82,0x23,0xB5,0x0D,0xB3 } }; // F56D926A-55ED-49C1-B09C-4B8223B50DB3
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector>{ 0xDB1F8DA5,0xB878,0x4D92,{ 0x98,0xDD,0x34,0x7D,0x23,0xD3,0x82,0x62 } }; // DB1F8DA5-B878-4D92-98DD-347D23D38262
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics>{ 0x36532047,0xF160,0x44FB,{ 0xB5,0x78,0x94,0x57,0x7C,0xA0,0x59,0x90 } }; // 36532047-F160-44FB-B578-94577CA05990
    template <> inline constexpr guid guid_v<winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs>{ 0xFDAC160B,0x9E8D,0x4DE3,{ 0xA9,0xFA,0xB0,0x63,0x21,0xD1,0x8D,0xB9 } }; // FDAC160B-9E8D-4DE3-A9FA-B06321D18DB9
    template <> struct default_interface<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs>{ using type = winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::Services::Maps::Guidance::GuidanceLaneInfo>{ using type = winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo; };
    template <> struct default_interface<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver>{ using type = winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver; };
    template <> struct default_interface<winrt::Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate>{ using type = winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate; };
    template <> struct default_interface<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator>{ using type = winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator; };
    template <> struct default_interface<winrt::Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs>{ using type = winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs; };
    template <> struct default_interface<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment>{ using type = winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment; };
    template <> struct default_interface<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSignpost>{ using type = winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost; };
    template <> struct default_interface<winrt::Windows::Services::Maps::Guidance::GuidanceRoute>{ using type = winrt::Windows::Services::Maps::Guidance::IGuidanceRoute; };
    template <> struct default_interface<winrt::Windows::Services::Maps::Guidance::GuidanceTelemetryCollector>{ using type = winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector; };
    template <> struct default_interface<winrt::Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs>{ using type = winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs; };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AudioNotification(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AudioFilePaths(void**) noexcept = 0;
            virtual int32_t __stdcall get_AudioText(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_LaneMarkers(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsOnRoute(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_StartLocation(void**) noexcept = 0;
            virtual int32_t __stdcall get_DistanceFromRouteStart(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DistanceFromPreviousManeuver(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DepartureRoadName(void**) noexcept = 0;
            virtual int32_t __stdcall get_NextRoadName(void**) noexcept = 0;
            virtual int32_t __stdcall get_DepartureShortRoadName(void**) noexcept = 0;
            virtual int32_t __stdcall get_NextShortRoadName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Kind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_StartAngle(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_EndAngle(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_RoadSignpost(void**) noexcept = 0;
            virtual int32_t __stdcall get_InstructionText(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Location(void**) noexcept = 0;
            virtual int32_t __stdcall get_CurrentHeading(double*) noexcept = 0;
            virtual int32_t __stdcall get_CurrentSpeed(double*) noexcept = 0;
            virtual int32_t __stdcall get_IsOnStreet(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Road(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall StartNavigating(void*) noexcept = 0;
            virtual int32_t __stdcall StartSimulating(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall StartTracking() noexcept = 0;
            virtual int32_t __stdcall Pause() noexcept = 0;
            virtual int32_t __stdcall Resume() noexcept = 0;
            virtual int32_t __stdcall Stop() noexcept = 0;
            virtual int32_t __stdcall RepeatLastAudioNotification() noexcept = 0;
            virtual int32_t __stdcall get_AudioMeasurementSystem(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_AudioMeasurementSystem(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_AudioNotifications(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_AudioNotifications(uint32_t) noexcept = 0;
            virtual int32_t __stdcall add_GuidanceUpdated(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_GuidanceUpdated(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_DestinationReached(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_DestinationReached(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Rerouting(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Rerouting(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Rerouted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Rerouted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_RerouteFailed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_RerouteFailed(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_UserLocationLost(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_UserLocationLost(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_UserLocationRestored(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_UserLocationRestored(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall SetGuidanceVoice(int32_t, void*) noexcept = 0;
            virtual int32_t __stdcall UpdateUserLocation(void*) noexcept = 0;
            virtual int32_t __stdcall UpdateUserLocationWithPositionOverride(void*, struct struct_Windows_Devices_Geolocation_BasicGeoposition) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_AudioNotificationRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AudioNotificationRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_IsGuidanceAudioMuted(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsGuidanceAudioMuted(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrent(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UseAppProvidedVoice(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Route(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RoadName(void**) noexcept = 0;
            virtual int32_t __stdcall get_ShortRoadName(void**) noexcept = 0;
            virtual int32_t __stdcall get_SpeedLimit(double*) noexcept = 0;
            virtual int32_t __stdcall get_TravelTime(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Path(void**) noexcept = 0;
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsHighway(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsTunnel(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsTollRoad(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsScenic(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ExitNumber(void**) noexcept = 0;
            virtual int32_t __stdcall get_Exit(void**) noexcept = 0;
            virtual int32_t __stdcall get_BackgroundColor(struct struct_Windows_UI_Color*) noexcept = 0;
            virtual int32_t __stdcall get_ForegroundColor(struct struct_Windows_UI_Color*) noexcept = 0;
            virtual int32_t __stdcall get_ExitDirections(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceRoute>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Duration(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Distance(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Maneuvers(void**) noexcept = 0;
            virtual int32_t __stdcall get_BoundingBox(void**) noexcept = 0;
            virtual int32_t __stdcall get_Path(void**) noexcept = 0;
            virtual int32_t __stdcall get_RoadSegments(void**) noexcept = 0;
            virtual int32_t __stdcall ConvertToMapRoute(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CanCreateFromMapRoute(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall TryCreateFromMapRoute(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Enabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Enabled(bool) noexcept = 0;
            virtual int32_t __stdcall ClearLocalData() noexcept = 0;
            virtual int32_t __stdcall get_SpeedTrigger(double*) noexcept = 0;
            virtual int32_t __stdcall put_SpeedTrigger(double) noexcept = 0;
            virtual int32_t __stdcall get_UploadFrequency(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_UploadFrequency(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrent(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Mode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_NextManeuver(void**) noexcept = 0;
            virtual int32_t __stdcall get_NextManeuverDistance(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AfterNextManeuver(void**) noexcept = 0;
            virtual int32_t __stdcall get_AfterNextManeuverDistance(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DistanceToDestination(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ElapsedDistance(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ElapsedTime(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_TimeToDestination(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_RoadName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Route(void**) noexcept = 0;
            virtual int32_t __stdcall get_CurrentLocation(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsNewManeuver(bool*) noexcept = 0;
            virtual int32_t __stdcall get_LaneInfo(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceAudioNotificationRequestedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationKind) AudioNotification() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) AudioFilePaths() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AudioText() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceAudioNotificationRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceLaneInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceLaneMarkers) LaneMarkers() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsOnRoute() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceLaneInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceManeuver
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::Geopoint) StartLocation() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) DistanceFromRouteStart() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) DistanceFromPreviousManeuver() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DepartureRoadName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) NextRoadName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DepartureShortRoadName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) NextShortRoadName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceManeuverKind) Kind() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) StartAngle() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) EndAngle() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceRoadSignpost) RoadSignpost() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) InstructionText() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::Geopoint) Location() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) CurrentHeading() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) CurrentSpeed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsOnStreet() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment) Road() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceNavigator
    {
        WINRT_IMPL_AUTO(void) StartNavigating(winrt::Windows::Services::Maps::Guidance::GuidanceRoute const& route) const;
        WINRT_IMPL_AUTO(void) StartSimulating(winrt::Windows::Services::Maps::Guidance::GuidanceRoute const& route, int32_t speedInMetersPerSecond) const;
        WINRT_IMPL_AUTO(void) StartTracking() const;
        WINRT_IMPL_AUTO(void) Pause() const;
        WINRT_IMPL_AUTO(void) Resume() const;
        WINRT_IMPL_AUTO(void) Stop() const;
        WINRT_IMPL_AUTO(void) RepeatLastAudioNotification() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem) AudioMeasurementSystem() const;
        WINRT_IMPL_AUTO(void) AudioMeasurementSystem(winrt::Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotifications) AudioNotifications() const;
        WINRT_IMPL_AUTO(void) AudioNotifications(winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotifications const& value) const;
        WINRT_IMPL_AUTO(winrt::event_token) GuidanceUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> const& handler) const;
        using GuidanceUpdated_revoker = impl::event_revoker<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator, &impl::abi_t<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>::remove_GuidanceUpdated>;
        [[nodiscard]] GuidanceUpdated_revoker GuidanceUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) GuidanceUpdated(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) DestinationReached(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using DestinationReached_revoker = impl::event_revoker<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator, &impl::abi_t<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>::remove_DestinationReached>;
        [[nodiscard]] DestinationReached_revoker DestinationReached(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) DestinationReached(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Rerouting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using Rerouting_revoker = impl::event_revoker<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator, &impl::abi_t<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>::remove_Rerouting>;
        [[nodiscard]] Rerouting_revoker Rerouting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) Rerouting(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Rerouted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> const& handler) const;
        using Rerouted_revoker = impl::event_revoker<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator, &impl::abi_t<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>::remove_Rerouted>;
        [[nodiscard]] Rerouted_revoker Rerouted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Rerouted(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) RerouteFailed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using RerouteFailed_revoker = impl::event_revoker<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator, &impl::abi_t<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>::remove_RerouteFailed>;
        [[nodiscard]] RerouteFailed_revoker RerouteFailed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) RerouteFailed(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) UserLocationLost(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using UserLocationLost_revoker = impl::event_revoker<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator, &impl::abi_t<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>::remove_UserLocationLost>;
        [[nodiscard]] UserLocationLost_revoker UserLocationLost(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) UserLocationLost(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) UserLocationRestored(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using UserLocationRestored_revoker = impl::event_revoker<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator, &impl::abi_t<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>::remove_UserLocationRestored>;
        [[nodiscard]] UserLocationRestored_revoker UserLocationRestored(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) UserLocationRestored(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(void) SetGuidanceVoice(int32_t voiceId, param::hstring const& voiceFolder) const;
        WINRT_IMPL_AUTO(void) UpdateUserLocation(winrt::Windows::Devices::Geolocation::Geocoordinate const& userLocation) const;
        WINRT_IMPL_AUTO(void) UpdateUserLocation(winrt::Windows::Devices::Geolocation::Geocoordinate const& userLocation, winrt::Windows::Devices::Geolocation::BasicGeoposition const& positionOverride) const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2
    {
        WINRT_IMPL_AUTO(winrt::event_token) AudioNotificationRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> const& value) const;
        using AudioNotificationRequested_revoker = impl::event_revoker<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2, &impl::abi_t<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2>::remove_AudioNotificationRequested>;
        [[nodiscard]] AudioNotificationRequested_revoker AudioNotificationRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> const& value) const;
        WINRT_IMPL_AUTO(void) AudioNotificationRequested(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsGuidanceAudioMuted() const;
        WINRT_IMPL_AUTO(void) IsGuidanceAudioMuted(bool value) const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceNavigatorStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceNavigator) GetCurrent() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceNavigatorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceNavigatorStatics2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) UseAppProvidedVoice() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceNavigatorStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceReroutedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceRoute) Route() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceReroutedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) RoadName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ShortRoadName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) SpeedLimit() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) TravelTime() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::Geopath) Path() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsHighway() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsTunnel() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsTollRoad() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsScenic() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment2>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment2<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ExitNumber() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Exit() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Color) BackgroundColor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Color) ForegroundColor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) ExitDirections() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceRoute
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) Duration() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Distance() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver>) Maneuvers() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::GeoboundingBox) BoundingBox() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::Geopath) Path() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment>) RoadSegments() const;
        WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::MapRoute) ConvertToMapRoute() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceRoute>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceRouteStatics
    {
        WINRT_IMPL_AUTO(bool) CanCreateFromMapRoute(winrt::Windows::Services::Maps::MapRoute const& mapRoute) const;
        WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceRoute) TryCreateFromMapRoute(winrt::Windows::Services::Maps::MapRoute const& mapRoute) const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceRouteStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Enabled() const;
        WINRT_IMPL_AUTO(void) Enabled(bool value) const;
        WINRT_IMPL_AUTO(void) ClearLocalData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) SpeedTrigger() const;
        WINRT_IMPL_AUTO(void) SpeedTrigger(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) UploadFrequency() const;
        WINRT_IMPL_AUTO(void) UploadFrequency(int32_t value) const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollectorStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceTelemetryCollector) GetCurrent() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollectorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceMode) Mode() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceManeuver) NextManeuver() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) NextManeuverDistance() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceManeuver) AfterNextManeuver() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) AfterNextManeuverDistance() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) DistanceToDestination() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) ElapsedDistance() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) ElapsedTime() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) TimeToDestination() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) RoadName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceRoute) Route() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate) CurrentLocation() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsNewManeuver() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceLaneInfo>) LaneInfo() const;
    };
    template <> struct consume<winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs>
    {
        template <typename D> using type = consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>;
    };
}
#endif
