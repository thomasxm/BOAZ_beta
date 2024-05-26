// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_StartScreen_0_H
#define WINRT_Windows_UI_StartScreen_0_H
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Core
{
    struct AppListEntry;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename T> struct __declspec(empty_bases) IReference;
    struct Point;
    struct Rect;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Perception::Spatial
{
    struct SpatialBoundingBox;
}
WINRT_EXPORT namespace winrt::Windows::System
{
    struct User;
}
WINRT_EXPORT namespace winrt::Windows::UI
{
    struct Color;
}
WINRT_EXPORT namespace winrt::Windows::UI::Popups
{
    enum class Placement : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::UI::StartScreen
{
    enum class ForegroundText : int32_t
    {
        Dark = 0,
        Light = 1,
    };
    enum class JumpListItemKind : int32_t
    {
        Arguments = 0,
        Separator = 1,
    };
    enum class JumpListSystemGroupKind : int32_t
    {
        None = 0,
        Frequent = 1,
        Recent = 2,
    };
    enum class TileMixedRealityModelActivationBehavior : int32_t
    {
        Default = 0,
        None = 1,
    };
    enum class TileOptions : uint32_t
    {
        None = 0,
        ShowNameOnLogo = 0x1,
        ShowNameOnWideLogo = 0x2,
        CopyOnDeployment = 0x4,
    };
    enum class TileSize : int32_t
    {
        Default = 0,
        Square30x30 = 1,
        Square70x70 = 2,
        Square150x150 = 3,
        Wide310x150 = 4,
        Square310x310 = 5,
        Square71x71 = 6,
        Square44x44 = 7,
    };
    struct IJumpList;
    struct IJumpListItem;
    struct IJumpListItemStatics;
    struct IJumpListStatics;
    struct ISecondaryTile;
    struct ISecondaryTile2;
    struct ISecondaryTileFactory;
    struct ISecondaryTileFactory2;
    struct ISecondaryTileStatics;
    struct ISecondaryTileVisualElements;
    struct ISecondaryTileVisualElements2;
    struct ISecondaryTileVisualElements3;
    struct ISecondaryTileVisualElements4;
    struct IStartScreenManager;
    struct IStartScreenManager2;
    struct IStartScreenManagerStatics;
    struct ITileMixedRealityModel;
    struct ITileMixedRealityModel2;
    struct IVisualElementsRequest;
    struct IVisualElementsRequestDeferral;
    struct IVisualElementsRequestedEventArgs;
    struct JumpList;
    struct JumpListItem;
    struct SecondaryTile;
    struct SecondaryTileVisualElements;
    struct StartScreenManager;
    struct TileMixedRealityModel;
    struct VisualElementsRequest;
    struct VisualElementsRequestDeferral;
    struct VisualElementsRequestedEventArgs;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::UI::StartScreen::IJumpList>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::IJumpListItem>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::IJumpListItemStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::IJumpListStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ISecondaryTile>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ISecondaryTile2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ISecondaryTileFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ISecondaryTileFactory2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ISecondaryTileStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::IStartScreenManager>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::IStartScreenManager2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::IStartScreenManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ITileMixedRealityModel>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ITileMixedRealityModel2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::IVisualElementsRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::IVisualElementsRequestDeferral>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::IVisualElementsRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::JumpList>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::JumpListItem>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::SecondaryTile>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::SecondaryTileVisualElements>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::StartScreenManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::TileMixedRealityModel>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::VisualElementsRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::VisualElementsRequestDeferral>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::VisualElementsRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::ForegroundText>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::JumpListItemKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::JumpListSystemGroupKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::TileOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::StartScreen::TileSize>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::JumpList> = L"Windows.UI.StartScreen.JumpList";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::JumpListItem> = L"Windows.UI.StartScreen.JumpListItem";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::SecondaryTile> = L"Windows.UI.StartScreen.SecondaryTile";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::SecondaryTileVisualElements> = L"Windows.UI.StartScreen.SecondaryTileVisualElements";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::StartScreenManager> = L"Windows.UI.StartScreen.StartScreenManager";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::TileMixedRealityModel> = L"Windows.UI.StartScreen.TileMixedRealityModel";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::VisualElementsRequest> = L"Windows.UI.StartScreen.VisualElementsRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::VisualElementsRequestDeferral> = L"Windows.UI.StartScreen.VisualElementsRequestDeferral";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::VisualElementsRequestedEventArgs> = L"Windows.UI.StartScreen.VisualElementsRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ForegroundText> = L"Windows.UI.StartScreen.ForegroundText";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::JumpListItemKind> = L"Windows.UI.StartScreen.JumpListItemKind";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::JumpListSystemGroupKind> = L"Windows.UI.StartScreen.JumpListSystemGroupKind";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior> = L"Windows.UI.StartScreen.TileMixedRealityModelActivationBehavior";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::TileOptions> = L"Windows.UI.StartScreen.TileOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::TileSize> = L"Windows.UI.StartScreen.TileSize";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::IJumpList> = L"Windows.UI.StartScreen.IJumpList";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::IJumpListItem> = L"Windows.UI.StartScreen.IJumpListItem";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::IJumpListItemStatics> = L"Windows.UI.StartScreen.IJumpListItemStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::IJumpListStatics> = L"Windows.UI.StartScreen.IJumpListStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ISecondaryTile> = L"Windows.UI.StartScreen.ISecondaryTile";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ISecondaryTile2> = L"Windows.UI.StartScreen.ISecondaryTile2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ISecondaryTileFactory> = L"Windows.UI.StartScreen.ISecondaryTileFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ISecondaryTileFactory2> = L"Windows.UI.StartScreen.ISecondaryTileFactory2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ISecondaryTileStatics> = L"Windows.UI.StartScreen.ISecondaryTileStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements> = L"Windows.UI.StartScreen.ISecondaryTileVisualElements";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements2> = L"Windows.UI.StartScreen.ISecondaryTileVisualElements2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements3> = L"Windows.UI.StartScreen.ISecondaryTileVisualElements3";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements4> = L"Windows.UI.StartScreen.ISecondaryTileVisualElements4";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::IStartScreenManager> = L"Windows.UI.StartScreen.IStartScreenManager";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::IStartScreenManager2> = L"Windows.UI.StartScreen.IStartScreenManager2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::IStartScreenManagerStatics> = L"Windows.UI.StartScreen.IStartScreenManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ITileMixedRealityModel> = L"Windows.UI.StartScreen.ITileMixedRealityModel";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::ITileMixedRealityModel2> = L"Windows.UI.StartScreen.ITileMixedRealityModel2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::IVisualElementsRequest> = L"Windows.UI.StartScreen.IVisualElementsRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::IVisualElementsRequestDeferral> = L"Windows.UI.StartScreen.IVisualElementsRequestDeferral";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::StartScreen::IVisualElementsRequestedEventArgs> = L"Windows.UI.StartScreen.IVisualElementsRequestedEventArgs";
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::IJumpList>{ 0xB0234C3E,0xCD6F,0x4CB6,{ 0xA6,0x11,0x61,0xFD,0x50,0x5F,0x3E,0xD1 } }; // B0234C3E-CD6F-4CB6-A611-61FD505F3ED1
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::IJumpListItem>{ 0x7ADB6717,0x8B5D,0x4820,{ 0x99,0x5B,0x9B,0x41,0x8D,0xBE,0x48,0xB0 } }; // 7ADB6717-8B5D-4820-995B-9B418DBE48B0
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::IJumpListItemStatics>{ 0xF1BFC4E8,0xC7AA,0x49CB,{ 0x8D,0xDE,0xEC,0xFC,0xCD,0x7A,0xD7,0xE4 } }; // F1BFC4E8-C7AA-49CB-8DDE-ECFCCD7AD7E4
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::IJumpListStatics>{ 0xA7E0C681,0xE67E,0x4B74,{ 0x82,0x50,0x3F,0x32,0x2C,0x4D,0x92,0xC3 } }; // A7E0C681-E67E-4B74-8250-3F322C4D92C3
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::ISecondaryTile>{ 0x9E9E51E0,0x2BB5,0x4BC0,{ 0xBB,0x8D,0x42,0xB2,0x3A,0xBC,0xC8,0x8D } }; // 9E9E51E0-2BB5-4BC0-BB8D-42B23ABCC88D
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::ISecondaryTile2>{ 0xB2F6CC35,0x3250,0x4990,{ 0x92,0x3C,0x29,0x4A,0xB4,0xB6,0x94,0xDD } }; // B2F6CC35-3250-4990-923C-294AB4B694DD
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::ISecondaryTileFactory>{ 0x57F52CA0,0x51BC,0x4ABF,{ 0x8E,0xBF,0x62,0x7A,0x03,0x98,0xB0,0x5A } }; // 57F52CA0-51BC-4ABF-8EBF-627A0398B05A
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::ISecondaryTileFactory2>{ 0x274B8A3B,0x522D,0x448E,{ 0x9E,0xB2,0xD0,0x67,0x2A,0xB3,0x45,0xC8 } }; // 274B8A3B-522D-448E-9EB2-D0672AB345C8
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::ISecondaryTileStatics>{ 0x99908DAE,0xD051,0x4676,{ 0x87,0xFE,0x9E,0xC2,0x42,0xD8,0x3C,0x74 } }; // 99908DAE-D051-4676-87FE-9EC242D83C74
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements>{ 0x1D8DF333,0x815E,0x413F,{ 0x9F,0x50,0xA8,0x1D,0xA7,0x0A,0x96,0xB2 } }; // 1D8DF333-815E-413F-9F50-A81DA70A96B2
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements2>{ 0xFD2E31D0,0x57DC,0x4794,{ 0x8E,0xCF,0x56,0x82,0xF5,0xF3,0xE6,0xEF } }; // FD2E31D0-57DC-4794-8ECF-5682F5F3E6EF
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements3>{ 0x56B55AD6,0xD15C,0x40F4,{ 0x81,0xE7,0x57,0xFF,0xD8,0xF8,0xA4,0xE9 } }; // 56B55AD6-D15C-40F4-81E7-57FFD8F8A4E9
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements4>{ 0x66566117,0xB544,0x40D2,{ 0x8D,0x12,0x74,0xD4,0xEC,0x24,0xD0,0x4C } }; // 66566117-B544-40D2-8D12-74D4EC24D04C
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::IStartScreenManager>{ 0x4A1DCBCB,0x26E9,0x4EB4,{ 0x89,0x33,0x85,0x9E,0xB6,0xEC,0xDB,0x29 } }; // 4A1DCBCB-26E9-4EB4-8933-859EB6ECDB29
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::IStartScreenManager2>{ 0x08A716B6,0x316B,0x4AD9,{ 0xAC,0xB8,0xFE,0x9C,0xF0,0x0B,0xD6,0x08 } }; // 08A716B6-316B-4AD9-ACB8-FE9CF00BD608
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::IStartScreenManagerStatics>{ 0x7865EF0F,0xB585,0x464E,{ 0x89,0x93,0x34,0xE8,0xF8,0x73,0x8D,0x48 } }; // 7865EF0F-B585-464E-8993-34E8F8738D48
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::ITileMixedRealityModel>{ 0xB0764E5B,0x887D,0x4242,{ 0x9A,0x19,0x3D,0x0A,0x4E,0xA7,0x80,0x31 } }; // B0764E5B-887D-4242-9A19-3D0A4EA78031
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::ITileMixedRealityModel2>{ 0x439470B2,0xD7C5,0x410B,{ 0x83,0x19,0x94,0x86,0xA2,0x7B,0x6C,0x67 } }; // 439470B2-D7C5-410B-8319-9486A27B6C67
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::IVisualElementsRequest>{ 0xC138333A,0x9308,0x4072,{ 0x88,0xCC,0xD0,0x68,0xDB,0x34,0x7C,0x68 } }; // C138333A-9308-4072-88CC-D068DB347C68
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::IVisualElementsRequestDeferral>{ 0xA1656EB0,0x0126,0x4357,{ 0x82,0x04,0xBD,0x82,0xBB,0x2A,0x04,0x6D } }; // A1656EB0-0126-4357-8204-BD82BB2A046D
    template <> inline constexpr guid guid_v<winrt::Windows::UI::StartScreen::IVisualElementsRequestedEventArgs>{ 0x7B6FC982,0x3A0D,0x4ECE,{ 0xAF,0x96,0xCD,0x17,0xE1,0xB0,0x0B,0x2D } }; // 7B6FC982-3A0D-4ECE-AF96-CD17E1B00B2D
    template <> struct default_interface<winrt::Windows::UI::StartScreen::JumpList>{ using type = winrt::Windows::UI::StartScreen::IJumpList; };
    template <> struct default_interface<winrt::Windows::UI::StartScreen::JumpListItem>{ using type = winrt::Windows::UI::StartScreen::IJumpListItem; };
    template <> struct default_interface<winrt::Windows::UI::StartScreen::SecondaryTile>{ using type = winrt::Windows::UI::StartScreen::ISecondaryTile; };
    template <> struct default_interface<winrt::Windows::UI::StartScreen::SecondaryTileVisualElements>{ using type = winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements; };
    template <> struct default_interface<winrt::Windows::UI::StartScreen::StartScreenManager>{ using type = winrt::Windows::UI::StartScreen::IStartScreenManager; };
    template <> struct default_interface<winrt::Windows::UI::StartScreen::TileMixedRealityModel>{ using type = winrt::Windows::UI::StartScreen::ITileMixedRealityModel; };
    template <> struct default_interface<winrt::Windows::UI::StartScreen::VisualElementsRequest>{ using type = winrt::Windows::UI::StartScreen::IVisualElementsRequest; };
    template <> struct default_interface<winrt::Windows::UI::StartScreen::VisualElementsRequestDeferral>{ using type = winrt::Windows::UI::StartScreen::IVisualElementsRequestDeferral; };
    template <> struct default_interface<winrt::Windows::UI::StartScreen::VisualElementsRequestedEventArgs>{ using type = winrt::Windows::UI::StartScreen::IVisualElementsRequestedEventArgs; };
    template <> struct abi<winrt::Windows::UI::StartScreen::IJumpList>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Items(void**) noexcept = 0;
            virtual int32_t __stdcall get_SystemGroupKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_SystemGroupKind(int32_t) noexcept = 0;
            virtual int32_t __stdcall SaveAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::IJumpListItem>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Kind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Arguments(void**) noexcept = 0;
            virtual int32_t __stdcall get_RemovedByUser(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Description(void**) noexcept = 0;
            virtual int32_t __stdcall put_Description(void*) noexcept = 0;
            virtual int32_t __stdcall get_DisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayName(void*) noexcept = 0;
            virtual int32_t __stdcall get_GroupName(void**) noexcept = 0;
            virtual int32_t __stdcall put_GroupName(void*) noexcept = 0;
            virtual int32_t __stdcall get_Logo(void**) noexcept = 0;
            virtual int32_t __stdcall put_Logo(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::IJumpListItemStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateWithArguments(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateSeparator(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::IJumpListStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall LoadCurrentAsync(void**) noexcept = 0;
            virtual int32_t __stdcall IsSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::ISecondaryTile>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_TileId(void*) noexcept = 0;
            virtual int32_t __stdcall get_TileId(void**) noexcept = 0;
            virtual int32_t __stdcall put_Arguments(void*) noexcept = 0;
            virtual int32_t __stdcall get_Arguments(void**) noexcept = 0;
            virtual int32_t __stdcall put_ShortName(void*) noexcept = 0;
            virtual int32_t __stdcall get_ShortName(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayName(void*) noexcept = 0;
            virtual int32_t __stdcall get_DisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall put_Logo(void*) noexcept = 0;
            virtual int32_t __stdcall get_Logo(void**) noexcept = 0;
            virtual int32_t __stdcall put_SmallLogo(void*) noexcept = 0;
            virtual int32_t __stdcall get_SmallLogo(void**) noexcept = 0;
            virtual int32_t __stdcall put_WideLogo(void*) noexcept = 0;
            virtual int32_t __stdcall get_WideLogo(void**) noexcept = 0;
            virtual int32_t __stdcall put_LockScreenBadgeLogo(void*) noexcept = 0;
            virtual int32_t __stdcall get_LockScreenBadgeLogo(void**) noexcept = 0;
            virtual int32_t __stdcall put_LockScreenDisplayBadgeAndTileText(bool) noexcept = 0;
            virtual int32_t __stdcall get_LockScreenDisplayBadgeAndTileText(bool*) noexcept = 0;
            virtual int32_t __stdcall put_TileOptions(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_TileOptions(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ForegroundText(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_ForegroundText(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_BackgroundColor(struct struct_Windows_UI_Color) noexcept = 0;
            virtual int32_t __stdcall get_BackgroundColor(struct struct_Windows_UI_Color*) noexcept = 0;
            virtual int32_t __stdcall RequestCreateAsync(void**) noexcept = 0;
            virtual int32_t __stdcall RequestCreateAsyncWithPoint(winrt::Windows::Foundation::Point, void**) noexcept = 0;
            virtual int32_t __stdcall RequestCreateAsyncWithRect(winrt::Windows::Foundation::Rect, void**) noexcept = 0;
            virtual int32_t __stdcall RequestCreateAsyncWithRectAndPlacement(winrt::Windows::Foundation::Rect, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall RequestDeleteAsync(void**) noexcept = 0;
            virtual int32_t __stdcall RequestDeleteAsyncWithPoint(winrt::Windows::Foundation::Point, void**) noexcept = 0;
            virtual int32_t __stdcall RequestDeleteAsyncWithRect(winrt::Windows::Foundation::Rect, void**) noexcept = 0;
            virtual int32_t __stdcall RequestDeleteAsyncWithRectAndPlacement(winrt::Windows::Foundation::Rect, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::ISecondaryTile2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_PhoneticName(void*) noexcept = 0;
            virtual int32_t __stdcall get_PhoneticName(void**) noexcept = 0;
            virtual int32_t __stdcall get_VisualElements(void**) noexcept = 0;
            virtual int32_t __stdcall put_RoamingEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_RoamingEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall add_VisualElementsRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_VisualElementsRequested(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::ISecondaryTileFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateTile(void*, void*, void*, void*, uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateWideTile(void*, void*, void*, void*, uint32_t, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateWithId(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::ISecondaryTileFactory2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateMinimalTile(void*, void*, void*, void*, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::ISecondaryTileStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Exists(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall FindAllAsync(void**) noexcept = 0;
            virtual int32_t __stdcall FindAllForApplicationAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindAllForPackageAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_Square30x30Logo(void*) noexcept = 0;
            virtual int32_t __stdcall get_Square30x30Logo(void**) noexcept = 0;
            virtual int32_t __stdcall put_Square70x70Logo(void*) noexcept = 0;
            virtual int32_t __stdcall get_Square70x70Logo(void**) noexcept = 0;
            virtual int32_t __stdcall put_Square150x150Logo(void*) noexcept = 0;
            virtual int32_t __stdcall get_Square150x150Logo(void**) noexcept = 0;
            virtual int32_t __stdcall put_Wide310x150Logo(void*) noexcept = 0;
            virtual int32_t __stdcall get_Wide310x150Logo(void**) noexcept = 0;
            virtual int32_t __stdcall put_Square310x310Logo(void*) noexcept = 0;
            virtual int32_t __stdcall get_Square310x310Logo(void**) noexcept = 0;
            virtual int32_t __stdcall put_ForegroundText(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_ForegroundText(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_BackgroundColor(struct struct_Windows_UI_Color) noexcept = 0;
            virtual int32_t __stdcall get_BackgroundColor(struct struct_Windows_UI_Color*) noexcept = 0;
            virtual int32_t __stdcall put_ShowNameOnSquare150x150Logo(bool) noexcept = 0;
            virtual int32_t __stdcall get_ShowNameOnSquare150x150Logo(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ShowNameOnWide310x150Logo(bool) noexcept = 0;
            virtual int32_t __stdcall get_ShowNameOnWide310x150Logo(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ShowNameOnSquare310x310Logo(bool) noexcept = 0;
            virtual int32_t __stdcall get_ShowNameOnSquare310x310Logo(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_Square71x71Logo(void*) noexcept = 0;
            virtual int32_t __stdcall get_Square71x71Logo(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_Square44x44Logo(void*) noexcept = 0;
            virtual int32_t __stdcall get_Square44x44Logo(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_MixedRealityModel(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::IStartScreenManager>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_User(void**) noexcept = 0;
            virtual int32_t __stdcall SupportsAppListEntry(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall ContainsAppListEntryAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAddAppListEntryAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::IStartScreenManager2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ContainsSecondaryTileAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall TryRemoveSecondaryTileAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::IStartScreenManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
            virtual int32_t __stdcall GetForUser(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::ITileMixedRealityModel>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_Uri(void*) noexcept = 0;
            virtual int32_t __stdcall get_Uri(void**) noexcept = 0;
            virtual int32_t __stdcall put_BoundingBox(void*) noexcept = 0;
            virtual int32_t __stdcall get_BoundingBox(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::ITileMixedRealityModel2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ActivationBehavior(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_ActivationBehavior(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::IVisualElementsRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_VisualElements(void**) noexcept = 0;
            virtual int32_t __stdcall get_AlternateVisualElements(void**) noexcept = 0;
            virtual int32_t __stdcall get_Deadline(int64_t*) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::IVisualElementsRequestDeferral>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Complete() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::StartScreen::IVisualElementsRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_IJumpList
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::StartScreen::JumpListItem>) Items() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::JumpListSystemGroupKind) SystemGroupKind() const;
        WINRT_IMPL_AUTO(void) SystemGroupKind(winrt::Windows::UI::StartScreen::JumpListSystemGroupKind const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SaveAsync() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::IJumpList>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_IJumpList<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_IJumpListItem
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::JumpListItemKind) Kind() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Arguments() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) RemovedByUser() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Description() const;
        WINRT_IMPL_AUTO(void) Description(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayName() const;
        WINRT_IMPL_AUTO(void) DisplayName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) GroupName() const;
        WINRT_IMPL_AUTO(void) GroupName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Logo() const;
        WINRT_IMPL_AUTO(void) Logo(winrt::Windows::Foundation::Uri const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::IJumpListItem>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_IJumpListItem<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_IJumpListItemStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::JumpListItem) CreateWithArguments(param::hstring const& arguments, param::hstring const& displayName) const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::JumpListItem) CreateSeparator() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::IJumpListItemStatics>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_IJumpListItemStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_IJumpListStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::StartScreen::JumpList>) LoadCurrentAsync() const;
        WINRT_IMPL_AUTO(bool) IsSupported() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::IJumpListStatics>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_IJumpListStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_ISecondaryTile
    {
        WINRT_IMPL_AUTO(void) TileId(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TileId() const;
        WINRT_IMPL_AUTO(void) Arguments(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Arguments() const;
        WINRT_IMPL_AUTO(void) ShortName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ShortName() const;
        WINRT_IMPL_AUTO(void) DisplayName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayName() const;
        WINRT_IMPL_AUTO(void) Logo(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Logo() const;
        WINRT_IMPL_AUTO(void) SmallLogo(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) SmallLogo() const;
        WINRT_IMPL_AUTO(void) WideLogo(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) WideLogo() const;
        WINRT_IMPL_AUTO(void) LockScreenBadgeLogo(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) LockScreenBadgeLogo() const;
        WINRT_IMPL_AUTO(void) LockScreenDisplayBadgeAndTileText(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) LockScreenDisplayBadgeAndTileText() const;
        WINRT_IMPL_AUTO(void) TileOptions(winrt::Windows::UI::StartScreen::TileOptions const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::TileOptions) TileOptions() const;
        WINRT_IMPL_AUTO(void) ForegroundText(winrt::Windows::UI::StartScreen::ForegroundText const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::ForegroundText) ForegroundText() const;
        WINRT_IMPL_AUTO(void) BackgroundColor(winrt::Windows::UI::Color const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Color) BackgroundColor() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestCreateAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestCreateAsync(winrt::Windows::Foundation::Point const& invocationPoint) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestCreateForSelectionAsync(winrt::Windows::Foundation::Rect const& selection) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestCreateForSelectionAsync(winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestDeleteAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestDeleteAsync(winrt::Windows::Foundation::Point const& invocationPoint) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestDeleteForSelectionAsync(winrt::Windows::Foundation::Rect const& selection) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestDeleteForSelectionAsync(winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) UpdateAsync() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::ISecondaryTile>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_ISecondaryTile<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_ISecondaryTile2
    {
        WINRT_IMPL_AUTO(void) PhoneticName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PhoneticName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::SecondaryTileVisualElements) VisualElements() const;
        WINRT_IMPL_AUTO(void) RoamingEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) RoamingEnabled() const;
        WINRT_IMPL_AUTO(winrt::event_token) VisualElementsRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::StartScreen::SecondaryTile, winrt::Windows::UI::StartScreen::VisualElementsRequestedEventArgs> const& handler) const;
        using VisualElementsRequested_revoker = impl::event_revoker<winrt::Windows::UI::StartScreen::ISecondaryTile2, &impl::abi_t<winrt::Windows::UI::StartScreen::ISecondaryTile2>::remove_VisualElementsRequested>;
        [[nodiscard]] VisualElementsRequested_revoker VisualElementsRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::StartScreen::SecondaryTile, winrt::Windows::UI::StartScreen::VisualElementsRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) VisualElementsRequested(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::ISecondaryTile2>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_ISecondaryTile2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_ISecondaryTileFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::SecondaryTile) CreateTile(param::hstring const& tileId, param::hstring const& shortName, param::hstring const& displayName, param::hstring const& arguments, winrt::Windows::UI::StartScreen::TileOptions const& tileOptions, winrt::Windows::Foundation::Uri const& logoReference) const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::SecondaryTile) CreateWideTile(param::hstring const& tileId, param::hstring const& shortName, param::hstring const& displayName, param::hstring const& arguments, winrt::Windows::UI::StartScreen::TileOptions const& tileOptions, winrt::Windows::Foundation::Uri const& logoReference, winrt::Windows::Foundation::Uri const& wideLogoReference) const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::SecondaryTile) CreateWithId(param::hstring const& tileId) const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::ISecondaryTileFactory>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_ISecondaryTileFactory<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_ISecondaryTileFactory2
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::SecondaryTile) CreateMinimalTile(param::hstring const& tileId, param::hstring const& displayName, param::hstring const& arguments, winrt::Windows::Foundation::Uri const& square150x150Logo, winrt::Windows::UI::StartScreen::TileSize const& desiredSize) const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::ISecondaryTileFactory2>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_ISecondaryTileFactory2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_ISecondaryTileStatics
    {
        WINRT_IMPL_AUTO(bool) Exists(param::hstring const& tileId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::StartScreen::SecondaryTile>>) FindAllAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::StartScreen::SecondaryTile>>) FindAllAsync(param::hstring const& applicationId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::StartScreen::SecondaryTile>>) FindAllForPackageAsync() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::ISecondaryTileStatics>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_ISecondaryTileStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_ISecondaryTileVisualElements
    {
        WINRT_IMPL_AUTO(void) Square30x30Logo(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Square30x30Logo() const;
        WINRT_IMPL_AUTO(void) Square70x70Logo(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Square70x70Logo() const;
        WINRT_IMPL_AUTO(void) Square150x150Logo(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Square150x150Logo() const;
        WINRT_IMPL_AUTO(void) Wide310x150Logo(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Wide310x150Logo() const;
        WINRT_IMPL_AUTO(void) Square310x310Logo(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Square310x310Logo() const;
        WINRT_IMPL_AUTO(void) ForegroundText(winrt::Windows::UI::StartScreen::ForegroundText const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::ForegroundText) ForegroundText() const;
        WINRT_IMPL_AUTO(void) BackgroundColor(winrt::Windows::UI::Color const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Color) BackgroundColor() const;
        WINRT_IMPL_AUTO(void) ShowNameOnSquare150x150Logo(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ShowNameOnSquare150x150Logo() const;
        WINRT_IMPL_AUTO(void) ShowNameOnWide310x150Logo(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ShowNameOnWide310x150Logo() const;
        WINRT_IMPL_AUTO(void) ShowNameOnSquare310x310Logo(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ShowNameOnSquare310x310Logo() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_ISecondaryTileVisualElements2
    {
        WINRT_IMPL_AUTO(void) Square71x71Logo(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Square71x71Logo() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements2>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_ISecondaryTileVisualElements2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_ISecondaryTileVisualElements3
    {
        WINRT_IMPL_AUTO(void) Square44x44Logo(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Square44x44Logo() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements3>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_ISecondaryTileVisualElements3<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_ISecondaryTileVisualElements4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::TileMixedRealityModel) MixedRealityModel() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements4>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_ISecondaryTileVisualElements4<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_IStartScreenManager
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::User) User() const;
        WINRT_IMPL_AUTO(bool) SupportsAppListEntry(winrt::Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) ContainsAppListEntryAsync(winrt::Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestAddAppListEntryAsync(winrt::Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::IStartScreenManager>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_IStartScreenManager<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_IStartScreenManager2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) ContainsSecondaryTileAsync(param::hstring const& tileId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryRemoveSecondaryTileAsync(param::hstring const& tileId) const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::IStartScreenManager2>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_IStartScreenManager2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_IStartScreenManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::StartScreenManager) GetDefault() const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::StartScreenManager) GetForUser(winrt::Windows::System::User const& user) const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::IStartScreenManagerStatics>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_IStartScreenManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_ITileMixedRealityModel
    {
        WINRT_IMPL_AUTO(void) Uri(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Uri() const;
        WINRT_IMPL_AUTO(void) BoundingBox(winrt::Windows::Foundation::IReference<winrt::Windows::Perception::Spatial::SpatialBoundingBox> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Perception::Spatial::SpatialBoundingBox>) BoundingBox() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::ITileMixedRealityModel>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_ITileMixedRealityModel<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_ITileMixedRealityModel2
    {
        WINRT_IMPL_AUTO(void) ActivationBehavior(winrt::Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior) ActivationBehavior() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::ITileMixedRealityModel2>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_ITileMixedRealityModel2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_IVisualElementsRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::SecondaryTileVisualElements) VisualElements() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::StartScreen::SecondaryTileVisualElements>) AlternateVisualElements() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Deadline() const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::VisualElementsRequestDeferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::IVisualElementsRequest>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_IVisualElementsRequest<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_IVisualElementsRequestDeferral
    {
        WINRT_IMPL_AUTO(void) Complete() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::IVisualElementsRequestDeferral>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_IVisualElementsRequestDeferral<D>;
    };
    template <typename D>
    struct consume_Windows_UI_StartScreen_IVisualElementsRequestedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::StartScreen::VisualElementsRequest) Request() const;
    };
    template <> struct consume<winrt::Windows::UI::StartScreen::IVisualElementsRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_StartScreen_IVisualElementsRequestedEventArgs<D>;
    };
}
#endif
