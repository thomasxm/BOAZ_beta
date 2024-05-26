// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_StartScreen_1_H
#define WINRT_Windows_UI_StartScreen_1_H
#include "winrt/impl/Windows.UI.StartScreen.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::StartScreen
{
    struct __declspec(empty_bases) IJumpList :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJumpList>
    {
        IJumpList(std::nullptr_t = nullptr) noexcept {}
        IJumpList(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IJumpListItem :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJumpListItem>
    {
        IJumpListItem(std::nullptr_t = nullptr) noexcept {}
        IJumpListItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IJumpListItemStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJumpListItemStatics>
    {
        IJumpListItemStatics(std::nullptr_t = nullptr) noexcept {}
        IJumpListItemStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IJumpListStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJumpListStatics>
    {
        IJumpListStatics(std::nullptr_t = nullptr) noexcept {}
        IJumpListStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryTile :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryTile>
    {
        ISecondaryTile(std::nullptr_t = nullptr) noexcept {}
        ISecondaryTile(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryTile2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryTile2>,
        impl::require<winrt::Windows::UI::StartScreen::ISecondaryTile2, winrt::Windows::UI::StartScreen::ISecondaryTile>
    {
        ISecondaryTile2(std::nullptr_t = nullptr) noexcept {}
        ISecondaryTile2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryTileFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryTileFactory>
    {
        ISecondaryTileFactory(std::nullptr_t = nullptr) noexcept {}
        ISecondaryTileFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryTileFactory2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryTileFactory2>,
        impl::require<winrt::Windows::UI::StartScreen::ISecondaryTileFactory2, winrt::Windows::UI::StartScreen::ISecondaryTileFactory>
    {
        ISecondaryTileFactory2(std::nullptr_t = nullptr) noexcept {}
        ISecondaryTileFactory2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryTileStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryTileStatics>
    {
        ISecondaryTileStatics(std::nullptr_t = nullptr) noexcept {}
        ISecondaryTileStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryTileVisualElements :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryTileVisualElements>
    {
        ISecondaryTileVisualElements(std::nullptr_t = nullptr) noexcept {}
        ISecondaryTileVisualElements(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryTileVisualElements2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryTileVisualElements2>
    {
        ISecondaryTileVisualElements2(std::nullptr_t = nullptr) noexcept {}
        ISecondaryTileVisualElements2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryTileVisualElements3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryTileVisualElements3>
    {
        ISecondaryTileVisualElements3(std::nullptr_t = nullptr) noexcept {}
        ISecondaryTileVisualElements3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryTileVisualElements4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryTileVisualElements4>
    {
        ISecondaryTileVisualElements4(std::nullptr_t = nullptr) noexcept {}
        ISecondaryTileVisualElements4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStartScreenManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStartScreenManager>
    {
        IStartScreenManager(std::nullptr_t = nullptr) noexcept {}
        IStartScreenManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStartScreenManager2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStartScreenManager2>,
        impl::require<winrt::Windows::UI::StartScreen::IStartScreenManager2, winrt::Windows::UI::StartScreen::IStartScreenManager>
    {
        IStartScreenManager2(std::nullptr_t = nullptr) noexcept {}
        IStartScreenManager2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStartScreenManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStartScreenManagerStatics>
    {
        IStartScreenManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IStartScreenManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITileMixedRealityModel :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITileMixedRealityModel>
    {
        ITileMixedRealityModel(std::nullptr_t = nullptr) noexcept {}
        ITileMixedRealityModel(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITileMixedRealityModel2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITileMixedRealityModel2>
    {
        ITileMixedRealityModel2(std::nullptr_t = nullptr) noexcept {}
        ITileMixedRealityModel2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVisualElementsRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVisualElementsRequest>
    {
        IVisualElementsRequest(std::nullptr_t = nullptr) noexcept {}
        IVisualElementsRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVisualElementsRequestDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVisualElementsRequestDeferral>
    {
        IVisualElementsRequestDeferral(std::nullptr_t = nullptr) noexcept {}
        IVisualElementsRequestDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVisualElementsRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVisualElementsRequestedEventArgs>
    {
        IVisualElementsRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IVisualElementsRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
