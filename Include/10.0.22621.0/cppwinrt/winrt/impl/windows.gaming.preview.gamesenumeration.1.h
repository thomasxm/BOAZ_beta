// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Gaming_Preview_GamesEnumeration_1_H
#define WINRT_Windows_Gaming_Preview_GamesEnumeration_1_H
#include "winrt/impl/Windows.Gaming.Preview.GamesEnumeration.0.h"
WINRT_EXPORT namespace winrt::Windows::Gaming::Preview::GamesEnumeration
{
    struct __declspec(empty_bases) IGameListEntry :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGameListEntry>
    {
        IGameListEntry(std::nullptr_t = nullptr) noexcept {}
        IGameListEntry(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGameListEntry2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGameListEntry2>,
        impl::require<winrt::Windows::Gaming::Preview::GamesEnumeration::IGameListEntry2, winrt::Windows::Gaming::Preview::GamesEnumeration::IGameListEntry>
    {
        IGameListEntry2(std::nullptr_t = nullptr) noexcept {}
        IGameListEntry2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGameListStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGameListStatics>
    {
        IGameListStatics(std::nullptr_t = nullptr) noexcept {}
        IGameListStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGameListStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGameListStatics2>
    {
        IGameListStatics2(std::nullptr_t = nullptr) noexcept {}
        IGameListStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGameModeConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGameModeConfiguration>
    {
        IGameModeConfiguration(std::nullptr_t = nullptr) noexcept {}
        IGameModeConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGameModeUserConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGameModeUserConfiguration>
    {
        IGameModeUserConfiguration(std::nullptr_t = nullptr) noexcept {}
        IGameModeUserConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGameModeUserConfigurationStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGameModeUserConfigurationStatics>
    {
        IGameModeUserConfigurationStatics(std::nullptr_t = nullptr) noexcept {}
        IGameModeUserConfigurationStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
