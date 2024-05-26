// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_AccessCache_1_H
#define WINRT_Windows_Storage_AccessCache_1_H
#include "winrt/impl/Windows.Storage.AccessCache.0.h"
WINRT_EXPORT namespace winrt::Windows::Storage::AccessCache
{
    struct __declspec(empty_bases) IItemRemovedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IItemRemovedEventArgs>
    {
        IItemRemovedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IItemRemovedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageApplicationPermissionsStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageApplicationPermissionsStatics>
    {
        IStorageApplicationPermissionsStatics(std::nullptr_t = nullptr) noexcept {}
        IStorageApplicationPermissionsStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageApplicationPermissionsStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageApplicationPermissionsStatics2>
    {
        IStorageApplicationPermissionsStatics2(std::nullptr_t = nullptr) noexcept {}
        IStorageApplicationPermissionsStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageItemAccessList :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageItemAccessList>
    {
        IStorageItemAccessList(std::nullptr_t = nullptr) noexcept {}
        IStorageItemAccessList(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageItemMostRecentlyUsedList :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageItemMostRecentlyUsedList>,
        impl::require<winrt::Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList, winrt::Windows::Storage::AccessCache::IStorageItemAccessList>
    {
        IStorageItemMostRecentlyUsedList(std::nullptr_t = nullptr) noexcept {}
        IStorageItemMostRecentlyUsedList(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageItemMostRecentlyUsedList2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageItemMostRecentlyUsedList2>,
        impl::require<winrt::Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList2, winrt::Windows::Storage::AccessCache::IStorageItemAccessList, winrt::Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList>
    {
        IStorageItemMostRecentlyUsedList2(std::nullptr_t = nullptr) noexcept {}
        IStorageItemMostRecentlyUsedList2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
        using impl::consume_t<IStorageItemMostRecentlyUsedList2, IStorageItemMostRecentlyUsedList2>::Add;
        using impl::consume_t<IStorageItemMostRecentlyUsedList2, winrt::Windows::Storage::AccessCache::IStorageItemAccessList>::Add;
        using impl::consume_t<IStorageItemMostRecentlyUsedList2, IStorageItemMostRecentlyUsedList2>::AddOrReplace;
        using impl::consume_t<IStorageItemMostRecentlyUsedList2, winrt::Windows::Storage::AccessCache::IStorageItemAccessList>::AddOrReplace;
    };
}
#endif
