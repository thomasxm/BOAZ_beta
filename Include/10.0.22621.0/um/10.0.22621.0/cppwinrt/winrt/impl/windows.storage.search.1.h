// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_Search_1_H
#define WINRT_Windows_Storage_Search_1_H
#include "winrt/impl/Windows.Storage.Search.0.h"
WINRT_EXPORT namespace winrt::Windows::Storage::Search
{
    struct __declspec(empty_bases) IContentIndexer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContentIndexer>
    {
        IContentIndexer(std::nullptr_t = nullptr) noexcept {}
        IContentIndexer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContentIndexerQuery :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContentIndexerQuery>
    {
        IContentIndexerQuery(std::nullptr_t = nullptr) noexcept {}
        IContentIndexerQuery(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContentIndexerQueryOperations :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContentIndexerQueryOperations>
    {
        IContentIndexerQueryOperations(std::nullptr_t = nullptr) noexcept {}
        IContentIndexerQueryOperations(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContentIndexerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContentIndexerStatics>
    {
        IContentIndexerStatics(std::nullptr_t = nullptr) noexcept {}
        IContentIndexerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IIndexableContent :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IIndexableContent>
    {
        IIndexableContent(std::nullptr_t = nullptr) noexcept {}
        IIndexableContent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IQueryOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IQueryOptions>
    {
        IQueryOptions(std::nullptr_t = nullptr) noexcept {}
        IQueryOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IQueryOptionsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IQueryOptionsFactory>
    {
        IQueryOptionsFactory(std::nullptr_t = nullptr) noexcept {}
        IQueryOptionsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IQueryOptionsWithProviderFilter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IQueryOptionsWithProviderFilter>
    {
        IQueryOptionsWithProviderFilter(std::nullptr_t = nullptr) noexcept {}
        IQueryOptionsWithProviderFilter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageFileQueryResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageFileQueryResult>,
        impl::require<winrt::Windows::Storage::Search::IStorageFileQueryResult, winrt::Windows::Storage::Search::IStorageQueryResultBase>
    {
        IStorageFileQueryResult(std::nullptr_t = nullptr) noexcept {}
        IStorageFileQueryResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageFileQueryResult2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageFileQueryResult2>,
        impl::require<winrt::Windows::Storage::Search::IStorageFileQueryResult2, winrt::Windows::Storage::Search::IStorageQueryResultBase>
    {
        IStorageFileQueryResult2(std::nullptr_t = nullptr) noexcept {}
        IStorageFileQueryResult2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageFolderQueryOperations :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageFolderQueryOperations>
    {
        IStorageFolderQueryOperations(std::nullptr_t = nullptr) noexcept {}
        IStorageFolderQueryOperations(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageFolderQueryResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageFolderQueryResult>,
        impl::require<winrt::Windows::Storage::Search::IStorageFolderQueryResult, winrt::Windows::Storage::Search::IStorageQueryResultBase>
    {
        IStorageFolderQueryResult(std::nullptr_t = nullptr) noexcept {}
        IStorageFolderQueryResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageItemQueryResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageItemQueryResult>,
        impl::require<winrt::Windows::Storage::Search::IStorageItemQueryResult, winrt::Windows::Storage::Search::IStorageQueryResultBase>
    {
        IStorageItemQueryResult(std::nullptr_t = nullptr) noexcept {}
        IStorageItemQueryResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageLibraryChangeTrackerTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageLibraryChangeTrackerTriggerDetails>
    {
        IStorageLibraryChangeTrackerTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IStorageLibraryChangeTrackerTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageLibraryContentChangedTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageLibraryContentChangedTriggerDetails>
    {
        IStorageLibraryContentChangedTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IStorageLibraryContentChangedTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageQueryResultBase :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageQueryResultBase>
    {
        IStorageQueryResultBase(std::nullptr_t = nullptr) noexcept {}
        IStorageQueryResultBase(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IValueAndLanguage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IValueAndLanguage>
    {
        IValueAndLanguage(std::nullptr_t = nullptr) noexcept {}
        IValueAndLanguage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
