// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_Search_2_H
#define WINRT_Windows_Storage_Search_2_H
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Storage.Search.1.h"
WINRT_EXPORT namespace winrt::Windows::Storage::Search
{
    struct SortEntry
    {
        hstring PropertyName;
        bool AscendingOrder;
    };
    inline bool operator==(SortEntry const& left, SortEntry const& right) noexcept
    {
        return left.PropertyName == right.PropertyName && left.AscendingOrder == right.AscendingOrder;
    }
    inline bool operator!=(SortEntry const& left, SortEntry const& right) noexcept
    {
        return !(left == right);
    }
    struct __declspec(empty_bases) ContentIndexer : winrt::Windows::Storage::Search::IContentIndexer,
        impl::require<ContentIndexer, winrt::Windows::Storage::Search::IContentIndexerQueryOperations>
    {
        ContentIndexer(std::nullptr_t) noexcept {}
        ContentIndexer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::Search::IContentIndexer(ptr, take_ownership_from_abi) {}
        static auto GetIndexer(param::hstring const& indexName);
        static auto GetIndexer();
    };
    struct __declspec(empty_bases) ContentIndexerQuery : winrt::Windows::Storage::Search::IContentIndexerQuery
    {
        ContentIndexerQuery(std::nullptr_t) noexcept {}
        ContentIndexerQuery(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::Search::IContentIndexerQuery(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IndexableContent : winrt::Windows::Storage::Search::IIndexableContent
    {
        IndexableContent(std::nullptr_t) noexcept {}
        IndexableContent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::Search::IIndexableContent(ptr, take_ownership_from_abi) {}
        IndexableContent();
    };
    struct __declspec(empty_bases) QueryOptions : winrt::Windows::Storage::Search::IQueryOptions,
        impl::require<QueryOptions, winrt::Windows::Storage::Search::IQueryOptionsWithProviderFilter>
    {
        QueryOptions(std::nullptr_t) noexcept {}
        QueryOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::Search::IQueryOptions(ptr, take_ownership_from_abi) {}
        QueryOptions();
        QueryOptions(winrt::Windows::Storage::Search::CommonFileQuery const& query, param::iterable<hstring> const& fileTypeFilter);
        explicit QueryOptions(winrt::Windows::Storage::Search::CommonFolderQuery const& query);
    };
    struct __declspec(empty_bases) SortEntryVector : winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Search::SortEntry>
    {
        SortEntryVector(std::nullptr_t) noexcept {}
        SortEntryVector(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Search::SortEntry>(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorageFileQueryResult : winrt::Windows::Storage::Search::IStorageFileQueryResult,
        impl::require<StorageFileQueryResult, winrt::Windows::Storage::Search::IStorageFileQueryResult2>
    {
        StorageFileQueryResult(std::nullptr_t) noexcept {}
        StorageFileQueryResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::Search::IStorageFileQueryResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorageFolderQueryResult : winrt::Windows::Storage::Search::IStorageFolderQueryResult
    {
        StorageFolderQueryResult(std::nullptr_t) noexcept {}
        StorageFolderQueryResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::Search::IStorageFolderQueryResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorageItemQueryResult : winrt::Windows::Storage::Search::IStorageItemQueryResult
    {
        StorageItemQueryResult(std::nullptr_t) noexcept {}
        StorageItemQueryResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::Search::IStorageItemQueryResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorageLibraryChangeTrackerTriggerDetails : winrt::Windows::Storage::Search::IStorageLibraryChangeTrackerTriggerDetails
    {
        StorageLibraryChangeTrackerTriggerDetails(std::nullptr_t) noexcept {}
        StorageLibraryChangeTrackerTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::Search::IStorageLibraryChangeTrackerTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorageLibraryContentChangedTriggerDetails : winrt::Windows::Storage::Search::IStorageLibraryContentChangedTriggerDetails
    {
        StorageLibraryContentChangedTriggerDetails(std::nullptr_t) noexcept {}
        StorageLibraryContentChangedTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::Search::IStorageLibraryContentChangedTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ValueAndLanguage : winrt::Windows::Storage::Search::IValueAndLanguage
    {
        ValueAndLanguage(std::nullptr_t) noexcept {}
        ValueAndLanguage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::Search::IValueAndLanguage(ptr, take_ownership_from_abi) {}
        ValueAndLanguage();
    };
}
#endif
