// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_BulkAccess_2_H
#define WINRT_Windows_Storage_BulkAccess_2_H
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.FileProperties.1.h"
#include "winrt/impl/Windows.Storage.Search.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Storage.BulkAccess.1.h"
WINRT_EXPORT namespace winrt::Windows::Storage::BulkAccess
{
    struct __declspec(empty_bases) FileInformation : winrt::Windows::Storage::BulkAccess::IStorageItemInformation,
        impl::require<FileInformation, winrt::Windows::Storage::IStorageItem, winrt::Windows::Storage::Streams::IRandomAccessStreamReference, winrt::Windows::Storage::Streams::IInputStreamReference, winrt::Windows::Storage::IStorageFile, winrt::Windows::Storage::IStorageItemProperties, winrt::Windows::Storage::IStorageItem2, winrt::Windows::Storage::IStorageItemPropertiesWithProvider, winrt::Windows::Storage::IStorageFilePropertiesWithAvailability, winrt::Windows::Storage::IStorageFile2>
    {
        FileInformation(std::nullptr_t) noexcept {}
        FileInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::BulkAccess::IStorageItemInformation(ptr, take_ownership_from_abi) {}
        using impl::consume_t<FileInformation, winrt::Windows::Storage::IStorageFile>::OpenAsync;
        using impl::consume_t<FileInformation, winrt::Windows::Storage::IStorageFile2>::OpenAsync;
        using impl::consume_t<FileInformation, winrt::Windows::Storage::IStorageFile>::OpenTransactedWriteAsync;
        using impl::consume_t<FileInformation, winrt::Windows::Storage::IStorageFile2>::OpenTransactedWriteAsync;
    };
    struct __declspec(empty_bases) FileInformationFactory : winrt::Windows::Storage::BulkAccess::IFileInformationFactory
    {
        FileInformationFactory(std::nullptr_t) noexcept {}
        FileInformationFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::BulkAccess::IFileInformationFactory(ptr, take_ownership_from_abi) {}
        FileInformationFactory(winrt::Windows::Storage::Search::IStorageQueryResultBase const& queryResult, winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode);
        FileInformationFactory(winrt::Windows::Storage::Search::IStorageQueryResultBase const& queryResult, winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize);
        FileInformationFactory(winrt::Windows::Storage::Search::IStorageQueryResultBase const& queryResult, winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize, winrt::Windows::Storage::FileProperties::ThumbnailOptions const& thumbnailOptions);
        FileInformationFactory(winrt::Windows::Storage::Search::IStorageQueryResultBase const& queryResult, winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize, winrt::Windows::Storage::FileProperties::ThumbnailOptions const& thumbnailOptions, bool delayLoad);
    };
    struct __declspec(empty_bases) FolderInformation : winrt::Windows::Storage::BulkAccess::IStorageItemInformation,
        impl::require<FolderInformation, winrt::Windows::Storage::IStorageItem, winrt::Windows::Storage::IStorageFolder, winrt::Windows::Storage::IStorageItemProperties, winrt::Windows::Storage::Search::IStorageFolderQueryOperations, winrt::Windows::Storage::IStorageItem2, winrt::Windows::Storage::IStorageFolder2, winrt::Windows::Storage::IStorageItemPropertiesWithProvider>
    {
        FolderInformation(std::nullptr_t) noexcept {}
        FolderInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::BulkAccess::IStorageItemInformation(ptr, take_ownership_from_abi) {}
        using impl::consume_t<FolderInformation, winrt::Windows::Storage::IStorageFolder>::GetFilesAsync;
        using impl::consume_t<FolderInformation, winrt::Windows::Storage::Search::IStorageFolderQueryOperations>::GetFilesAsync;
        using impl::consume_t<FolderInformation, winrt::Windows::Storage::IStorageFolder>::GetFoldersAsync;
        using impl::consume_t<FolderInformation, winrt::Windows::Storage::Search::IStorageFolderQueryOperations>::GetFoldersAsync;
        using impl::consume_t<FolderInformation, winrt::Windows::Storage::IStorageFolder>::GetItemsAsync;
        using impl::consume_t<FolderInformation, winrt::Windows::Storage::Search::IStorageFolderQueryOperations>::GetItemsAsync;
    };
}
#endif
