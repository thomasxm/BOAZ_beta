// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_FileProperties_2_H
#define WINRT_Windows_Storage_FileProperties_2_H
#include "winrt/impl/Windows.Devices.Geolocation.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Storage.FileProperties.1.h"
WINRT_EXPORT namespace winrt::Windows::Storage::FileProperties
{
    struct __declspec(empty_bases) BasicProperties : winrt::Windows::Storage::FileProperties::IBasicProperties,
        impl::require<BasicProperties, winrt::Windows::Storage::FileProperties::IStorageItemExtraProperties>
    {
        BasicProperties(std::nullptr_t) noexcept {}
        BasicProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::FileProperties::IBasicProperties(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DocumentProperties : winrt::Windows::Storage::FileProperties::IDocumentProperties
    {
        DocumentProperties(std::nullptr_t) noexcept {}
        DocumentProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::FileProperties::IDocumentProperties(ptr, take_ownership_from_abi) {}
    };
    struct GeotagHelper
    {
        GeotagHelper() = delete;
        static auto GetGeotagAsync(winrt::Windows::Storage::IStorageFile const& file);
        static auto SetGeotagFromGeolocatorAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Devices::Geolocation::Geolocator const& geolocator);
        static auto SetGeotagAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Devices::Geolocation::Geopoint const& geopoint);
    };
    struct __declspec(empty_bases) ImageProperties : winrt::Windows::Storage::FileProperties::IImageProperties
    {
        ImageProperties(std::nullptr_t) noexcept {}
        ImageProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::FileProperties::IImageProperties(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MusicProperties : winrt::Windows::Storage::FileProperties::IMusicProperties
    {
        MusicProperties(std::nullptr_t) noexcept {}
        MusicProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::FileProperties::IMusicProperties(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorageItemContentProperties : winrt::Windows::Storage::FileProperties::IStorageItemContentProperties
    {
        StorageItemContentProperties(std::nullptr_t) noexcept {}
        StorageItemContentProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::FileProperties::IStorageItemContentProperties(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorageItemThumbnail : winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType,
        impl::require<StorageItemThumbnail, winrt::Windows::Storage::FileProperties::IThumbnailProperties>
    {
        StorageItemThumbnail(std::nullptr_t) noexcept {}
        StorageItemThumbnail(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) VideoProperties : winrt::Windows::Storage::FileProperties::IVideoProperties
    {
        VideoProperties(std::nullptr_t) noexcept {}
        VideoProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Storage::FileProperties::IVideoProperties(ptr, take_ownership_from_abi) {}
    };
}
#endif
