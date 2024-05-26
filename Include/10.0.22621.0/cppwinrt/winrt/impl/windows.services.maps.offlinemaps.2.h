// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Services_Maps_OfflineMaps_2_H
#define WINRT_Windows_Services_Maps_OfflineMaps_2_H
#include "winrt/impl/Windows.Devices.Geolocation.1.h"
#include "winrt/impl/Windows.Services.Maps.OfflineMaps.1.h"
WINRT_EXPORT namespace winrt::Windows::Services::Maps::OfflineMaps
{
    struct __declspec(empty_bases) OfflineMapPackage : winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage
    {
        OfflineMapPackage(std::nullptr_t) noexcept {}
        OfflineMapPackage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage(ptr, take_ownership_from_abi) {}
        static auto FindPackagesAsync(winrt::Windows::Devices::Geolocation::Geopoint const& queryPoint);
        static auto FindPackagesInBoundingBoxAsync(winrt::Windows::Devices::Geolocation::GeoboundingBox const& queryBoundingBox);
        static auto FindPackagesInGeocircleAsync(winrt::Windows::Devices::Geolocation::Geocircle const& queryCircle);
    };
    struct __declspec(empty_bases) OfflineMapPackageQueryResult : winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult
    {
        OfflineMapPackageQueryResult(std::nullptr_t) noexcept {}
        OfflineMapPackageQueryResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) OfflineMapPackageStartDownloadResult : winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStartDownloadResult
    {
        OfflineMapPackageStartDownloadResult(std::nullptr_t) noexcept {}
        OfflineMapPackageStartDownloadResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStartDownloadResult(ptr, take_ownership_from_abi) {}
    };
}
#endif
