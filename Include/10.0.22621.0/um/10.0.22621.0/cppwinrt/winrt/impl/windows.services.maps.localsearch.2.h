// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Services_Maps_LocalSearch_2_H
#define WINRT_Windows_Services_Maps_LocalSearch_2_H
#include "winrt/impl/Windows.Devices.Geolocation.1.h"
#include "winrt/impl/Windows.Services.Maps.LocalSearch.1.h"
WINRT_EXPORT namespace winrt::Windows::Services::Maps::LocalSearch
{
    struct LocalCategories
    {
        LocalCategories() = delete;
        [[nodiscard]] static auto BankAndCreditUnions();
        [[nodiscard]] static auto EatDrink();
        [[nodiscard]] static auto Hospitals();
        [[nodiscard]] static auto HotelsAndMotels();
        [[nodiscard]] static auto All();
        [[nodiscard]] static auto Parking();
        [[nodiscard]] static auto SeeDo();
        [[nodiscard]] static auto Shop();
    };
    struct __declspec(empty_bases) LocalLocation : winrt::Windows::Services::Maps::LocalSearch::ILocalLocation,
        impl::require<LocalLocation, winrt::Windows::Services::Maps::LocalSearch::ILocalLocation2>
    {
        LocalLocation(std::nullptr_t) noexcept {}
        LocalLocation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Maps::LocalSearch::ILocalLocation(ptr, take_ownership_from_abi) {}
    };
    struct LocalLocationFinder
    {
        LocalLocationFinder() = delete;
        static auto FindLocalLocationsAsync(param::hstring const& searchTerm, winrt::Windows::Devices::Geolocation::Geocircle const& searchArea, param::hstring const& localCategory, uint32_t maxResults);
    };
    struct __declspec(empty_bases) LocalLocationFinderResult : winrt::Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult
    {
        LocalLocationFinderResult(std::nullptr_t) noexcept {}
        LocalLocationFinderResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Maps::LocalSearch::ILocalLocationFinderResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LocalLocationHoursOfOperationItem : winrt::Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem
    {
        LocalLocationHoursOfOperationItem(std::nullptr_t) noexcept {}
        LocalLocationHoursOfOperationItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Maps::LocalSearch::ILocalLocationHoursOfOperationItem(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LocalLocationRatingInfo : winrt::Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo
    {
        LocalLocationRatingInfo(std::nullptr_t) noexcept {}
        LocalLocationRatingInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Maps::LocalSearch::ILocalLocationRatingInfo(ptr, take_ownership_from_abi) {}
    };
    struct PlaceInfoHelper
    {
        PlaceInfoHelper() = delete;
        static auto CreateFromLocalLocation(winrt::Windows::Services::Maps::LocalSearch::LocalLocation const& location);
    };
}
#endif
