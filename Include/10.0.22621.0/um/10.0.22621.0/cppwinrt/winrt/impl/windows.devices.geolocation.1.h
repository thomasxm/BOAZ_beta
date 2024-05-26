// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Geolocation_1_H
#define WINRT_Windows_Devices_Geolocation_1_H
#include "winrt/impl/Windows.Devices.Geolocation.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation
{
    struct __declspec(empty_bases) ICivicAddress :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICivicAddress>
    {
        ICivicAddress(std::nullptr_t = nullptr) noexcept {}
        ICivicAddress(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeoboundingBox :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeoboundingBox>,
        impl::require<winrt::Windows::Devices::Geolocation::IGeoboundingBox, winrt::Windows::Devices::Geolocation::IGeoshape>
    {
        IGeoboundingBox(std::nullptr_t = nullptr) noexcept {}
        IGeoboundingBox(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeoboundingBoxFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeoboundingBoxFactory>
    {
        IGeoboundingBoxFactory(std::nullptr_t = nullptr) noexcept {}
        IGeoboundingBoxFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeoboundingBoxStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeoboundingBoxStatics>
    {
        IGeoboundingBoxStatics(std::nullptr_t = nullptr) noexcept {}
        IGeoboundingBoxStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeocircle :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeocircle>,
        impl::require<winrt::Windows::Devices::Geolocation::IGeocircle, winrt::Windows::Devices::Geolocation::IGeoshape>
    {
        IGeocircle(std::nullptr_t = nullptr) noexcept {}
        IGeocircle(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeocircleFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeocircleFactory>
    {
        IGeocircleFactory(std::nullptr_t = nullptr) noexcept {}
        IGeocircleFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeocoordinate :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeocoordinate>
    {
        IGeocoordinate(std::nullptr_t = nullptr) noexcept {}
        IGeocoordinate(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeocoordinateSatelliteData :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeocoordinateSatelliteData>
    {
        IGeocoordinateSatelliteData(std::nullptr_t = nullptr) noexcept {}
        IGeocoordinateSatelliteData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeocoordinateSatelliteData2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeocoordinateSatelliteData2>
    {
        IGeocoordinateSatelliteData2(std::nullptr_t = nullptr) noexcept {}
        IGeocoordinateSatelliteData2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeocoordinateWithPoint :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeocoordinateWithPoint>
    {
        IGeocoordinateWithPoint(std::nullptr_t = nullptr) noexcept {}
        IGeocoordinateWithPoint(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeocoordinateWithPositionData :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeocoordinateWithPositionData>,
        impl::require<winrt::Windows::Devices::Geolocation::IGeocoordinateWithPositionData, winrt::Windows::Devices::Geolocation::IGeocoordinate>
    {
        IGeocoordinateWithPositionData(std::nullptr_t = nullptr) noexcept {}
        IGeocoordinateWithPositionData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeocoordinateWithPositionSourceTimestamp :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeocoordinateWithPositionSourceTimestamp>
    {
        IGeocoordinateWithPositionSourceTimestamp(std::nullptr_t = nullptr) noexcept {}
        IGeocoordinateWithPositionSourceTimestamp(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeocoordinateWithRemoteSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeocoordinateWithRemoteSource>
    {
        IGeocoordinateWithRemoteSource(std::nullptr_t = nullptr) noexcept {}
        IGeocoordinateWithRemoteSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeolocator :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeolocator>
    {
        IGeolocator(std::nullptr_t = nullptr) noexcept {}
        IGeolocator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeolocator2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeolocator2>
    {
        IGeolocator2(std::nullptr_t = nullptr) noexcept {}
        IGeolocator2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeolocatorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeolocatorStatics>
    {
        IGeolocatorStatics(std::nullptr_t = nullptr) noexcept {}
        IGeolocatorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeolocatorStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeolocatorStatics2>
    {
        IGeolocatorStatics2(std::nullptr_t = nullptr) noexcept {}
        IGeolocatorStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeolocatorWithScalarAccuracy :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeolocatorWithScalarAccuracy>,
        impl::require<winrt::Windows::Devices::Geolocation::IGeolocatorWithScalarAccuracy, winrt::Windows::Devices::Geolocation::IGeolocator>
    {
        IGeolocatorWithScalarAccuracy(std::nullptr_t = nullptr) noexcept {}
        IGeolocatorWithScalarAccuracy(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeopath :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeopath>,
        impl::require<winrt::Windows::Devices::Geolocation::IGeopath, winrt::Windows::Devices::Geolocation::IGeoshape>
    {
        IGeopath(std::nullptr_t = nullptr) noexcept {}
        IGeopath(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeopathFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeopathFactory>
    {
        IGeopathFactory(std::nullptr_t = nullptr) noexcept {}
        IGeopathFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeopoint :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeopoint>,
        impl::require<winrt::Windows::Devices::Geolocation::IGeopoint, winrt::Windows::Devices::Geolocation::IGeoshape>
    {
        IGeopoint(std::nullptr_t = nullptr) noexcept {}
        IGeopoint(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeopointFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeopointFactory>
    {
        IGeopointFactory(std::nullptr_t = nullptr) noexcept {}
        IGeopointFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeoposition :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeoposition>
    {
        IGeoposition(std::nullptr_t = nullptr) noexcept {}
        IGeoposition(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeoposition2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeoposition2>,
        impl::require<winrt::Windows::Devices::Geolocation::IGeoposition2, winrt::Windows::Devices::Geolocation::IGeoposition>
    {
        IGeoposition2(std::nullptr_t = nullptr) noexcept {}
        IGeoposition2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeoshape :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeoshape>
    {
        IGeoshape(std::nullptr_t = nullptr) noexcept {}
        IGeoshape(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeovisit :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeovisit>
    {
        IGeovisit(std::nullptr_t = nullptr) noexcept {}
        IGeovisit(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeovisitMonitor :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeovisitMonitor>
    {
        IGeovisitMonitor(std::nullptr_t = nullptr) noexcept {}
        IGeovisitMonitor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeovisitMonitorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeovisitMonitorStatics>
    {
        IGeovisitMonitorStatics(std::nullptr_t = nullptr) noexcept {}
        IGeovisitMonitorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeovisitStateChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeovisitStateChangedEventArgs>
    {
        IGeovisitStateChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IGeovisitStateChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeovisitTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeovisitTriggerDetails>
    {
        IGeovisitTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IGeovisitTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPositionChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPositionChangedEventArgs>
    {
        IPositionChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPositionChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStatusChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStatusChangedEventArgs>
    {
        IStatusChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IStatusChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVenueData :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVenueData>
    {
        IVenueData(std::nullptr_t = nullptr) noexcept {}
        IVenueData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
