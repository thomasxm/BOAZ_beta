// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Geolocation_Geofencing_1_H
#define WINRT_Windows_Devices_Geolocation_Geofencing_1_H
#include "winrt/impl/Windows.Devices.Geolocation.Geofencing.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation::Geofencing
{
    struct __declspec(empty_bases) IGeofence :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeofence>
    {
        IGeofence(std::nullptr_t = nullptr) noexcept {}
        IGeofence(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeofenceFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeofenceFactory>
    {
        IGeofenceFactory(std::nullptr_t = nullptr) noexcept {}
        IGeofenceFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeofenceMonitor :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeofenceMonitor>
    {
        IGeofenceMonitor(std::nullptr_t = nullptr) noexcept {}
        IGeofenceMonitor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeofenceMonitorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeofenceMonitorStatics>
    {
        IGeofenceMonitorStatics(std::nullptr_t = nullptr) noexcept {}
        IGeofenceMonitorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeofenceStateChangeReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeofenceStateChangeReport>
    {
        IGeofenceStateChangeReport(std::nullptr_t = nullptr) noexcept {}
        IGeofenceStateChangeReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
