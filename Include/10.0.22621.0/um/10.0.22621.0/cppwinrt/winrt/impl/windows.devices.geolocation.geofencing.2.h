// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Geolocation_Geofencing_2_H
#define WINRT_Windows_Devices_Geolocation_Geofencing_2_H
#include "winrt/impl/Windows.Devices.Geolocation.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Devices.Geolocation.Geofencing.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation::Geofencing
{
    struct __declspec(empty_bases) Geofence : winrt::Windows::Devices::Geolocation::Geofencing::IGeofence
    {
        Geofence(std::nullptr_t) noexcept {}
        Geofence(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Geolocation::Geofencing::IGeofence(ptr, take_ownership_from_abi) {}
        Geofence(param::hstring const& id, winrt::Windows::Devices::Geolocation::IGeoshape const& geoshape);
        Geofence(param::hstring const& id, winrt::Windows::Devices::Geolocation::IGeoshape const& geoshape, winrt::Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const& monitoredStates, bool singleUse);
        Geofence(param::hstring const& id, winrt::Windows::Devices::Geolocation::IGeoshape const& geoshape, winrt::Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const& monitoredStates, bool singleUse, winrt::Windows::Foundation::TimeSpan const& dwellTime);
        Geofence(param::hstring const& id, winrt::Windows::Devices::Geolocation::IGeoshape const& geoshape, winrt::Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const& monitoredStates, bool singleUse, winrt::Windows::Foundation::TimeSpan const& dwellTime, winrt::Windows::Foundation::DateTime const& startTime, winrt::Windows::Foundation::TimeSpan const& duration);
    };
    struct __declspec(empty_bases) GeofenceMonitor : winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor
    {
        GeofenceMonitor(std::nullptr_t) noexcept {}
        GeofenceMonitor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor(ptr, take_ownership_from_abi) {}
        [[nodiscard]] static auto Current();
    };
    struct __declspec(empty_bases) GeofenceStateChangeReport : winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceStateChangeReport
    {
        GeofenceStateChangeReport(std::nullptr_t) noexcept {}
        GeofenceStateChangeReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceStateChangeReport(ptr, take_ownership_from_abi) {}
    };
}
#endif
