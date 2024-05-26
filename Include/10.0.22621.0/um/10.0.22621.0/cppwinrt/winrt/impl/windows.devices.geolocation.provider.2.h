// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Geolocation_Provider_2_H
#define WINRT_Windows_Devices_Geolocation_Provider_2_H
#include "winrt/impl/Windows.Devices.Geolocation.Provider.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation::Provider
{
    struct __declspec(empty_bases) GeolocationProvider : winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider
    {
        GeolocationProvider(std::nullptr_t) noexcept {}
        GeolocationProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider(ptr, take_ownership_from_abi) {}
        GeolocationProvider();
    };
}
#endif
